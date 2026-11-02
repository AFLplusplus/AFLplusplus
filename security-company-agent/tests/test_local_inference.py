"""Deterministic transport tests use a fake loopback server, never a real model."""
import copy
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core import trainer, studio, service, model_api, personality
from brain_core.appraisal import EMOTIONS, NEUTRAL, offline_appraisal
from brain_core.decision import SCHEMA
from quality_fixtures import output

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        raw = self.rfile.read(int(self.headers['Content-Length']))
        payload = json.loads(raw)
        self.server.seen.append((self.path, dict(self.headers), payload))
        status = self.server.status
        content = (self.server.responses.pop(0) if self.server.responses is not None
                   else self.server.output)
        if isinstance(content, str):
            content = content.encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(content)

class LocalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        root = Path(self.folder.name)
        self.paths = dict(profile_path=root / 'personality.json', state_path=root / 'state.json',
                          history_path=root / 'history.json', data_dir=root, db_path=root / 'test.sqlite3')
        for owner, name, value in ((personality, 'PROFILE_PATH', self.paths['profile_path']),
                                   (trainer, 'STATE_PATH', self.paths['state_path']),
                                   (trainer, 'HISTORY_PATH', self.paths['history_path']),
                                   (studio, 'DATA', self.paths['data_dir']), (studio, 'DB', self.paths['db_path'])):
            p = patch.object(owner, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.server.seen = []
        self.server.responses = None
        self.server.status = 200
        self.fixture = output('Love and attachment in an uncertain relationship. Anger and attachment.')
        self.fixture['_trainer_approved'] = False
        self.server.output = json.dumps({'choices': [{'message': {'content': json.dumps(self.fixture)},
                                                     'finish_reason': 'stop'}]}).encode()
        self.config = model_api.ModelConfig(f'http://127.0.0.1:{self.server.server_port}/v1',
                                            'test-fixture-not-a-real-model', 3, reasoning_effort=None)

    def test_structured_request_and_local_secret_exclusion(self):
        local = model_api.ModelConfig('http://127.0.0.1:%s/v1' % self.server.server_port,
                                      'test-fixture-not-a-real-model', 3, reasoning_effort=None)
        with patch.dict(os.environ, {'BRAIN_API_KEY': 'do-not-transmit-test-secret'}):
            result, meta = model_api.complete([{'role': 'user', 'content': 'test'}], local, SCHEMA)
        path, headers, request = self.server.seen[-1]
        self.assertEqual(path, '/v1/chat/completions')
        self.assertNotIn('Authorization', headers)
        self.assertEqual(request['response_format']['type'], 'json_schema')
        self.assertEqual(request['max_tokens'], 1000)
        self.assertEqual(request['model'], 'test-fixture-not-a-real-model')
        self.assertEqual(result['emotion'], 'curious')

    def test_configured_output_limit_can_only_lower_policy_ceiling(self):
        config = model_api.ModelConfig(f'http://127.0.0.1:{self.server.server_port}/v1',
                                       'test-fixture-not-a-real-model', 3,
                                       reasoning_effort=None, max_output_tokens=400)
        model_api.complete([{'role': 'user', 'content': 'test'}], config, SCHEMA)
        request = self.server.seen[-1][2]
        self.assertEqual(request['max_tokens'], 400)
        self.assertLessEqual(request['max_tokens'], 1000)

    def test_connection_failure_is_safe(self):
        with patch.object(model_api, 'opener_for') as mocked:
            mocked.return_value.open.side_effect = model_api.urllib.error.URLError('private body')
            with self.assertRaisesRegex(model_api.ModelError, 'Cannot connect') as raised:
                model_api.complete([], self.config, SCHEMA)
        self.assertNotIn('private body', str(raised.exception))

    def test_timeout_is_safe(self):
        with patch.object(model_api, 'opener_for') as mocked:
            mocked.return_value.open.side_effect = socket.timeout('private details')
            with self.assertRaisesRegex(model_api.ModelError, 'timed out'):
                model_api.complete([], self.config, SCHEMA)

    def test_http_error_does_not_disclose_body(self):
        self.server.status = 401
        self.server.output = b'confidential diagnostic credentials'
        with self.assertRaisesRegex(model_api.ModelError, 'HTTP 401') as raised:
            model_api.complete([], self.config, SCHEMA)
        self.assertNotIn('confidential', str(raised.exception))

    def test_invalid_json_rejected(self):
        self.server.output = b'not-json'
        with self.assertRaisesRegex(model_api.ModelError, 'invalid structured'):
            model_api.complete([], self.config, SCHEMA)

    def test_failed_inference_preserves_memory_and_stops_after_stage_one(self):
        state_path = self.paths['state_path']
        history_path = self.paths['history_path']
        before = trainer.inspect_status(state_path=state_path, history_path=history_path)
        invalid = {'choices': [{'message': {'content': 'not-json'}, 'finish_reason': 'stop'}]}
        self.server.output = json.dumps(invalid).encode()
        config = model_api.ModelConfig(f'http://127.0.0.1:{self.server.server_port}/v1',
                                       'test-fixture-not-a-real-model', 3, reasoning_effort=None)
        with patch.object(model_api, 'available_memory_gib', return_value=2.0):
            with self.assertRaises(model_api.ModelOutputError):
                service.analyze('A colleague is quiet after disappointing project news.',
                                config=config, **self.paths)
        self.assertEqual(trainer.inspect_status(state_path=state_path, history_path=history_path), before)
        self.assertEqual(studio.inspect_turns(db_path=self.paths['db_path']), [])

    def test_invalid_emotions_do_not_update_memory(self):
        before, _ = trainer.inspect_status(state_path=self.paths['state_path'], history_path=self.paths['history_path'])
        self.fixture['emotions']['anger'] = 7
        self.server.output = json.dumps({'choices': [{'message': {'content': json.dumps(self.fixture)}}]}).encode()
        with self.assertRaisesRegex(model_api.ModelError, 'reasoning quality checks'):
            trainer.train('Anger and attachment', config=self.config,
                          state_path=self.paths['state_path'], history_path=self.paths['history_path'],
                          data_dir=self.paths['data_dir'], db_path=self.paths['db_path'],
                          profile_path=self.paths['profile_path'])
        after, _ = trainer.inspect_status(state_path=self.paths['state_path'], history_path=self.paths['history_path'])
        self.assertEqual(before, after)
        self.assertEqual(studio.inspect_turns(db_path=self.paths['db_path']), [])

    def test_gateway_authorization_and_url_boundary(self):
        with self.assertRaises(model_api.ModelError):
            model_api.ModelConfig('https://gateway.example/v1')
        self.assertFalse(model_api.ModelConfig('https://gateway.example/v1', allow_remote=True).local)
        for url in ('http://gateway.example/v1', 'http://localhost.example/v1',
                    'http://127.0.0.1@evil.example/v1', 'http://127.0.0.1:123/v1?token=secret'):
            with self.subTest(url=url), self.assertRaises(model_api.ModelError):
                model_api.ModelConfig(url, allow_remote=True)

    def test_low_ram_does_not_launch_local_model(self):
        with patch.object(model_api, 'available_memory_gib', return_value=0.7), \
             patch.object(model_api, 'opener_for') as opener:
            opener.return_value.open.side_effect = OSError()
            with self.assertRaisesRegex(model_api.ModelError, 'on hold'):
                model_api.complete([], model_api.ModelConfig(), SCHEMA)
            self.assertEqual(opener.return_value.open.call_count, 0)

    def test_request_lock_serializes_application_calls(self):
        entered = threading.Event()
        release = threading.Event()
        calls = []
        def fake_complete(messages, config, schema):
            calls.append(threading.current_thread().name)
            if len(calls) == 1:
                entered.set()
                release.wait(2)
            return {'ok': True}, {'seconds': 0}
        with patch.object(model_api, '_complete', side_effect=fake_complete):
            first = threading.Thread(target=model_api.complete, args=([], self.config, SCHEMA), name='first')
            second = threading.Thread(target=model_api.complete, args=([], self.config, SCHEMA), name='second')
            first.start()
            self.assertTrue(entered.wait(1))
            second.start()
            self.assertEqual(calls, ['first'])
            release.set()
            first.join(2)
            second.join(2)
        self.assertEqual(calls, ['first', 'second'])

    def test_openai_compatible_loopback_options_for_nondefault_port(self):
        self.server.output = json.dumps({'choices': [{'message': {'content': json.dumps(self.fixture)},
                                                      'finish_reason': 'stop'}]}).encode()
        config = model_api.ModelConfig(f'http://127.0.0.1:{self.server.server_port}/v1',
                                       'test-fixture-not-a-real-model', 3, reasoning_effort=None)
        result, _ = model_api.complete([{'role': 'user', 'content': 'test'}], config, SCHEMA)
        path, _, request = self.server.seen[-1]
        self.assertEqual(path, '/v1/chat/completions')
        self.assertEqual(request['max_tokens'], 1000)
        self.assertEqual(request['model'], 'test-fixture-not-a-real-model')
        self.assertEqual(result['emotion'], 'curious')

    def test_resource_error_is_separate_from_output_validation(self):
        self.server.status = 500
        self.server.output = b'model requires more system memory; private diagnostic'
        with self.assertRaises(model_api.MemoryGuardError) as raised:
            model_api.complete([], self.config, SCHEMA)
        self.assertNotIn('private diagnostic', str(raised.exception))

    def test_invalid_json_has_output_error_category(self):
        self.server.output = b'not-json'
        with self.assertRaises(model_api.ModelOutputError):
            model_api.complete([], self.config, SCHEMA)

    def test_failed_first_stage_leaves_memory_unchanged(self):
        self.server.output = json.dumps({'choices': [{'message': {'content': 'not-json'},
                                                       'finish_reason': 'stop'}]}).encode()
        config = model_api.ModelConfig(f'http://127.0.0.1:{self.server.server_port}/v1',
                                       'test-fixture-not-a-real-model', 3, reasoning_effort=None)
        with patch.object(model_api, 'available_memory_gib', return_value=2.0):
            with self.assertRaises(model_api.ModelOutputError):
                service.analyze('Love and attachment in an uncertain relationship',
                                config=config, **self.paths)
        self.assertEqual(len(self.server.seen), 1)
        self.assertEqual(trainer.inspect_status(state_path=self.paths['state_path'],
                                                history_path=self.paths['history_path']), (None, {'history': [], 'rules': []}))
        self.assertEqual(len(studio.inspect_turns(db_path=self.paths['db_path'])), 0)

    @unittest.skip('Three-stage pending approval is covered with schema-valid mocks in decision quality tests.')
    def test_approved_inference_can_be_explicitly_saved_and_corrected(self):
        stage1={'facts':['The scenario describes love and attachment in an uncertain relationship.'],'emotions':[{'label':'love and attachment','trigger':'Love and attachment are mentioned.'},{'label':'uncertainty and fear','trigger':'The relationship is described as uncertain.'}],'assumptions':['The relationship outcome is unknown.']}
        stage2={'alternatives':[{'action':'I will ask my partner whether they want to talk about what feels uncertain.','consequence':'A gentle question may clarify what support they want.'},{'action':'I will give my partner space and revisit the conversation later.','consequence':'Waiting may respect their space but leave uncertainty unresolved.'}]}
        stage3={'selected_action':stage2['alternatives'][0]['action'],'rationale':'The scenario gives no evidence of what my partner wants, so a gentle question can clarify whether they want to talk.','emotional_tradeoff':'Concern supports offering help, while uncertainty argues for a low-pressure question.'}
        with patch('brain_core.reasoning_stages.complete', side_effect=[(stage1,{}),(stage2,{}),(stage3,{})]):
            _, _, pending, retrieved = service.analyze(
                'Love and attachment in an uncertain relationship', config=self.config, **self.paths)
        self.assertIsInstance(pending, dict)
        approved = dict(pending)
        approved.pop('_trainer_pending', None)
        approved['_trainer_approved'] = True
        turn_id = studio.add_turn('Love and attachment in an uncertain relationship', '', approved, {},
                                  data_dir=self.paths['data_dir'], db_path=self.paths['db_path'])
        approved['_provenance'] = {'source': 'approved_training', 'model': 'test-fixture'}
        approved['_cognitive_context'] = trainer.cognition.assess(
            'Love and attachment in an uncertain relationship',
            personality.DEFAULT, {'emotions': dict(NEUTRAL)})
        self.fixture['_cognitive_context'] = approved['_cognitive_context']
        with patch('brain_core.reasoning_stages.complete', side_effect=[(stage1,{}),(stage2,{}),(stage3,{})]):
            _, updated, result = trainer.train(
                'Love and attachment in an uncertain relationship', config=self.config,
                persistent_profile=personality.inspect(profile_path=self.paths['profile_path']),
                proposed_result=approved,
                feedback='Discuss a trial boundary.',
                state_path=self.paths['state_path'], history_path=self.paths['history_path'],
                data_dir=self.paths['data_dir'], db_path=self.paths['db_path'],
                profile_path=self.paths['profile_path'])
        self.assertEqual(updated['iterations'], 1)
        self.assertTrue(self.paths['state_path'].exists())
        approved_saved = dict(approved, _trainer_approved=True)
        with studio.connect(initialize=False, data_dir=self.paths['data_dir'], db_path=self.paths['db_path']) as db:
            db.execute('UPDATE turns SET result_json=? WHERE id=?', (json.dumps(approved_saved), turn_id))
        service.give_feedback(turn_id, 'partial', 'Discuss a trial boundary.',
                              data_dir=self.paths['data_dir'], db_path=self.paths['db_path'])
        self.assertEqual(studio.inspect_turns(db_path=self.paths['db_path'])[-1]['rating'], 'partial')

    def test_irrelevant_feedback_is_not_retrieved(self):
        id = studio.add_turn('Gardening tomato seedlings', '',
                             {'_trainer_approved': True}, {},
                             data_dir=self.paths['data_dir'], db_path=self.paths['db_path'])
        studio.rate_turn(id, 'good', 'Water roots gently.',
                         data_dir=self.paths['data_dir'], db_path=self.paths['db_path'])
        self.assertEqual(studio.feedback_context('Relationship trust and anger',
                                                 data_dir=self.paths['data_dir'], db_path=self.paths['db_path']), [])

    def test_legacy_state_is_preserved(self):
        state = {'metrics': dict(trainer.BASE), 'emotion': 'legacy', 'iterations': 9,
                 'narrative': 'Earlier session', 'confidence': 0.5}
        trainer.write_json(trainer.STATE_PATH, state)
        trainer.write_json(trainer.HISTORY_PATH, {'history': [{'legacy': True}], 'rules': []})
        loaded, history = trainer.inspect_status(state_path=self.paths['state_path'],
                                                 history_path=self.paths['history_path'])
        self.assertEqual(loaded['iterations'], 9)
        self.assertEqual(history['history'], [{'legacy': True}])
        self.assertEqual(set(loaded['emotions']), set(EMOTIONS))
        self.assertNotIn('emotions', json.loads(trainer.STATE_PATH.read_text()))

    def test_offline_display_is_deterministic_and_scenario_dependent(self):
        conflict = 'Love, attachment, anger, hurt and fear of losing her; I am indecisive.'
        self.assertEqual(offline_appraisal(conflict), offline_appraisal(conflict))
        self.assertGreater(offline_appraisal(conflict)['anger'], offline_appraisal('A calm day')['anger'])

    def test_text_markdown_and_docx_ingestion(self):
        from docx import Document
        document = Document()
        document.add_paragraph('Trust requires mutual respect.')
        blob = io.BytesIO()
        document.save(blob)
        for filename, content in [('lesson.txt', b'Trust requires mutual respect.'),
                                  ('lesson.md', b'# Trust requires mutual respect.'),
                                  ('lesson.docx', blob.getvalue())]:
            text = studio.decode_document(filename, content)
            studio.add_document(filename, text, data_dir=self.paths['data_dir'], db_path=self.paths['db_path'])
            self.assertIn('mutual respect', studio.relevant_context('trust respect', data_dir=self.paths['data_dir'], db_path=self.paths['db_path']))
        self.assertEqual(len(studio.inspect_documents(db_path=self.paths['db_path'])), 3)

    @unittest.skipUnless(__import__('importlib').util.find_spec('pypdf'), 'optional pypdf dependency is unavailable')
    def test_pdf_ingestion(self):
        from pypdf import PdfWriter
        from pypdf.generic import DictionaryObject, NameObject, DecodedStreamObject
        writer = PdfWriter()
        page = writer.add_blank_page(width=300, height=200)
        font = DictionaryObject({NameObject('/Type'): NameObject('/Font'),
                                 NameObject('/Subtype'): NameObject('/Type1'),
                                 NameObject('/BaseFont'): NameObject('/Helvetica')})
        page[NameObject('/Resources')] = DictionaryObject({NameObject('/Font'):
            DictionaryObject({NameObject('/F1'): writer._add_object(font)})})
        stream = DecodedStreamObject()
        stream.set_data(b'BT /F1 12 Tf 10 100 Td (Trust and boundaries.) Tj ET')
        page[NameObject('/Contents')] = writer._add_object(stream)
        blob = io.BytesIO()
        writer.write(blob)
        self.assertIn('Trust and boundaries.', studio.decode_document('lesson.pdf', blob.getvalue()))

    def test_unapproved_research_does_not_enter_context(self):
        with studio.connect(initialize=True, data_dir=self.paths['data_dir'], db_path=self.paths['db_path']) as db:
            id = db.execute('INSERT INTO research(created,query,title,url,excerpt) VALUES(?,?,?,?,?)',
                            ('now','trust','Trust study','https://example.org/study','Trust is reciprocal')).lastrowid
        self.assertEqual(studio.relevant_context('trust', db_path=self.paths['db_path']), '')
        studio.approve_research(id, True, data_dir=self.paths['data_dir'], db_path=self.paths['db_path'])
        self.assertIn('https://example.org/study', studio.relevant_context('trust', db_path=self.paths['db_path']))

if __name__ == '__main__':
    unittest.main()
