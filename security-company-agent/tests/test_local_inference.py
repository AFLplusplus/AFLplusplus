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
from brain_core.appraisal import EMOTIONS, offline_appraisal
from brain_core.decision import SCHEMA

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        raw = self.rfile.read(int(self.headers['Content-Length']))
        payload = json.loads(raw)
        self.server.seen.append((self.path, dict(self.headers), payload))
        status = self.server.status
        content = self.server.output
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
        for owner, name, value in ((personality, 'PROFILE_PATH', root / 'personality.json'),
                                   (trainer, 'STATE_PATH', root / 'state.json'),
                                   (trainer, 'HISTORY_PATH', root / 'history.json'),
                                   (studio, 'DATA', root), (studio, 'DB', root / 'test.sqlite3')):
            p = patch.object(owner, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.server.seen = []
        self.server.status = 200
        self.fixture = trainer.infer('I feel love and anger', '', {}, {}, mock=True)
        self.fixture.pop('_provenance')
        self.server.output = json.dumps({'choices': [{'message': {'content': json.dumps(self.fixture)},
                                                     'finish_reason': 'stop'}]}).encode()
        self.config = model_api.ModelConfig(f'http://127.0.0.1:{self.server.server_port}/v1',
                                            'test-fixture-not-a-real-model', 3, reasoning_effort=None)

    def test_structured_request_and_local_secret_exclusion(self):
        with patch.dict(os.environ, {'BRAIN_API_KEY': 'do-not-transmit-test-secret'}):
            result, meta = model_api.complete([{'role': 'user', 'content': 'test'}], self.config, SCHEMA)
        path, headers, request = self.server.seen[0]
        self.assertEqual(path, '/v1/chat/completions')
        self.assertNotIn('Authorization', headers)
        self.assertEqual(request['response_format']['type'], 'json_schema')
        self.assertEqual(result['emotion'], 'curious')

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

    def test_invalid_emotions_do_not_update_memory(self):
        before, _ = trainer.status()
        self.fixture['emotions']['anger'] = 7
        self.server.output = json.dumps({'choices': [{'message': {'content': json.dumps(self.fixture)}}]}).encode()
        with self.assertRaisesRegex(model_api.ModelError, 'validation'):
            trainer.train('Anger and attachment', config=self.config)
        after, _ = trainer.status()
        self.assertEqual(before, after)
        self.assertEqual(studio.recent_turns(), [])

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

    def test_feedback_retrieved_and_sent_on_second_session(self):
        first, _, _, _ = service.analyze('Love and attachment in an uncertain relationship', config=self.config)
        service.give_feedback(first, 'partial', 'Discuss a trial boundary before recommending separation.')
        second, state, result, retrieved = service.analyze('An uncertain relationship: love and attachment',
                                                         config=self.config)
        request = json.loads(self.server.seen[-1][2]['messages'][-1]['content'])
        self.assertEqual(request['previous_trainer_corrections'][0]['turn_id'], first)
        self.assertIn('trial boundary', request['previous_trainer_corrections'][0]['correction'])
        self.assertEqual(result['_feedback_turn_ids'], [first])
        self.assertEqual(state['iterations'], 2)
        self.assertEqual(len(studio.recent_turns()), 2)
        self.assertEqual(studio.recent_turns()[-1]['commentary'], 'Discuss a trial boundary before recommending separation.')

    def test_irrelevant_feedback_is_not_retrieved(self):
        id = studio.add_turn('Gardening tomato seedlings', '', {}, {})
        studio.rate_turn(id, 'good', 'Water roots gently.')
        self.assertEqual(studio.feedback_context('Relationship trust and anger'), [])

    def test_legacy_state_is_preserved(self):
        state = {'metrics': dict(trainer.BASE), 'emotion': 'legacy', 'iterations': 9,
                 'narrative': 'Earlier session', 'confidence': 0.5}
        trainer.write_json(trainer.STATE_PATH, state)
        trainer.write_json(trainer.HISTORY_PATH, {'history': [{'legacy': True}], 'rules': []})
        loaded, history = trainer.status()
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
            studio.add_document(filename, text)
            self.assertIn('mutual respect', studio.relevant_context('trust respect'))
        self.assertEqual(len(studio.documents()), 3)

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
        with studio.connect() as db:
            id = db.execute('INSERT INTO research(created,query,title,url,excerpt) VALUES(?,?,?,?,?)',
                            ('now','trust','Trust study','https://example.org/study','Trust is reciprocal')).lastrowid
        self.assertEqual(studio.relevant_context('trust'), '')
        studio.approve_research(id, True)
        self.assertIn('https://example.org/study', studio.relevant_context('trust'))

if __name__ == '__main__':
    unittest.main()
