"""Offline tests for OpenAI Responses provider and shared consent orchestration."""
import io
import json
import sys
import unittest
import urllib.error
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core.cloud_consent import CloudApprovalManager
from brain_core.cloud_orchestration import CloudOrchestrationError, CloudOrchestrator
from brain_core.openai_provider import (OPENAI_ENDPOINT, OpenAIResponsesProvider,
                                        openai_configuration, responses_payload)
from brain_core.providers import InferenceRequest, ProviderID

SCHEMA = {'type': 'object', 'properties': {'answer': {'type': 'string'}},
          'required': ['answer'], 'additionalProperties': False}
REQUEST = InferenceRequest(({'role': 'system', 'content': 'Synthetic identity'},
                            {'role': 'user', 'content': 'A synthetic question'}),
                           'synthetic-model', 64, 3, SCHEMA)


class Response:
    def __init__(self, value):
        self.value = value
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self, size=-1):
        return json.dumps(self.value).encode()


class Opener:
    def __init__(self, result=None, error=None):
        self.result, self.error, self.calls = result, error, []
    def open(self, request, timeout):
        self.calls.append((request, timeout))
        if self.error:
            raise self.error
        return Response(self.result)


def success_body(text='{"answer":"mocked"}'):
    return {'id': 'resp_mock', 'status': 'completed', 'output_text': text,
            'usage': {'input_tokens': 12, 'output_tokens': 4}}


class OpenAIProviderTests(unittest.TestCase):
    def provider(self, opener):
        return OpenAIResponsesProvider(model='synthetic-model', api_key='synthetic-key', opener=opener)

    def test_configuration_never_makes_network_calls_and_reports_missing_fields(self):
        cfg = openai_configuration(environ={})
        self.assertFalse(cfg.configured)
        self.assertFalse(cfg.api_key_configured)
        self.assertIsNone(cfg.api_key)
        self.assertTrue(any('key' in item for item in cfg.errors))
        self.assertTrue(any('model' in item for item in cfg.errors))
        cfg = openai_configuration(environ={'OPENAI_API_KEY':'synthetic-secret', 'SOVEREIGN_OPENAI_MODEL':'gpt-candidate'})
        self.assertTrue(cfg.configured)
        self.assertEqual(cfg.model, 'gpt-candidate')
        self.assertNotIn('synthetic-secret', repr(cfg))

    def test_responses_payload_and_success_parsing(self):
        payload = responses_payload(REQUEST)
        self.assertEqual(payload['model'], 'synthetic-model')
        self.assertEqual(payload['instructions'], 'Synthetic identity')
        self.assertEqual(payload['input'][0]['content'][0]['text'], 'A synthetic question')
        self.assertFalse(payload['store'])
        self.assertEqual(payload['tools'], [])
        opener = Opener(success_body())
        provider = self.provider(opener)
        fp = provider.fingerprint(REQUEST)
        with self.assertRaises(PermissionError):
            provider.infer(REQUEST)
        provider.authorize_once(REQUEST, fp)
        result = provider.infer(REQUEST)
        self.assertEqual(result.status, 'success')
        self.assertEqual(result.provider, ProviderID.OPENAI_CLOUD)
        self.assertEqual(result.structured, {'answer': 'mocked'})
        self.assertEqual(result.request_id, 'resp_mock')
        self.assertEqual(result.input_tokens, 12)
        self.assertEqual(result.output_tokens, 4)
        self.assertEqual(result.estimated_cost, None)
        self.assertEqual(len(opener.calls), 1)
        with self.assertRaises(PermissionError):
            provider.infer(REQUEST)

    def test_authorize_approved_payload_matches_infer_request_and_is_single_use(self):
        opener = Opener(success_body())
        provider = OpenAIResponsesProvider(model='synthetic-model', api_key='synthetic-key',
                                           max_output_tokens=REQUEST.max_output_tokens, opener=opener)
        approved_payload = responses_payload(REQUEST)
        provider.authorize_payload_once(approved_payload)
        self.assertEqual(provider.infer(REQUEST).status, 'success')
        self.assertEqual(len(opener.calls), 1)
        with self.assertRaises(PermissionError):
            provider.authorize_payload_once(approved_payload)

    def test_general_text_without_schema(self):
        request = replace(REQUEST, json_schema=None)
        provider = self.provider(Opener(success_body('Natural synthetic reply.')))
        provider.authorize_once(request, provider.fingerprint(request))
        result = provider.infer(request)
        self.assertEqual(result.text, 'Natural synthetic reply.')
        self.assertIsNone(result.structured)

    def test_incomplete_empty_malformed_and_provider_errors(self):
        cases = [({'status':'incomplete','incomplete_details':{'reason':'max_output_tokens'},'output_text':'{}'}, 'incomplete_response'),
                 ({'status':'completed','output_text':''}, 'empty_response'),
                 (success_body('not-json'), 'malformed_structured_output')]
        for body, category in cases:
            with self.subTest(category=category):
                opener = Opener(body)
                provider = self.provider(opener)
                provider.authorize_once(REQUEST, provider.fingerprint(REQUEST))
                self.assertEqual(provider.infer(REQUEST).error_category, category)
        http_cases = [(401, b'{"error":{"message":"bad key"}}', 'authentication'),
                      (429, b'{"error":{"code":"insufficient_quota"}}', 'insufficient_credits_or_quota'),
                      (429, b'{"error":{"message":"slow down"}}', 'rate_limit')]
        for status, body, category in http_cases:
            error = urllib.error.HTTPError(OPENAI_ENDPOINT, status, 'failure', {}, io.BytesIO(body))
            provider = self.provider(Opener(error=error))
            provider.authorize_once(REQUEST, provider.fingerprint(REQUEST))
            self.assertEqual(provider.infer(REQUEST).error_category, category)
        for error, category in [(TimeoutError(), 'timeout'),
                                (urllib.error.URLError('synthetic offline'), 'connection'),
                                (RuntimeError('private detail'), 'provider_exception')]:
            provider = self.provider(Opener(error=error))
            provider.authorize_once(REQUEST, provider.fingerprint(REQUEST))
            self.assertEqual(provider.infer(REQUEST).error_category, category)

    def test_exact_payload_provider_model_and_conversation_consent_binding(self):
        manager = CloudApprovalManager()
        payload = responses_payload(REQUEST)
        approval = manager.prepare(provider='openai_cloud', model=REQUEST.model, region='global',
            payload=payload, session_id='conversation-a', token_estimate=12)
        manager.register(approval)
        with self.assertRaises(Exception):
            manager.consume(approval.approval_id, provider='alibaba_qwen_cloud', model=REQUEST.model,
                           region='global', payload=payload, session_id='conversation-a', user_approved=True)
        with self.assertRaises(Exception):
            manager.consume(approval.approval_id, provider='openai_cloud', model=REQUEST.model,
                           region='global', payload=payload, session_id='conversation-b', user_approved=True)
        manager.consume(approval.approval_id, provider='openai_cloud', model=REQUEST.model,
                        region='global', payload=payload, session_id='conversation-a', user_approved=True)
        with self.assertRaises(Exception):
            manager.consume(approval.approval_id, provider='openai_cloud', model='other-model',
                           region='global', payload=payload, session_id='conversation-a', user_approved=True)

    def test_openai_cloud_orchestrator_preview_execution_and_duplicate_block(self):
        manager = CloudApprovalManager()
        opener = Opener(success_body())
        factory = Mock(side_effect=lambda **kwargs: OpenAIResponsesProvider(opener=opener, **kwargs))
        settings = lambda: openai_configuration(environ={
            'OPENAI_API_KEY':'synthetic-key', 'SOVEREIGN_OPENAI_MODEL':'synthetic-model'})
        from types import SimpleNamespace
        def payload_factory(text, profile, approved_lessons, *, session_id, settings):
            request = InferenceRequest(({'role':'system','content':'Synthetic instructions'},
                                        {'role':'user','content':text}), settings.model, 64, 60, SCHEMA)
            return responses_payload(request), SCHEMA
        service = CloudOrchestrator(consent=manager, payload_factory=payload_factory,
            provider_factory=factory, api_key=lambda:'synthetic-key', provider='openai_cloud',
            region='global', provider_settings=settings)
        request = service.prepare_fallback(user_text='fictional synthetic scenario', conversation_id='c1',
            profile={'identity_name':'Synthetic'}, approved_lessons=[], local_error=RuntimeError('synthetic'))
        self.assertEqual(request.provider, 'openai_cloud')
        self.assertEqual(request.preview['model'], 'synthetic-model')
        self.assertEqual(len(opener.calls), 0)
        result = service.approve_and_execute(request=request, conversation_id='c1').result
        self.assertEqual(result.status, 'success')
        self.assertEqual(len(opener.calls), 1)
        with self.assertRaises(CloudOrchestrationError):
            service.approve_and_execute(request=request, conversation_id='c1')
        self.assertEqual(len(opener.calls), 1)

    def test_cloud_output_is_not_persisted_as_validated_without_real_checks(self):
        import tempfile
        from unittest.mock import patch
        from brain_studio import _cloud_result_writer
        from brain_core.providers import InferenceResult, ProviderID
        from brain_core import conversation
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / 'isolated.sqlite3'
            conversation.create_session('Synthetic', db_path=db_path)
            from brain_core import studio
            with studio.connect(initialize=False, db_path=db_path) as db:
                db.execute('CREATE TABLE IF NOT EXISTS conversation_messages (message_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL, role TEXT NOT NULL, created_at TEXT NOT NULL, content TEXT NOT NULL, message_type TEXT NOT NULL, related_lesson_id TEXT, inference_status TEXT NOT NULL DEFAULT "not_applicable")')
            session_id = conversation.list_sessions(db_path=db_path)[0]['conversation_id']
            output = {
                'version':'sovereign-reasoning.v1',
                'facts':['A synthetic person cancelled a meeting.'],
                'assumptions':['It is unknown why the meeting was cancelled.'],
                'emotional_interpretation':'fear',
                'alternatives':['Ask the person what happened.', 'Wait before deciding.'],
                'recommended_action':'Ask the person what happened.',
                'rationale':'This can clarify the cancelled meeting.',
                'next_step':'Ask the person what happened.',
                'lesson_ids_used':[],
            }
            result = InferenceResult(ProviderID.OPENAI_CLOUD, 'synthetic-model', json.dumps(output),
                                     output, 'success', None, 0.01, 2, 3, 'synthetic', None, True, True)
            with patch('brain_core.decision.validate_emotional_understanding', side_effect=ValueError('synthetic failure')):
                _cloud_result_writer(session_id, result, ())
            self.assertFalse(any(item['message_type'] == 'validated_reasoning'
                                 for item in conversation.load_messages(session_id, db_path=db_path)))

    def test_openai_request_factory_uses_current_environment_without_disclosing_key(self):
        from brain_studio import _make_openai_payload
        settings = openai_configuration(environ={
            'OPENAI_API_KEY': 'synthetic-secret', 'SOVEREIGN_OPENAI_MODEL': 'synthetic-model'})
        payload, schema = _make_openai_payload('Synthetic scenario', {'identity_name':'Synthetic'}, [],
                                               session_id='conversation-x', settings=settings)
        self.assertEqual(payload['model'], 'synthetic-model')
        self.assertEqual(payload['store'], False)
        self.assertEqual(payload['tools'], [])
        self.assertEqual(payload['text']['format']['schema'], schema)
        self.assertNotIn('synthetic-secret', json.dumps(payload))

    def test_changed_openai_model_invalidates_pending_approval(self):
        manager = CloudApprovalManager()
        current_model = ['synthetic-model']
        settings = lambda: __import__('brain_core.openai_provider', fromlist=['OpenAIConfiguration']).OpenAIConfiguration(
            current_model[0], True, (), api_key='synthetic-key')
        def payload_factory(text, profile, approved_lessons, *, session_id, settings):
            req = replace(REQUEST, model=settings.model)
            return responses_payload(req), SCHEMA
        service = CloudOrchestrator(consent=manager, payload_factory=payload_factory,
            provider_factory=Mock(), api_key=lambda:'synthetic-key', provider='openai_cloud',
            region='global', provider_settings=settings)
        request = service.prepare_fallback(user_text='synthetic text', conversation_id='c1', profile={},
            approved_lessons=[], local_error=RuntimeError('synthetic'))
        current_model[0] = 'changed-model'
        with self.assertRaises(CloudOrchestrationError):
            service.approve_and_execute(request=request, conversation_id='c1')


if __name__ == '__main__':
    unittest.main()
