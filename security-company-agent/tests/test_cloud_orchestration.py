"""Network-free unit tests for cloud fallback orchestration boundaries."""
import json
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core.cloud_consent import CloudApprovalManager, CloudApprovalRequired
from brain_core.cloud_orchestration import CloudOrchestrationError, CloudOrchestrator
from brain_core.providers import InferenceResult, ProviderID


@dataclass(frozen=True)
class Settings:
    configured: bool = True
    api_key_configured: bool = True
    model: str = 'qwen-test'
    region: str = 'ap-southeast-1'


PAYLOAD = {
    'model': 'qwen-test',
    'messages': [
        {'role': 'system', 'content': 'Synthetic instructions'},
        {'role': 'user', 'content': '{"scenario":"fictional"}'},
    ],
    'stream': False,
    'temperature': 0.2,
    'max_tokens': 256,
    'response_format': {'type': 'json_schema', 'json_schema': {'name': 'sovereign_reasoning_v1', 'strict': True,
                          'schema': {'type': 'object'}}},
    'reasoning_schema': {'type': 'object'},
}
ENDPOINT = 'https://ws-example123.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1'


class MockProvider:
    def __init__(self, result=None, error=None):
        self.calls = 0
        self.authorized = []
        self.result = result or InferenceResult(ProviderID.ALIBABA_QWEN_CLOUD, 'qwen-test', '{}',
                                                {'ok': True}, 'success', None, .01,
                                                None, None, 'mock-id', None, True, True)
        self.error = error

    @staticmethod
    def fingerprint(request):
        return 'mock-request-fingerprint'

    def authorize_once(self, request, fingerprint):
        self.authorized.append((request, fingerprint))

    def infer(self, request):
        self.calls += 1
        self.request = request
        if self.error:
            raise self.error
        return self.result


class CloudOrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.manager = CloudApprovalManager()
        self.provider = MockProvider()
        self.provider_factory = Mock(return_value=self.provider)
        self.writer = Mock()
        self.payload_factory = Mock(return_value=(Settings(), ENDPOINT, PAYLOAD, {'type': 'object'}))
        self.service = CloudOrchestrator(
            consent=self.manager, payload_factory=self.payload_factory,
            provider_factory=self.provider_factory, api_key=lambda: 'synthetic-key',
            provider_payload=lambda payload, request: payload,
            provider_fingerprint=lambda request, payload: 'mock-request-fingerprint',
            result_writer=self.writer)
        self.lessons = [{'lesson_id': 'lesson-safe', 'approval_status': 'approved',
                         'corrective_principle': 'Treat uncertainty carefully.'}]

    def prepare(self, conversation='conversation-1', error=None, *, eligible=True):
        return self.service.prepare_fallback(
            user_text='fictional scenario', conversation_id=conversation,
            profile={'identity_name': 'Synthetic'}, approved_lessons=self.lessons,
            local_error=error or RuntimeError('controlled local failure'), eligible=eligible)

    def test_eligible_local_failure_prepares_frozen_preview_without_network(self):
        with patch('urllib.request.urlopen', side_effect=AssertionError('network forbidden')) as network:
            request = self.prepare()
        self.assertEqual(network.call_count, 0)
        self.assertEqual(request.preview, PAYLOAD)
        self.assertEqual(request.max_output_tokens, PAYLOAD['max_tokens'])
        request.preview['messages'][0]['content'] = 'mutated copy'
        self.assertEqual(self.service.get_pending_request('conversation-1').preview, PAYLOAD)
        self.assertEqual(self.provider_factory.call_count, 0)
        self.assertEqual(self.manager.events, ())

    def test_noneligible_failure_and_invalid_configuration_do_not_prepare(self):
        with self.assertRaises(CloudOrchestrationError):
            self.prepare(eligible=False)
        self.assertIsNone(self.service.get_pending_request('conversation-1'))
        self.payload_factory.return_value = (Settings(configured=False), ENDPOINT, PAYLOAD, {})
        with self.assertRaises(CloudOrchestrationError):
            self.prepare()
        self.assertEqual(self.provider_factory.call_count, 0)
        self.assertIsNone(self.service.get_pending_request('conversation-1'))

    def test_approval_executes_exact_preview_once_and_writes_correct_conversation(self):
        request = self.prepare()
        with patch('urllib.request.urlopen', side_effect=AssertionError('network forbidden')) as network:
            execution = self.service.approve_and_execute(request=request, conversation_id='conversation-1')
        self.assertEqual(network.call_count, 0)
        self.assertEqual(execution.result.status, 'success')
        inference = self.provider.request
        self.assertEqual(inference.model, request.model)
        self.assertEqual(list(inference.messages), request.preview['messages'])
        self.assertEqual(inference.max_output_tokens, request.max_output_tokens)
        self.assertEqual(self.provider.calls, 1)
        self.assertEqual(len(self.provider.authorized), 1)
        self.writer.assert_called_once_with('conversation-1', execution.result, tuple(self.lessons))
        self.assertEqual(len(self.manager.events), 1)
        self.assertTrue(self.manager.events[0]['success'])
        self.assertIsNone(self.manager.events[0]['error_category'])
        self.assertNotIn('_session_id', self.manager.events[0])
        self.assertIsNone(self.service.get_pending_request('conversation-1'))
        with self.assertRaises(CloudOrchestrationError):
            self.service.approve_and_execute(request=request, conversation_id='conversation-1')
        self.assertEqual(self.provider.calls, 1)

    def test_decline_and_wrong_conversation_make_no_provider_call(self):
        request = self.prepare('conversation-1')
        with self.assertRaises(CloudOrchestrationError):
            self.service.approve_and_execute(request=request, conversation_id='conversation-2')
        self.assertTrue(self.service.decline_fallback(request=request, conversation_id='conversation-1'))
        self.assertFalse(self.service.decline_fallback(request=request, conversation_id='conversation-1'))
        self.assertEqual(self.provider_factory.call_count, 0)
        self.assertIsNone(self.service.get_pending_request('conversation-1'))
        with self.assertRaises(CloudApprovalRequired):
            self.manager.consume(request.approval_id, provider=request.provider, model=request.model,
                                 region=request.region, payload=request.preview,
                                 session_id='conversation-1', user_approved=True)

    def test_changed_request_requires_new_approval(self):
        request = self.prepare()
        # Tamper only with internal payload state to model a changed contextual request.
        pending = self.service._pending['conversation-1']
        changed_payload = dict(pending[3], temperature=0.9)
        self.service._pending['conversation-1'] = (pending[0], pending[1], pending[2], changed_payload, pending[4])
        with self.assertRaises(CloudOrchestrationError):
            self.service.approve_and_execute(request=request, conversation_id='conversation-1')
        self.assertEqual(self.provider_factory.call_count, 0)
        self.assertIsNone(self.service.get_pending_request('conversation-1'))

    def test_provider_error_or_timeout_consumes_authorization_without_retry(self):
        for failure in (RuntimeError('provider failed'), TimeoutError('timeout')):
            with self.subTest(failure=type(failure).__name__):
                self.setUp()
                self.provider.error = failure
                request = self.prepare()
                with self.assertRaises(CloudOrchestrationError):
                    self.service.approve_and_execute(request=request, conversation_id='conversation-1')
                self.assertEqual(self.provider.calls, 1)
                self.assertFalse(self.manager.events[0]['success'])
                self.assertEqual(self.manager.events[0]['error_category'], 'execution_failed')
                with self.assertRaises(CloudOrchestrationError):
                    self.service.approve_and_execute(request=request, conversation_id='conversation-1')
                self.assertEqual(self.provider.calls, 1)
                self.assertFalse(self.manager.events[0]['success'])
                self.assertEqual(self.manager.events[0]['error_category'], 'execution_failed')
                with self.assertRaises(CloudApprovalRequired):
                    self.manager.consume(request.approval_id, provider=request.provider, model=request.model,
                                         region=request.region, payload=request.preview,
                                         session_id='conversation-1', user_approved=True)

    def test_explicit_port_is_rejected_and_superseded_request_is_retired(self):
        explicit_port = ENDPOINT.replace('aliyuncs.com/', 'aliyuncs.com:443/')
        self.payload_factory.return_value = (Settings(), explicit_port, PAYLOAD, {})
        with self.assertRaises(CloudOrchestrationError):
            self.prepare()
        self.payload_factory.return_value = (Settings(), ENDPOINT, PAYLOAD, {})
        first = self.prepare()
        second = self.prepare()
        with self.assertRaises(CloudOrchestrationError):
            self.service.approve_and_execute(request=first, conversation_id='conversation-1')
        self.assertEqual(self.manager.events, ())
        self.assertEqual(self.service.get_pending_request('conversation-1'), second)

    def test_concurrent_approval_attempts_cannot_duplicate_provider_execution(self):
        import threading
        request = self.prepare()
        barrier = threading.Barrier(2)
        outcomes = []
        def execute():
            barrier.wait()
            try:
                outcomes.append(self.service.approve_and_execute(
                    request=request, conversation_id='conversation-1'))
            except CloudOrchestrationError:
                outcomes.append('rejected')
        threads = [threading.Thread(target=execute) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(self.provider.calls, 1)
        self.assertEqual(sum(item == 'rejected' for item in outcomes), 1)

    def test_provider_payload_must_equal_the_approved_request(self):
        self.service._provider_request_payload = lambda payload, request: dict(payload, temperature=0.9)
        request = self.prepare()
        with self.assertRaises(CloudOrchestrationError):
            self.service.approve_and_execute(request=request, conversation_id='conversation-1')
        self.assertEqual(self.provider.calls, 0)
        with self.assertRaises(CloudApprovalRequired):
            self.manager.consume(request.approval_id, provider=request.provider, model=request.model,
                                 region=request.region, payload=request.preview,
                                 session_id='conversation-1', user_approved=True)

    def test_service_has_no_streamlit_import_and_no_memory_or_lesson_writer(self):
        import brain_core.cloud_orchestration as module
        self.assertNotIn('streamlit', module.__dict__)
        before = json.dumps(self.lessons, sort_keys=True)
        request = self.prepare()
        self.service.approve_and_execute(request=request, conversation_id='conversation-1')
        self.assertEqual(json.dumps(self.lessons, sort_keys=True), before)
        self.assertFalse(any(name in module.__dict__ for name in ('personality', 'memory', 'emotional_transition')))


if __name__ == '__main__':
    unittest.main()
