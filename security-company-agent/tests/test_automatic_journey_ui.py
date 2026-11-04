"""Focused, offline coverage for automatic Conversation inference orchestration."""
from pathlib import Path
import json
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from brain_core import conversation
from brain_core.conversation_journey import ConversationJourneyStore
from brain_core.intelligence_journey import IntelligenceJourneyController
from brain_core.providers import InferenceResult, ProviderID
from brain_core.cloud_orchestration import CloudExecution, CloudRequest
import brain_studio as app_module


class AutomaticJourneyUITests(unittest.TestCase):
    def setUp(self):
        from test_studio_ui import StudioUITests
        self.fixture = StudioUITests(methodName='test_ui_readiness_inspection_does_not_initialize_runtime_files')
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.app = self.fixture.app.run()
        self.cid = self.app.session_state['conversation_id']

    def _setup_journey(self, text, local_result=None, local_error=None):
        from types import SimpleNamespace
        cid = self.app.session_state['conversation_id']
        profile = {'identity_name': 'Synthetic', 'identity_id': 'synthetic', 'mission': 'offline test'}
        local = Mock(side_effect=local_error) if local_error else Mock(return_value=local_result)
        store = ConversationJourneyStore()
        from brain_core.openai_provider import responses_payload, InferenceRequest
        schema = {'type': 'object', 'properties': {'value': {'type': 'string'}},
                  'required': ['value'], 'additionalProperties': False}
        payload_factory = Mock(return_value=(responses_payload(InferenceRequest(
            ({'role': 'system', 'content': 'Synthetic safe instructions.'},
             {'role': 'user', 'content': json.dumps({'scenario': text})}),
            'gpt-test', 256, 60, schema)), schema))
        with patch.object(app_module, 'CLOUD_CONSENT') as consent, \
             patch.object(app_module, 'CLOUD_SERVICE_FACTORY') as service_factory, \
             patch.object(app_module, 'service') as mocked_service, \
             patch.object(app_module.trainer, 'infer', side_effect=local), \
             patch.object(app_module, 'openai_configuration',
                          return_value=SimpleNamespace(configured=True, api_key_configured=True, model='gpt-test', api_key='synthetic-key', region='global', endpoint='https://api.openai.com/v1/responses')), \
             patch.object(app_module, '_make_openai_payload', payload_factory):
            from brain_core.cloud_orchestration import CloudOrchestrator
            service_factory.side_effect = lambda **kwargs: CloudOrchestrator(**kwargs)
            mocked_service.cognition.assess.return_value = {}
            app_module.st.session_state['_conversation_journey_store'] = store
            app_module.st.session_state['conversation_id'] = cid
            app_module._start_automatic_journey(text, cid, profile, Mock(local=True, model='local-test'))
        return cid, profile, local, store.get(cid)

    def test_local_success_is_saved_once_and_never_prepares_cloud(self):
        text = 'I feel worried after a difficult conversation with my colleague.'
        structured = {'conversational_response': 'Synthetic validated local response.',
                      'narrative': 'Synthetic narrative.'}
        result = InferenceResult(ProviderID.LOCAL_OLLAMA, 'local-test', '{}', structured,
                                 'success', None, .01, None, None, None, None, True, False)
        cid, profile, local, turn = self._setup_journey(text, local_result=result)
        self.assertIsNotNone(turn)
        self.assertEqual(turn.local_state, 'complete')
        self.assertEqual(local.call_count, 1)
        self.assertNotIn((cid, 'openai_cloud'), app_module.st.session_state.get(
            '_cloud_services_by_conversation', {}))
        self.assertEqual(local.call_count, 1)
        rows = conversation.load_messages(cid, data_dir=self.fixture.paths['data_dir'],
                                          db_path=self.fixture.paths['db_path'])
        self.assertEqual(sum(item['role'] == 'assistant' for item in rows), 1)
        app_module._start_automatic_journey(text, cid, profile, Mock(local=True))
        self.assertEqual(local.call_count, 1)
        rows = conversation.load_messages(cid, data_dir=self.fixture.paths['data_dir'],
                                          db_path=self.fixture.paths['db_path'])
        self.assertEqual(sum(item['role'] == 'assistant' for item in rows), 1)

    def test_local_failure_prepares_openai_preview_without_execution(self):
        text = 'Synthetic concern after a colleague conversation.'
        failed = InferenceResult(ProviderID.LOCAL_OLLAMA, 'local-test', '', None,
                                 'failed', 'connection', .01, None, None, None, None, True, False)
        cid, _, local, turn = self._setup_journey(text, local_result=failed)
        self.assertIsNotNone(turn)
        self.assertEqual(turn.local_state, 'failed')
        self.assertEqual(turn.cloud_state, 'awaiting_approval')
        self.assertEqual(turn.cloud_request.provider, 'openai_cloud')
        self.assertIn(text, turn.cloud_request.payload_json)
        self.assertEqual(local.call_count, 1)
        # Preparation only registers a preview; execution requires the UI approval action.
        self.assertEqual(turn.cloud_service.get_pending_request(cid), turn.cloud_request)

    def test_local_exception_prepares_pending_preview_and_stays_silent(self):
        text = 'Synthetic concern about an uncertain conversation.'
        cid, _, local, turn = self._setup_journey(text, local_error=RuntimeError('synthetic local failure'))
        self.assertIsNotNone(turn)
        self.assertEqual(turn.cloud_state, 'awaiting_approval')
        self.assertEqual(local.call_count, 1)
        self.assertEqual(turn.cloud_service.get_pending_request(cid), turn.cloud_request)
        rows = conversation.load_messages(cid, data_dir=self.fixture.paths['data_dir'],
                                          db_path=self.fixture.paths['db_path'])
        self.assertEqual(sum(item['role'] == 'assistant' for item in rows), 0)

    def test_approved_execution_runs_once_and_records_response_once(self):
        cid = self.cid
        text = 'Synthetic request for a mocked cloud result.'
        response = {'version': 'sovereign-reasoning.v1', 'facts': ['A conversation occurred.'],
                    'assumptions': ['Intent is not established.'],
                    'emotional_interpretation': 'Concern.',
                    'alternatives': ['Ask calmly.', 'Wait for more information.'],
                    'recommended_action': 'Ask calmly.', 'rationale': 'Clarify rather than assume.',
                    'next_step': 'Prepare a neutral question.', 'lesson_ids_used': []}
        result = InferenceResult(ProviderID.OPENAI_CLOUD, 'gpt-test', json.dumps(response), response,
                                 'success', None, .01, None, None, 'synthetic', None, True, True)
        request = CloudRequest('approval-synthetic', 'fingerprint-synthetic', cid, 'openai_cloud',
                               'gpt-test', 'global', 'https://api.openai.com/v1/responses',
                               json.dumps({'model': 'gpt-test', 'messages': []}), 20, 256)
        fake = Mock()
        fake.get_pending_request.return_value = request
        fake.approve_and_execute.return_value = CloudExecution(request, result)
        fake.decline_fallback.return_value = True
        store = ConversationJourneyStore()
        turn, _ = store.begin(cid, text=text, profile={}, approved_lessons=[])
        turn.local_state = 'failed'
        turn.cloud_state = 'awaiting_approval'
        turn.cloud_request = request
        journey_controller = IntelligenceJourneyController(local_runner=lambda _: None)
        journey = journey_controller.start(
            text, local_readiness={'status': 'UNAVAILABLE'},
            openai_readiness={'status': 'AVAILABLE'})
        from brain_core.fallback_state import FallbackState
        from dataclasses import replace
        turn.journey = replace(journey, state=FallbackState.AWAITING_CLOUD_APPROVAL,
                               attempted=(ProviderID.LOCAL_OLLAMA,))
        self.app.session_state['_conversation_journey_store'] = store
        self.app.session_state['_journey_controller'] = journey_controller
        fake.approve_and_execute = Mock(return_value=CloudExecution(request, result))
        fake.decline_fallback = Mock(return_value=True)
        fake.prepare_fallback = Mock(return_value=request)
        self.app.session_state['_cloud_services_by_conversation'] = {(cid, 'openai_cloud'): fake}
        self.app.session_state['_active_cloud_service_key'] = (cid, 'openai_cloud')
        self.app.session_state['conversation_id'] = cid
        self.app.session_state['workspace_page'] = 'Conversation'
        fake.approve_and_execute.assert_not_called()
        # Render through AppTest and click the explicit consent control.
        app = self.fixture.app.run()
        next(button for button in app.button if button.label == 'Approve this cloud request once').click()
        app.run()
        fake.approve_and_execute.assert_called_once()
        self.assertEqual(turn.cloud_state, 'completed')
        self.assertTrue(turn.result_recorded)
        rows = conversation.load_messages(cid, data_dir=self.fixture.paths['data_dir'],
                                          db_path=self.fixture.paths['db_path'])
        self.assertEqual(sum(item['message_type'] == 'cloud_reasoning' for item in rows), 1)
        app.run()
        fake.approve_and_execute.assert_called_once()
        rows = conversation.load_messages(cid, data_dir=self.fixture.paths['data_dir'],
                                          db_path=self.fixture.paths['db_path'])
        self.assertEqual(sum(item['message_type'] == 'cloud_reasoning' for item in rows), 1)

    def test_rerun_of_same_pending_turn_does_not_repeat_local_work(self):
        text = 'Synthetic pending request must not run twice.'
        failed = InferenceResult(ProviderID.LOCAL_OLLAMA, 'local-test', '', None,
                                 'failed', 'connection', .01, None, None, None, None, True, False)
        cid, profile, local, turn = self._setup_journey(text, local_result=failed)
        self.assertIsNotNone(turn)
        self.assertEqual(turn.cloud_state, 'awaiting_approval')
        with patch.object(app_module, 'service') as mocked_service, \
             patch.object(app_module.trainer, 'infer') as second_inference:
            mocked_service.cognition.assess.return_value = {}
            app_module._start_automatic_journey(text, cid, profile, Mock(local=True))
        self.assertEqual(local.call_count, 1)
        second_inference.assert_not_called()
        self.assertEqual(turn.cloud_state, 'awaiting_approval')
        self.assertEqual(len(conversation.load_messages(cid, data_dir=self.fixture.paths['data_dir'],
                                                        db_path=self.fixture.paths['db_path'])), 0)


if __name__ == '__main__':
    unittest.main()
