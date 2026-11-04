"""Mocked coverage for separate factual-answer contracts and fallback."""
from pathlib import Path
import json
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import brain_studio as app_module
from brain_core import conversation
from brain_core.cloud_orchestration import CloudExecution, CloudOrchestrator
from brain_core.providers import InferenceResult, ProviderID


class GeneralIntelligenceTests(unittest.TestCase):
    def setUp(self):
        from test_studio_ui import StudioUITests
        self.fixture = StudioUITests(
            methodName='test_ui_readiness_inspection_does_not_initialize_runtime_files')
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.app = self.fixture.app.run()
        self.cid = self.app.session_state['conversation_id']
        app_module.st.session_state['conversation_id'] = self.cid
        self.profile = {'identity_name': 'Synthetic', 'identity_id': 'synthetic', 'mission': 'offline test'}
        self.model = SimpleNamespace(local=True, model='offline-test', base_url='http://127.0.0.1:11434/v1')
        self.good = {'answer': 'The sky appears blue because air scatters shorter blue wavelengths more strongly.',
                     'citations': []}

    def _dispatch(self, local_result, *, mode='Automatic (Local first)', response=None):
        state = app_module.st.session_state
        state['conversation_id'] = self.cid
        state['studio_inference'] = mode
        state['_general_journey_store'] = {}
        state['_general_local_completed'] = {}
        state.pop('_conversation_research_store', None)
        history = conversation.load_messages(
            self.cid, data_dir=self.fixture.paths['data_dir'], db_path=self.fixture.paths['db_path'])
        response = self.good if response is None else response
        self.response = response
        with patch.object(app_module, '_prepare_conversation_research') as research, \
             patch.object(app_module.lessons, 'retrieve', return_value=[]) as retrieve, \
             patch('brain_core.providers.LocalOllamaProvider.infer', return_value=local_result) as infer, \
             patch.object(app_module, 'CLOUD_CONSENT') as consent, \
             patch.object(app_module, 'OPENAI_API_KEY', return_value='synthetic-key'), \
             patch.object(app_module, 'openai_configuration', return_value=SimpleNamespace(
                 configured=True, api_key_configured=True, model='gpt-test', api_key='synthetic-key',
                 region='global', endpoint='https://api.openai.com/v1/responses', errors=())), \
             patch.object(app_module, 'OPENAI_PROVIDER_FACTORY', side_effect=lambda **kwargs: _FakeOpenAIProvider(response)), \
             patch.object(app_module, 'CLOUD_SERVICE_FACTORY', CloudOrchestrator), \
             patch.object(app_module, '_render_cloud_approval'):
            app_module._handle_message('Explain why the sky is blue in two sentences', self.cid,
                                       history, self.profile, self.model, None)
            turn = state.get('_general_journey_store', {}).get(self.cid)
            return infer, research, retrieve, turn, consent

    def test_general_local_success_uses_minimal_contract_and_persists_answer(self):
        infer, research, _, turn, _ = self._dispatch(_local_success(self.good))
        infer.assert_called_once()
        request = infer.call_args.args[0]
        schema = request.json_schema
        self.assertEqual(set(schema['properties']), {'answer', 'citations'})
        self.assertTrue({'answer', 'citations'}.issubset(schema['required']))
        self.assertNotIn('emotional_interpretation', schema['properties'])
        self.assertNotIn('assumptions', schema['properties'])
        self.assertNotIn('recommended_action', schema['properties'])
        self.assertEqual(turn.local_state, 'complete')
        self.assertEqual(turn.result_recorded, True)
        research.assert_not_called()
        rows = conversation.load_messages(self.cid, data_dir=self.fixture.paths['data_dir'],
                                          db_path=self.fixture.paths['db_path'])
        self.assertEqual(rows[-1]['message_type'], 'general_answer')
        self.assertIn(self.good['answer'], rows[-1]['content'])

    def test_local_failure_prepares_openai_preview_without_execution(self):
        failed = InferenceResult(ProviderID.LOCAL_OLLAMA, 'offline-test', '', None, 'failed',
                                 'connection', .01, None, None, None, None, True, False)
        _, _, _, turn, consent = self._dispatch(failed)
        self.assertIsNotNone(turn)
        self.assertEqual(turn.cloud_state, 'awaiting_approval')
        self.assertEqual(turn.cloud_request.provider, 'openai_cloud')
        preview = turn.cloud_request.preview
        schema = preview['text']['format']['schema']
        self.assertEqual(schema['required'], ['answer', 'citations'])
        self.assertEqual(preview['text']['format']['name'], 'sovereign_general_answer_v1')
        self.assertNotIn('emotional_interpretation', json.dumps(preview))
        self.assertEqual(consent.prepare.call_count, 1)
        self.assertEqual(consent.consume.call_count, 0)
        self.assertEqual(turn.cloud_service.get_pending_request(self.cid), turn.cloud_request)

    def _approve_general_openai_result(self, turn, result):
        service = turn.cloud_service
        request = turn.cloud_request
        service_key = (self.cid, 'openai_cloud', 'general')
        original_render = app_module._render_cloud_approval

        def render_general_approval(session_id):
            if session_id == self.cid:
                services = app_module.st.session_state.setdefault('_cloud_services_by_conversation', {})
                services[service_key] = service
                app_module.st.session_state['_active_cloud_service_key'] = service_key
            original_render(session_id)

        patcher = patch.object(app_module, '_render_cloud_approval', side_effect=render_general_approval)
        patcher.start()
        self.addCleanup(patcher.stop)
        service.approve_and_execute = Mock(return_value=CloudExecution(request, result))
        service.get_pending_request = Mock(return_value=request)
        state = app_module.st.session_state
        state['conversation_id'] = self.cid
        state['workspace_page'] = 'Conversation'
        state['studio_inference'] = 'Automatic (Local first)'
        app = self.fixture.app
        app.session_state['workspace_page'] = 'Conversation'
        app.session_state['studio_inference'] = 'Automatic (Local first)'
        state['conversation_id'] = self.cid
        state['conversation_selector'] = self.cid
        state['workspace_page'] = 'Conversation'
        state['_cloud_services_by_conversation'][(self.cid, 'openai_cloud', 'general')] = service
        state['_active_cloud_service_key'] = (self.cid, 'openai_cloud', 'general')
        app_module.st.session_state['_general_journey_store'] = {self.cid: turn}
        app_module.st.session_state['conversation_id'] = self.cid
        app_module.st.session_state['studio_inference'] = 'Automatic (Local first)'
        app_module.st.session_state['_general_journey_store'] = {self.cid: turn}
        app.session_state['_general_journey_store'] = {self.cid: turn}
        app = self.fixture.app.run()
        next(button for button in app.button if button.label == 'Approve this cloud request once').click()
        app.run()
        service.approve_and_execute.assert_called_once()

    def test_approved_openai_valid_answer_is_displayed(self):
        failed = InferenceResult(ProviderID.LOCAL_OLLAMA, 'offline-test', '', None, 'failed',
                                 'connection', .01, None, None, None, None, True, False)
        _, _, _, turn, _ = self._dispatch(failed)
        result = _cloud_success(self.good)
        self._approve_general_openai_result(turn, result)
        rows = conversation.load_messages(self.cid, data_dir=self.fixture.paths['data_dir'],
                                          db_path=self.fixture.paths['db_path'])
        self.assertEqual(rows[-1]['message_type'], 'general_answer')
        self.assertIn(self.good['answer'], rows[-1]['content'])

    def test_invalid_local_and_approved_cloud_answers_are_never_saved(self):
        invalid = {'answer': '', 'citations': []}
        failed_validation = InferenceResult(ProviderID.LOCAL_OLLAMA, 'offline-test', '',
            invalid, 'success', None, .01, None, None, None, None, True, False)
        _, _, _, turn, _ = self._dispatch(failed_validation)
        self.assertEqual(turn.cloud_state, 'awaiting_approval')
        result = _cloud_success(invalid)
        self._approve_general_openai_result(turn, result)
        rows = conversation.load_messages(self.cid, data_dir=self.fixture.paths['data_dir'],
                                          db_path=self.fixture.paths['db_path'])
        self.assertFalse(any(row['message_type'] == 'general_answer' for row in rows))
        self.assertEqual(turn.cloud_state, 'invalid_response')

    def test_emotional_route_keeps_existing_reasoning_pipeline(self):
        state = app_module.st.session_state
        state['conversation_id'] = self.cid
        state['studio_inference'] = 'Automatic (Local first)'
        text = 'I feel worried after a conversation with my friend.'
        history = conversation.load_messages(self.cid, data_dir=self.fixture.paths['data_dir'],
                                             db_path=self.fixture.paths['db_path'])
        with patch.object(app_module, '_start_automatic_journey') as automatic, \
             patch.object(app_module, '_run_general_answer') as general:
            app_module._handle_message(text, self.cid, history, self.profile, self.model, None)
        automatic.assert_called_once_with(text, self.cid, self.profile, self.model)
        general.assert_not_called()
        self.assertEqual(conversation.classify_intent(text).intent, 'emotional_reasoning')


class _FakeOpenAIProvider:
    def __init__(self, response):
        self.response = response

    def __call__(self, **kwargs):
        return self

    def authorize_payload_once(self, payload):
        self.payload = payload

    def infer(self, request):
        return _cloud_success(self.response)


def _local_success(value):
    return InferenceResult(ProviderID.LOCAL_OLLAMA, 'offline-test', json.dumps(value), value,
                           'success', None, .01, None, None, None, None, True, False)


def _cloud_success(value):
    return InferenceResult(ProviderID.OPENAI_CLOUD, 'gpt-test', json.dumps(value), value,
                           'success', None, .01, None, None, 'synthetic', None, True, True)


if __name__ == '__main__':
    unittest.main()
