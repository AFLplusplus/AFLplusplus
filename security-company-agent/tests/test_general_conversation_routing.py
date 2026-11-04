"""Mocked end-to-end tests for general versus emotional Conversation routing."""
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import brain_studio as app_module
from brain_core import conversation


class GeneralConversationRoutingTests(unittest.TestCase):
    def setUp(self):
        from test_studio_ui import StudioUITests
        self.fixture = StudioUITests(
            methodName='test_ui_readiness_inspection_does_not_initialize_runtime_files')
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.app = self.fixture.app.run()
        self.cid = self.app.session_state['conversation_id']
        self.profile = {'identity_name': 'Synthetic', 'identity_id': 'synthetic', 'mission': 'offline test'}

    def _dispatch(self, text, *, inference='Automatic (Local first)'):
        state = app_module.st.session_state
        state['conversation_id'] = self.cid
        state['studio_inference'] = inference
        history = conversation.load_messages(
            self.cid, data_dir=self.fixture.paths['data_dir'], db_path=self.fixture.paths['db_path'])
        with patch.object(app_module, '_start_automatic_journey') as automatic, \
             patch.object(app_module, 'trainer') as trainer, \
             patch.object(app_module, '_prepare_conversation_research') as prepare_research, \
             patch.object(app_module, '_run_general_answer') as general_answer:
            trainer.infer.return_value = {'narrative': 'mocked', 'conversational_response': 'mocked'}
            app_module._handle_message(text, self.cid, history, self.profile,
                                       Mock(local=True, model='offline-test'), None)
        return automatic, trainer.infer, prepare_research, general_answer

    def test_sky_question_uses_general_answer_not_automatic_emotional_pipeline(self):
        text = 'Explain why the sky is blue in two sentences.'
        automatic, inference, research, general_answer = self._dispatch(text)
        self.assertEqual(conversation.classify_intent(text).intent, 'general')
        automatic.assert_not_called()
        self.assertEqual(general_answer.call_args.args[:2], (text, self.cid))
        inference.assert_not_called()
        research.assert_not_called()
        rows = conversation.load_messages(self.cid, data_dir=self.fixture.paths['data_dir'],
                                          db_path=self.fixture.paths['db_path'])
        self.assertEqual(rows[-1]['role'], 'user')

    def test_interpersonal_question_uses_automatic_emotional_pipeline(self):
        text = "My friend hasn't replied for two days. Does that mean they no longer care?"
        automatic, inference, research, _ = self._dispatch(text)
        self.assertEqual(conversation.classify_intent(text).intent, 'emotional_reasoning')
        automatic.assert_called_once_with(text, self.cid, self.profile, unittest.mock.ANY)
        inference.assert_not_called()
        research.assert_not_called()

    def test_latest_developments_uses_general_answer_and_research_preview(self):
        text = 'What are the latest developments in AI agents?'
        automatic, inference, research, general_answer = self._dispatch(text)
        self.assertEqual(conversation.classify_intent(text).intent, 'general')
        automatic.assert_not_called()
        self.assertEqual(general_answer.call_args.args[:2], (text, self.cid))
        inference.assert_not_called()
        research.assert_not_called()
        general_answer.assert_called_once()
        self.assertEqual(conversation.load_messages(
            self.cid, data_dir=self.fixture.paths['data_dir'], db_path=self.fixture.paths['db_path'])[-1]['role'],
            'user')

    def test_explicit_training_request_keeps_training_dispatch(self):
        text = 'I want to teach you that silence can have many explanations.'
        automatic, inference, research, _ = self._dispatch(text)
        self.assertEqual(conversation.classify_intent(text).intent, 'training')
        automatic.assert_not_called()
        inference.assert_not_called()
        research.assert_not_called()
        rows = conversation.load_messages(self.cid, data_dir=self.fixture.paths['data_dir'],
                                          db_path=self.fixture.paths['db_path'])
        self.assertEqual(rows[-1]['message_type'], 'lesson_clarification')


if __name__ == '__main__':
    unittest.main()
