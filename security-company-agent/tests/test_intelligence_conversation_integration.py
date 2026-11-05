"""Offline integration tests for Conversation's existing intelligence pipeline."""
from pathlib import Path
import json
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from brain_core.providers import InferenceResult, ProviderID
from brain_core.research_evidence import ResearchEvidence
import brain_studio as app_module


class ConversationIntelligenceIntegrationTests(unittest.TestCase):
    PRINCIPLE = 'Always verify claims before deciding to avoid unsupported conclusions.'

    def setUp(self):
        from test_studio_ui import StudioUITests
        self.fixture = StudioUITests(methodName='test_ui_readiness_inspection_does_not_initialize_runtime_files')
        self.fixture.setUp()
        self.app = self.fixture.app.run()
        self.session_id = self.app.session_state['conversation_id']
        self.research = Mock(status='completed', evidence=(ResearchEvidence(
            claim=self.PRINCIPLE, snippet=self.PRINCIPLE, title='Synthetic source',
            source_url='https://example.test/evidence', retrieved_at='2026-01-01T00:00:00Z',
            confidence=0.8, content_trusted=False, uncertainty='Unverified synthetic web claim.'),))

    def inference(self, provider=ProviderID.OPENAI_CLOUD, *, status='success', structured=None):
        if structured is None:
            structured = {'claims': [self.PRINCIPLE]}
        return InferenceResult(provider, 'synthetic-model', json.dumps(structured), structured,
                               status, None if status == 'success' else 'timeout', .01,
                               None, None, 'request-synthetic', None, True,
                               provider is not ProviderID.LOCAL_OLLAMA)

    def test_multisource_result_is_qualified_and_candidate_uses_review_ui_state(self):
        result = self.inference()
        with patch.object(app_module.st, 'session_state', self.app.session_state):
            response = app_module._present_intelligence_result(self.session_id, result, self.research,
                                                                response='Original answer')
            state = self.app.session_state['_candidate_learning_review']
        self.assertIn('Qualified summary of available source claims', response)
        self.assertIn('https://example.test/evidence', response)
        self.assertIn('Uncertainty:', response)
        self.assertIn('validated_model_content_not_factually_verified', response)
        self.assertIn('unverified_web_evidence', response)
        self.assertNotEqual(response, 'Original answer')
        self.assertEqual(state['status'], 'candidate_review')
        self.assertEqual(state['candidate'].proposed_principle, self.PRINCIPLE.rstrip('.'))
        self.assertEqual(state['candidate'].review_status, 'pending_review')
        self.assertEqual(state['conversation_id'], self.session_id)
        with patch.object(app_module.st, 'session_state', self.app.session_state):
            app_module._render_candidate_learning_review(self.session_id)
        reviewed = self.app.session_state.get('_candidate_learning_review')
        self.assertEqual(reviewed['status'], 'candidate_review')
        self.assertTrue(self.app.session_state['_candidate_learning_review']['candidate'])

    def test_single_source_falls_back_without_candidate_or_synthetic_response(self):
        result = self.inference(provider=ProviderID.ALIBABA_QWEN_CLOUD)
        with patch.object(app_module.st, 'session_state', self.app.session_state):
            response = app_module._present_intelligence_result(self.session_id, result, None,
                                                                response='Provider answer')
        self.assertEqual(response, 'Provider answer')
        with patch.object(app_module.st, 'session_state', self.app.session_state):
            empty_claim_response = app_module._present_intelligence_result(
                self.session_id, result, None, response='Keep this response', claims=[])
        self.assertEqual(empty_claim_response, 'Keep this response')
        self.assertNotIn('Sources:', response)
        self.assertNotIn('_candidate_learning_review', self.app.session_state)

    def test_failed_provider_and_absent_research_do_not_create_candidate(self):
        with patch.object(app_module.st, 'session_state', self.app.session_state):
            app_module._present_intelligence_result(self.session_id,
                self.inference(status='failed'), self.research)
        self.assertNotIn('_candidate_learning_review', self.app.session_state)
        with patch.object(app_module.st, 'session_state', self.app.session_state):
            response = app_module._present_intelligence_result(self.session_id,
                self.inference(provider=ProviderID.ALIBABA_QWEN_CLOUD), None,
                response='Valid single-source Qwen answer')
        self.assertEqual(response, 'Valid single-source Qwen answer')
        self.assertNotIn('_candidate_learning_review', self.app.session_state)

    def test_research_must_be_completed_before_it_can_contribute(self):
        pending = Mock(status='awaiting_approval', evidence=self.research.evidence)
        result = self.inference()
        with patch.object(app_module.st, 'session_state', self.app.session_state):
            response = app_module._present_intelligence_result(
                self.session_id, result, pending, response='Unchanged provider answer')
        self.assertEqual(response, 'Unchanged provider answer')
        self.assertNotIn('_candidate_learning_review', self.app.session_state)
        approved_empty = Mock(status='completed', evidence=())
        with patch.object(app_module.st, 'session_state', self.app.session_state):
            response = app_module._present_intelligence_result(
                self.session_id, result, approved_empty, response='Single provider answer')
        self.assertEqual(response, 'Single provider answer')

    def test_streamlit_reruns_keep_one_candidate_review(self):
        result = self.inference(provider=ProviderID.ALIBABA_QWEN_CLOUD)
        with patch.object(app_module.st, 'session_state', self.app.session_state):
            first = app_module._offer_candidate_from_intelligence(self.session_id, result, self.research)
            second = app_module._offer_candidate_from_intelligence(self.session_id, result, self.research)
        self.assertIs(first, second)
        self.assertEqual(self.app.session_state['_candidate_learning_review'], first)

    def tearDown(self):
        self.fixture.tearDown()


if __name__ == '__main__':
    unittest.main()
