"""Offline UI tests for separately approved Conversation web research."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from streamlit.testing.v1 import AppTest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from brain_core import conversation
from brain_core.conversation_research import ConversationResearchStore
from brain_core.research_coordination import ResearchAuthorizationLedger
from brain_core.research_evidence import validate_search_results
import brain_studio as app_module


class ConversationResearchUITests(unittest.TestCase):
    def setUp(self):
        from test_studio_ui import StudioUITests
        self.fixture = StudioUITests(methodName='test_ui_readiness_inspection_does_not_initialize_runtime_files')
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.fixture.app.run()
        self.app = self.fixture.app
        self.cid = self.app.session_state['conversation_id']
        self.ledger_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.ledger_dir.cleanup)
        self.ledger = ResearchAuthorizationLedger(Path(self.ledger_dir.name) / 'authorization.sqlite3')
        self.store = ConversationResearchStore()
        self.app.session_state['_conversation_research_store'] = self.store
        self.app.session_state['_research_authorization_ledger'] = self.ledger
        app_module.st.session_state['_conversation_research_store'] = self.store
        app_module.st.session_state['_research_authorization_ledger'] = self.ledger
        self.ui_mock_values = {
            'columns': Mock(return_value=(Mock(button=Mock(return_value=False)),
                                          Mock(button=Mock(return_value=False)))),
            'warning': Mock(), 'write': Mock(), 'code': Mock(), 'caption': Mock(),
            'markdown': Mock(), 'rerun': Mock(), 'info': Mock(),
        }
        self.ui_mocks = patch.multiple(app_module.st, **self.ui_mock_values)
        self.ui_mocks.start()
        self.addCleanup(self.ui_mocks.stop)

    def test_approval_button_executes_exact_query_once_and_displays_citation(self):
        store = self.store
        self.app.session_state['_conversation_research_store'] = store
        app_module.st.session_state['_conversation_research_store'] = store
        app_module.st.session_state['_research_authorization_ledger'] = self.ledger
        item = app_module._prepare_conversation_research(
            'I feel worried after a difficult conversation with my colleague about current project status', self.cid)
        result = {'status': 'ok', 'error': None, 'results': [{
            'title': 'Synthetic source', 'url': 'https://example.test/research',
            'snippet': 'A synthetic unverified search snippet.'}]}
        runner = Mock(return_value=result)
        self.ui_mock_values['columns'].return_value = (
            Mock(button=Mock(return_value=True)), Mock(button=Mock(return_value=False)))
        with patch.object(app_module, 'BRAVE_SEARCH_RUNNER', runner):
            app_module._render_conversation_research_approval(self.cid)
        self.assertEqual(runner.call_count, 1)
        self.assertEqual(runner.call_args.args[0], item.query)
        app_module.st.code.assert_called_once_with(item.query)
        app_module.st.markdown.assert_called_once()
        self.assertIn('example.test/research', app_module.st.markdown.call_args.args[0])
        self.assertEqual(item.status, 'completed')
        app_module._run_authorized_research(self.cid)
        self.assertEqual(runner.call_count, 1)

    def test_approval_executes_one_exact_minimized_query_and_preserves_citation(self):
        query = 'I feel worried after a difficult conversation with my colleague about project status'
        item = app_module._prepare_conversation_research(query, self.cid)
        result = {'status': 'ok', 'error': None, 'results': [{
            'title': 'Synthetic source', 'url': 'https://example.test/research',
            'snippet': 'A synthetic unverified search snippet.'}]}
        runner = Mock(return_value=result)
        app_module.st.session_state['_conversation_research_store'] = self.store
        app_module.st.session_state['_research_authorization_ledger'] = self.ledger
        item.status = 'awaiting_approval'
        with patch.object(app_module, 'BRAVE_SEARCH_RUNNER', runner):
            app_module._run_authorized_research(self.cid)
            self.assertEqual(runner.call_count, 1)
            self.assertEqual(runner.call_args.args[0], item.query)
            app_module._run_authorized_research(self.cid)
        self.assertEqual(runner.call_count, 1)
        self.assertEqual(item.status, 'completed')
        self.assertEqual(len(item.evidence), 1)
        self.assertFalse(item.evidence[0].content_trusted)
        self.assertEqual(item.evidence[0].source_url, 'https://example.test/research')
        bundle = app_module.build_evidence_context(item.evidence)
        self.assertTrue(bundle.separate_from_approved_memory)
        self.assertEqual(bundle.evidence[0]['source_url'], 'https://example.test/research')
        self.store = ConversationResearchStore()
        self.app.session_state['_conversation_research_store'] = self.store
        completed, _ = self.store.prepare(self.cid, 'latest research query')
        completed.status = 'completed'
        completed.evidence = item.evidence
        app_module.st.session_state['_conversation_research_store'] = self.store
        inference = Mock(return_value={'narrative': 'Done', 'conversational_response': 'Done'})
        with patch.object(app_module, 'service') as service_mock, \
             patch.object(app_module.trainer, 'infer', inference):
            service_mock.cognition.assess.return_value = {}
            app_module._handle_message('latest research query', self.cid, [],
                                       {'identity_name': 'Synthetic'}, Mock(local=True), None)
        reasoning_context = inference.call_args.kwargs['cognitive_context']
        self.assertEqual(reasoning_context['research_evidence'], bundle.serialized_context)

    def test_denial_never_calls_search(self):
        item = app_module._prepare_conversation_research('I feel uncertain about a conversation.', self.cid)
        runner = Mock(side_effect=AssertionError('search must not run without approval'))
        app_module.st.session_state['_conversation_research_store'] = self.store
        with patch.object(app_module, 'BRAVE_SEARCH_RUNNER', runner):
            item.status = 'declined'
            app_module._run_authorized_research(self.cid)
        runner.assert_not_called()
        self.assertEqual(item.status, 'declined')
        self.assertEqual(item.evidence, ())

    def test_duplicate_suppression_survives_store_and_ledger_reuse(self):
        item = app_module._prepare_conversation_research('I feel worried about a difficult conversation.', self.cid)
        app_module.st.session_state['_conversation_research_store'] = self.store
        app_module.st.session_state['_research_authorization_ledger'] = self.ledger
        item.status = 'awaiting_approval'
        runner = Mock(return_value={'status': 'ok', 'error': None, 'results': []})
        with patch.object(app_module, 'BRAVE_SEARCH_RUNNER', runner):
            app_module._run_authorized_research(self.cid)
            item.status = 'awaiting_approval'
            app_module._run_authorized_research(self.cid)
        self.assertEqual(runner.call_count, 1)
        self.assertEqual(item.status, 'duplicate')

    def test_decline_button_never_calls_search(self):
        store = self.store
        self.app.session_state['_conversation_research_store'] = store
        app_module.st.session_state['_conversation_research_store'] = store
        item = app_module._prepare_conversation_research('latest research on fictional topic', self.cid)
        runner = Mock(side_effect=AssertionError('search must not run after denial'))
        self.ui_mock_values['columns'].return_value = (
            Mock(button=Mock(return_value=False)), Mock(button=Mock(return_value=True)))
        with patch.object(app_module, 'BRAVE_SEARCH_RUNNER', runner):
            app_module._render_conversation_research_approval(self.cid)
        runner.assert_not_called()
        self.assertEqual(item.status, 'declined')

    def test_reasoning_progresses_even_when_research_is_pending_or_declined(self):
        store = self.app.session_state['_conversation_research_store']
        item, _ = store.prepare(self.cid, 'conversation concern')
        reasoning = Mock(return_value={'conversational_response': 'Reasoning progressed independently.',
                                       'narrative': 'Safe offline result.'})
        self.app.session_state['studio_inference'] = 'Local model (Ollama)'
        history = conversation.load_messages(self.cid, data_dir=self.fixture.paths['data_dir'],
                                             db_path=self.fixture.paths['db_path'])
        with patch.object(app_module, 'service') as service_mock, \
             patch.object(app_module.trainer, 'infer', reasoning), \
             patch.object(app_module, '_prepare_conversation_research', return_value=item):
            service_mock.cognition.assess.return_value = {}
            app_module._handle_message('I feel worried after a conversation.', self.cid, history,
                                       {'identity_name': 'Synthetic'}, Mock(local=True), None)
        reasoning.assert_called_once()
        evidence_context = reasoning.call_args.kwargs['cognitive_context']
        self.assertNotIn('research_evidence', evidence_context)
        self.assertEqual(item.status, 'awaiting_approval')
        self.assertEqual(len(conversation.load_messages(self.cid, data_dir=self.fixture.paths['data_dir'],
                                                        db_path=self.fixture.paths['db_path'])), 2)

    def test_session_store_prepares_preview_only_for_research_relevant_requests(self):
        self.assertTrue(app_module._research_relevant('What are the latest studies?'))
        self.assertFalse(app_module._research_relevant('I feel worried after a hard conversation.'))
        item = app_module._prepare_conversation_research('latest research on a synthetic topic', self.cid)
        self.assertEqual(item.status, 'awaiting_approval')
        self.assertLessEqual(len(item.query), 180)
        same, created = self.store.prepare(self.cid, item.query)
        self.assertFalse(created)
        self.assertIs(same, item)

    def test_minimization_and_evidence_validation_retain_untrusted_source(self):
        query = app_module._minimized_research_query(
            'I feel worried, email alice@example.test, https://private.test/a, after my colleague stopped replying')
        self.assertNotIn('alice@example.test', query)
        self.assertNotIn('private.test', query)
        records = validate_search_results([{'title': 'Source', 'url': 'https://example.test/path',
                                            'snippet': 'Unverified'}], retrieved_at='synthetic-time')
        self.assertEqual(records[0].source_url, 'https://example.test/path')
        self.assertFalse(records[0].content_trusted)


if __name__ == '__main__':
    unittest.main()
