"""Mocked Conversation review UI tests; no live providers are called."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from brain_core.candidate_learning import CandidateLesson
from brain_core import conversation, lessons
import brain_studio as app_module


class CandidateLearningReviewUITests(unittest.TestCase):
    def setUp(self):
        from test_studio_ui import StudioUITests
        self.fixture = StudioUITests(methodName='test_ui_readiness_inspection_does_not_initialize_runtime_files')
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.fixture.app.run()
        self.app = self.fixture.app
        self.cid = self.app.session_state['conversation_id']
        self.mock_values = {
            'session_state': self.app.session_state,
            'subheader': Mock(), 'caption': Mock(), 'markdown': Mock(), 'write': Mock(),
            'warning': Mock(), 'info': Mock(), 'success': Mock(), 'error': Mock(),
            'text_area': Mock(return_value='Ask for evidence before deciding.'),
            'checkbox': Mock(side_effect=lambda label, value=False, **kwargs: value),
            'columns': Mock(return_value=(Mock(button=Mock(return_value=False)),
                                          Mock(button=Mock(return_value=False)),
                                          Mock(button=Mock(return_value=False)))),
            'rerun': Mock(),
        }
        self.patch_ui = patch.multiple(app_module.st, **self.mock_values)
        self.patch_ui.start()
        self.addCleanup(self.patch_ui.stop)
        self.session_state = self.mock_values['session_state']
        self.candidate = CandidateLesson(
            proposed_principle='Separate stated facts from assumptions before responding.',
            source_references=(('inference', 'model-1', (), (('provider', 'local_ollama'),)),
                               ('web_evidence', 'https://example.test/source',
                                ('https://example.test/source',), (('content_trusted', False),))),
            uncertainty=('Model content is not independently verified.',),
            provenance=((('provider', 'local_ollama'),), (('content_trusted', False),)),
            review_status='pending_review')

    def state(self):
        return {'status': 'candidate_review', 'candidate': self.candidate,
                'conversation_id': self.cid, 'candidate_id': 'candidate-1',
                'reviewed_text': self.candidate.proposed_principle,
                'text_reviewed': False, 'reviewed_text_at_confirmation': None, 'action': None}

    def test_card_is_not_rendered_without_genuine_pending_candidate(self):
        self.session_state['_candidate_learning_review'] = None
        app_module._render_candidate_learning_review(self.cid)
        app_module.st.subheader.assert_not_called()
        self.session_state['_candidate_learning_review'] = {
            **self.state(), 'candidate': {'proposed_principle': 'fake'}}
        app_module._render_candidate_learning_review(self.cid)
        self.assertEqual(app_module.st.subheader.call_count, 0)

    def test_render_card_displays_uncertainty_and_source_references(self):
        self.session_state['_candidate_learning_review'] = self.state()
        app_module._render_candidate_learning_review(self.cid)
        self.assertTrue(any('Uncertainty' in call.args[0] for call in app_module.st.markdown.call_args_list))
        self.assertTrue(any('example.test/source' in repr(call.args) for call in app_module.st.write.call_args_list))

    def test_approval_requires_explicit_confirmation_of_exact_text(self):
        state = self.state()
        self.session_state['_candidate_learning_review'] = state
        self.session_state[f"candidate_confirm_{state['candidate_id']}"] = False
        self.mock_values['columns'].return_value = (
            Mock(button=Mock(return_value=True)), Mock(button=Mock(return_value=False)),
            Mock(button=Mock(return_value=False)))
        with patch.object(app_module.lessons, 'approve') as approve:
            app_module._render_candidate_learning_review(self.cid)
        approve.assert_not_called()
        self.assertNotEqual(state.get('status'), 'approved')

    def test_modify_requires_review_of_final_modified_text_before_approval(self):
        state = self.state()
        state['reviewed_text'] = 'Ask for evidence before deciding.'
        state['action'] = 'modify'
        self.session_state['_candidate_learning_review'] = state
        self.session_state[f"candidate_confirm_{state['candidate_id']}"] = False
        self.mock_values['columns'].return_value = (
            Mock(button=Mock(return_value=True)), Mock(button=Mock(return_value=False)),
            Mock(button=Mock(return_value=False)))
        with patch.object(app_module.lessons, 'approve') as approve:
            app_module._render_candidate_learning_review(self.cid)
        approve.assert_not_called()

    def test_modify_action_marks_candidate_for_re_review(self):
        state = self.state()
        state['reviewed_text'] = 'Ask for evidence before deciding.'
        self.session_state['_candidate_learning_review'] = state
        self.mock_values['columns'].return_value = (
            Mock(button=Mock(return_value=False)), Mock(button=Mock(return_value=True)),
            Mock(button=Mock(return_value=False)))
        app_module._render_candidate_learning_review(self.cid)
        self.assertEqual(state['action'], 'modify')
        self.assertFalse(state['text_reviewed'])

    def test_reject_discards_without_persistent_approval(self):
        state = self.state()
        self.session_state['_candidate_learning_review'] = state
        self.mock_values['columns'].return_value = (
            Mock(button=Mock(return_value=False)), Mock(button=Mock(return_value=False)),
            Mock(button=Mock(return_value=True)))
        with patch.object(app_module.lessons, 'approve') as approve:
            app_module._render_candidate_learning_review(self.cid)
        approve.assert_not_called()
        self.assertEqual(state['status'], 'rejected')

    def test_approval_reuses_existing_supervised_lesson_api_and_is_idempotent(self):
        state = self.state()
        state['text_reviewed'] = True
        state['reviewed_text'] = self.candidate.proposed_principle
        self.session_state['_candidate_learning_review'] = state
        self.session_state[f"candidate_confirm_{state['candidate_id']}"] = True
        self.mock_values['text_area'].return_value = self.candidate.proposed_principle
        self.mock_values['columns'].return_value = (
            Mock(button=Mock(return_value=True)), Mock(button=Mock(return_value=False)),
            Mock(button=Mock(return_value=False)))
        self.mock_values['checkbox'].side_effect = lambda label, value=False, **kwargs: True
        with patch.object(app_module.lessons, 'approve', wraps=lessons.approve) as approve:
            with patch.object(app_module.lessons.studio, 'DATA', self.fixture.paths['data_dir']), \
                 patch.object(app_module.lessons.studio, 'DB', self.fixture.paths['db_path']), \
                 patch.object(app_module.conversation, 'save_lesson_state'):
                app_module._render_candidate_learning_review(self.cid)
        self.assertEqual(approve.call_count, 1)
        self.assertEqual(self.session_state['_candidate_learning_review']['status'], 'approved')
        saved = lessons._lesson_rows(data_dir=self.fixture.paths['data_dir'],
                                     db_path=self.fixture.paths['db_path'], include_revoked=True)
        self.assertEqual(len(saved), 1)
        record = approve.call_args.args[0]
        self.assertEqual(record['approval_status'], 'proposed')

    def test_duplicate_deterministic_lesson_id_does_not_create_duplicate(self):
        state = self.state()
        state['text_reviewed'] = True
        state['reviewed_text'] = self.candidate.proposed_principle
        self.session_state['_candidate_learning_review'] = state
        self.session_state[f"candidate_confirm_{state['candidate_id']}"] = True
        self.mock_values['text_area'].return_value = self.candidate.proposed_principle
        self.mock_values['columns'].return_value = (
            Mock(button=Mock(return_value=True)), Mock(button=Mock(return_value=False)),
            Mock(button=Mock(return_value=False)))
        temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(temp.cleanup)
        db = Path(temp.name) / 'brain.sqlite3'
        self.mock_values['checkbox'].side_effect = lambda label, value=False, **kwargs: True
        with patch.object(app_module.studio, 'DATA', Path(temp.name)), patch.object(app_module.studio, 'DB', db), \
             patch.object(app_module.conversation, 'save_lesson_state'):
            app_module._render_candidate_learning_review(self.cid)
            self.assertEqual(state['status'], 'approved')
            state['status'] = 'candidate_review'
            state['action'] = None
            state['text_reviewed'] = True
            app_module._render_candidate_learning_review(self.cid)
            payload_rows = []
            import sqlite3
            with sqlite3.connect(db) as conn:
                payload_rows = conn.execute('SELECT lesson_id FROM supervised_lessons').fetchall()
            conn = None
        self.assertEqual(len(payload_rows), 1)

    def test_rerun_and_repeated_submission_are_suppressed(self):
        state = self.state()
        state['text_reviewed'] = True
        state['reviewed_text'] = self.candidate.proposed_principle
        self.session_state['_candidate_learning_review'] = state
        self.session_state[f"candidate_confirm_{state['candidate_id']}"] = True
        self.mock_values['text_area'].return_value = self.candidate.proposed_principle
        self.mock_values['checkbox'].side_effect = lambda label, value=False, **kwargs: True
        self.mock_values['columns'].return_value = (
            Mock(button=Mock(return_value=True)), Mock(button=Mock(return_value=False)),
            Mock(button=Mock(return_value=False)))
        with patch.object(app_module.lessons, 'approve') as approve:
            app_module._render_candidate_learning_review(self.cid)
            app_module._render_candidate_learning_review(self.cid)
        self.assertEqual(approve.call_count, 1)
        self.assertEqual(self.session_state['_candidate_learning_review']['status'], 'approved')


if __name__ == '__main__':
    unittest.main()
