"""Streamlit UI regression tests, strictly offline with isolated temporary stores."""
from contextlib import ExitStack
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core import trainer, studio, model_api, runtime_guard, personality, service
from streamlit.testing.v1 import AppTest

class StudioUITests(unittest.TestCase):
    def setUp(self):
        self.context = ExitStack()
        self.addCleanup(self.context.close)
        root = Path(self.context.enter_context(tempfile.TemporaryDirectory()))
        self.root = root
        self.paths = {'profile_path': root / 'personality.json',
                      'state_path': root / 'state.json', 'history_path': root / 'history.json',
                      'data_dir': root, 'db_path': root / 'brain.sqlite3'}
        self.active_paths = (Path(__file__).resolve().parents[1] / 'brain_core' / name
                             for name in ('personality.json', 'eq_matrix.json', 'trainer_history.json'))
        self.active_paths = tuple(self.active_paths) + (
            Path(__file__).resolve().parents[1] / 'brain_core' / 'personality.identity',
            Path(__file__).resolve().parents[1] / 'brain_core' / 'studio_data' / 'brain.sqlite3')
        self.active_before = {path: (path.exists(), path.read_bytes() if path.is_file() else None)
                              for path in self.active_paths}
        for owner, key, value in ((personality, 'PROFILE_PATH', self.paths['profile_path']),
                                   (trainer, 'STATE_PATH', self.paths['state_path']),
                                   (trainer, 'HISTORY_PATH', self.paths['history_path']),
                                   (studio, 'DATA', self.paths['data_dir']),
                                   (studio, 'DB', self.paths['db_path'])):
            self.context.enter_context(patch.object(owner, key, value))
        self.context.enter_context(patch.object(model_api, 'local_inventory', return_value=[]))
        self.context.enter_context(patch.object(runtime_guard, 'available_memory_gib', return_value=0.8))
        self.service_analyze = self.context.enter_context(patch.object(service, 'analyze', wraps=service.analyze))
        self.context.enter_context(patch('brain_studio.selected_local_model', return_value='offline-only-test-model'))
        script = str(Path(__file__).resolve().parents[1] / 'brain_studio.py')
        self.app = AppTest.from_file(script, default_timeout=20)
        self.fresh_app = AppTest.from_file(script, default_timeout=20)

    def test_offline_scenario_feedback_and_fresh_session(self):
        app = self.app.run()
        self.assertEqual(list(app.exception), [])
        next(area for area in app.text_area if area.label == 'Situation').set_value(
            'I love someone, feel anger, hurt and fear of losing her, and am indecisive.')
        app.run()
        next(button for button in app.button if button.label == 'Analyze emotions and decide').click()
        app.run()
        self.assertEqual(list(app.exception), [])
        self.assertEqual(self.service_analyze.call_count, 1)
        self.assertIs(self.service_analyze.call_args.kwargs['mock'], True)
        self.assertEqual(Path(self.service_analyze.call_args.kwargs['db_path']), self.root / 'brain.sqlite3')
        self.assertTrue((self.root / 'brain.sqlite3').exists())
        turns = studio.inspect_turns(db_path=self.root / 'brain.sqlite3')
        self.assertEqual(len(turns), 1)
        self.assertIn('offline_fixture', turns[0]['result_json'])
        self.assertNotIn('_trainer_approved', turns[0]['result_json'])
        next(area for area in app.text_area if area.label == 'Correct the response / challenge its recommendation').set_value(
            'First distinguish uncertainty from established exploitation.')
        next(radio for radio in app.radio if radio.label == 'Rate emotional appropriateness').set_value('partial')
        next(button for button in app.button if button.label == 'Save trainer feedback').click()
        app.run()
        self.assertEqual(list(app.exception), [])
        self.assertEqual(self.service_analyze.call_count, 1)
        self.assertIsNone(studio.inspect_turns(db_path=self.root / 'brain.sqlite3')[0]['rating'])
        self.assertEqual(self.active_before,
                         {path: (path.exists(), path.read_bytes() if path.is_file() else None)
                          for path in self.active_paths})
        # A separate UI session reads persisted stores, not the original session_state.
        fresh = self.fresh_app.run()
        self.assertEqual(list(fresh.exception), [])
        self.assertFalse((self.root / 'personality.json').exists())
        self.assertFalse((self.root / 'personality.identity').exists())
        self.assertIsNone(trainer.inspect_status(state_path=Path(self.root) / 'state.json',
                                                 history_path=Path(self.root) / 'history.json')[0])
        self.assertEqual(len(studio.inspect_turns(db_path=self.root / 'brain.sqlite3')), 1)

    def test_ui_readiness_inspection_does_not_initialize_runtime_files(self):
        app = self.app.run()
        self.assertEqual(list(app.exception), [])
        self.assertFalse((self.root / 'personality.json').exists())
        self.assertFalse((self.root / 'personality.identity').exists())
        self.assertFalse((self.root / 'state.json').exists())
        self.assertFalse((self.root / 'history.json').exists())
        self.assertFalse((self.root / 'brain.sqlite3').exists())
        self.assertFalse(Path(trainer.STATE_PATH).exists())
        self.assertFalse(Path(trainer.HISTORY_PATH).exists())
        self.assertFalse(Path(personality.PROFILE_PATH).exists())
        self.assertFalse(Path(studio.DB).exists())
        self.assertEqual(self.active_before,
                         {path: (path.exists(), path.read_bytes() if path.is_file() else None)
                          for path in self.active_paths})

    def test_model_output_error_is_friendly_and_retryable(self):
        from brain_core.model_api import ModelOutputError
        with patch('brain_core.service.analyze', side_effect=ModelOutputError('private validation detail')):
            app = self.app.run()
            next(area for area in app.text_area if area.label == 'Situation').set_value(
                'My colleague was blamed after my mistake and I feel guilty and afraid.')
            app.run()
            next(button for button in app.button if button.label == 'Analyze emotions and decide').click()
            app.run()
        self.assertEqual(list(app.exception), [])
        self.assertTrue(any('reasoning quality checks' in error.value for error in app.error))
        self.assertFalse(any('private validation detail' in error.value for error in app.error))
        self.assertTrue(any(button.label == 'Retry analysis' for button in app.button))
        self.assertEqual(trainer.inspect_status(state_path=self.root / 'state.json',
                                                history_path=self.root / 'history.json')[0], None)
        self.assertEqual(studio.inspect_turns(db_path=self.root / 'brain.sqlite3'), [])
        self.assertFalse((self.root / 'personality.json').exists())
        self.assertFalse((self.root / 'personality.identity').exists())
        self.assertFalse((self.root / 'state.json').exists())
        self.assertFalse((self.root / 'history.json').exists())
        self.assertFalse((self.root / 'brain.sqlite3').exists())
        self.assertEqual(self.active_before,
                         {path: (path.exists(), path.read_bytes() if path.is_file() else None)
                          for path in self.active_paths})

    def test_missing_local_model_is_visible_and_prevents_inference(self):
        app = self.app.run()
        next(radio for radio in app.radio if radio.label == 'Inference').set_value('Local model (Ollama)')
        app.run()
        self.assertEqual(list(app.exception), [])
        self.assertTrue(any('not installed' in warning.value for warning in app.warning))
        self.assertTrue(next(button for button in app.button if button.label == 'Analyze emotions and decide').disabled)

if __name__ == '__main__':
    unittest.main()
