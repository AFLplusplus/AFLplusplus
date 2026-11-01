"""Streamlit UI regression tests, strictly offline with isolated temporary stores."""
from contextlib import ExitStack
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core import trainer, studio, model_api, runtime_guard, personality
from streamlit.testing.v1 import AppTest

class StudioUITests(unittest.TestCase):
    def setUp(self):
        self.context = ExitStack()
        self.addCleanup(self.context.close)
        root = Path(self.context.enter_context(tempfile.TemporaryDirectory()))
        for owner, key, value in ((personality, 'PROFILE_PATH', root / 'personality.json'),
                                   (trainer, 'STATE_PATH', root / 'state.json'),
                                   (trainer, 'HISTORY_PATH', root / 'history.json'),
                                   (studio, 'DATA', root), (studio, 'DB', root / 'brain.sqlite3')):
            self.context.enter_context(patch.object(owner, key, value))
        self.context.enter_context(patch.object(model_api, 'local_inventory', return_value=[]))
        self.context.enter_context(patch.object(runtime_guard, 'available_memory_gib', return_value=0.8))
        self.app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / 'brain_studio.py'),
                                     default_timeout=20)

    def test_offline_scenario_feedback_and_fresh_session(self):
        app = self.app.run()
        self.assertEqual(list(app.exception), [])
        next(area for area in app.text_area if area.label == 'Situation').set_value(
            'I love someone, feel anger, hurt and fear of losing her, and am indecisive.')
        app.run()
        next(button for button in app.button if button.label == 'Analyze emotions and decide').click()
        app.run()
        self.assertEqual(list(app.exception), [])
        self.assertEqual(len(app.dataframe), 1)
        next(area for area in app.text_area if area.label == 'Correct the response / challenge its recommendation').set_value(
            'First distinguish uncertainty from established exploitation.')
        next(radio for radio in app.radio if radio.label == 'Rate emotional appropriateness').set_value('partial')
        next(button for button in app.button if button.label == 'Save trainer feedback').click()
        app.run()
        self.assertEqual(list(app.exception), [])
        self.assertEqual(studio.recent_turns()[0]['rating'], 'partial')
        self.assertIn('established exploitation', studio.recent_turns()[0]['commentary'])
        # A separate UI session reads persisted stores, not the original session_state.
        fresh = AppTest.from_file(str(Path(__file__).resolve().parents[1] / 'brain_studio.py')).run()
        self.assertEqual(list(fresh.exception), [])
        self.assertEqual(trainer.status()[0]['iterations'], 1)
        self.assertEqual(len(studio.recent_turns()), 1)

    def test_missing_local_model_is_visible_and_prevents_inference(self):
        app = self.app.run()
        next(radio for radio in app.radio if radio.label == 'Inference').set_value('Local model (Ollama)')
        app.run()
        self.assertEqual(list(app.exception), [])
        self.assertTrue(any('not installed' in warning.value for warning in app.warning))
        self.assertTrue(next(button for button in app.button if button.label == 'Analyze emotions and decide').disabled)

if __name__ == '__main__':
    unittest.main()
