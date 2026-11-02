import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core import trainer, personality

class BrainTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.paths = {'personality': root / 'personality.json', 'state': root / 'state.json',
                      'history': root / 'history.json'}
        for owner, name, value in ((personality, 'PROFILE_PATH', self.paths['personality']),
                                   (trainer, 'STATE_PATH', self.paths['state']),
                                   (trainer, 'HISTORY_PATH', self.paths['history'])):
            p = patch.object(owner, name, value)
            p.start()
            self.addCleanup(p.stop)

    def test_offline_fixture_rejects_active_runtime_paths(self):
        from brain_core.model_api import ModelOutputError
        paths = (trainer.STATE_PATH, trainer.HISTORY_PATH, Path(__file__).resolve().parents[1] / 'brain_core' / 'studio_data' / 'brain.sqlite3')
        before = [(path.exists(), path.read_bytes() if path.is_file() else None) for path in paths]
        with self.assertRaisesRegex(ModelOutputError, 'injected temporary'):
            trainer.train('An offline fixture', mock=True)
        self.assertEqual(before, [(path.exists(), path.read_bytes() if path.is_file() else None) for path in paths])

    def test_offline_fixture_runs_without_creating_training_memory(self):
        _, state, result = trainer.train("A colleague is worried", "Respond empathetically", mock=True,
                                     state_path=self.paths['state'], history_path=self.paths['history'],
                                     data_dir=self.temp.name, db_path=Path(self.temp.name) / 'brain.sqlite3',
                                     persistent_profile=dict(personality.DEFAULT), initialize_profile=False)
        self.assertEqual(state["iterations"], 0)
        self.assertEqual(result["emotion"], "curious")
        self.assertFalse(self.paths['state'].exists())
        self.assertFalse(self.paths['history'].exists())

    def test_importing_configuration_and_read_only_status_do_not_create_active_files(self):
        import brain_core.model_policy
        import brain_core.local_runtime
        import brain_core.studio
        from brain_core import studio
        active = (personality.PROFILE_PATH, trainer.STATE_PATH, trainer.HISTORY_PATH, studio.DB)
        before = {path: path.exists() for path in active}
        import brain_core.model_policy
        brain_core.model_policy.selected_local_model()
        trainer.inspect_status(state_path=self.paths['state'], history_path=self.paths['history'])
        personality.inspect(profile_path=self.paths['personality'])
        studio.inspect_turns(db_path=Path(self.temp.name) / 'brain.sqlite3')
        studio.inspect_documents(db_path=Path(self.temp.name) / 'brain.sqlite3')
        studio.inspect_research_items(db_path=Path(self.temp.name) / 'brain.sqlite3')
        self.assertEqual(before, {path: path.exists() for path in active})

    def test_read_only_status_does_not_initialize_state_or_history(self):
        before = {path: path.exists() for path in (personality.PROFILE_PATH, trainer.STATE_PATH, trainer.HISTORY_PATH)}
        self.assertEqual(trainer.inspect_status(state_path=self.paths['state'], history_path=self.paths['history']),
                         (None, {'history': [], 'rules': []}))
        active = (personality.PROFILE_PATH, trainer.STATE_PATH, trainer.HISTORY_PATH)
        self.assertTrue(all(path.parent == Path(self.temp.name) for path in active))
        self.assertEqual(before, {path: path.exists() for path in before})

    def test_automated_training_writes_only_to_injected_paths(self):
        state_path = Path(self.temp.name) / 'alt-state.json'
        history_path = Path(self.temp.name) / 'alt-history.json'
        active_before = {path: path.exists() for path in
                         (personality.PROFILE_PATH, trainer.STATE_PATH, trainer.HISTORY_PATH)}
        trainer.train('A colleague is worried', mock=True, state_path=state_path, history_path=history_path,
                      data_dir=self.temp.name, db_path=Path(self.temp.name) / 'test.sqlite3',
                      persistent_profile=dict(personality.DEFAULT), initialize_profile=False, persist_fixture_state=True)
        self.assertFalse(state_path.exists())
        self.assertFalse(history_path.exists())
        self.assertEqual(active_before, {path: path.exists() for path in active_before})

    def test_reject_out_of_range(self):
        obj = trainer.infer("scenario", "", {}, {}, mock=True, state_path=self.paths['state'],
                            history_path=self.paths['history'], data_dir=self.temp.name,
                            db_path=Path(self.temp.name) / 'test.sqlite3')
        obj["chemical_indexes"]["cortisol"] = 500
        with self.assertRaises(ValueError):
            trainer.validate(obj)

if __name__ == "__main__":
    unittest.main()
