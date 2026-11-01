import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core import trainer

class BrainTests(unittest.TestCase):
    def test_offline_train_and_memory(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(trainer, "STATE_PATH", Path(d) / "state.json"), \
                 patch.object(trainer, "HISTORY_PATH", Path(d) / "history.json"):
                state, result = trainer.train("A colleague is worried", "Respond empathetically", mock=True)
                self.assertEqual(state["iterations"], 1)
                self.assertEqual(result["emotion"], "curious")
                _, history = trainer.status()
                self.assertEqual(len(history["rules"]), 1)
                self.assertEqual(len(history["history"]), 1)

    def test_reject_out_of_range(self):
        obj = trainer.infer("scenario", "", {}, {}, mock=True)
        obj["chemical_indexes"]["cortisol"] = 500
        with self.assertRaises(ValueError):
            trainer.validate(obj)

if __name__ == "__main__":
    unittest.main()
