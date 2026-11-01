"""One identity persists independently of the LLM provider."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core import personality

class PersonalityTests(unittest.TestCase):
    def test_stable_identity_across_reads(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(personality, "PROFILE_PATH", Path(tmp) / "personality.json"):
                first = personality.load()
                second = personality.load()
                self.assertEqual(first["identity_id"], second["identity_id"])
                self.assertEqual(first["traits"], second["traits"])
                self.assertEqual(personality.model_context()["identity_name"], "Sovereign Brain")

    def test_unexpected_identity_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "personality.json"
            target.write_text('{"identity_id":"different"}', encoding="utf-8")
            with patch.object(personality, "PROFILE_PATH", target):
                with self.assertRaises(ValueError):
                    personality.load()

if __name__ == "__main__":
    unittest.main()
