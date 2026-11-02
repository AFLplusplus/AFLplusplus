"""One identity persists independently of the LLM provider."""
import json
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
            target = Path(tmp) / "personality.json"
            with patch.object(personality, "PROFILE_PATH", target):
                first = personality.load(profile_path=target, initialize=True)
                second = personality.load(profile_path=target, initialize=True)
                self.assertEqual(first["identity_id"], second["identity_id"])
                self.assertEqual(first["traits"], second["traits"])
                self.assertEqual(personality.model_context(profile=first)["identity_name"], "Sovereign Brain")
                self.assertTrue(target.exists())

    def test_inspection_does_not_mutate_profile_bytes_or_identity_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'personality.json'
            marker = target.with_suffix('.identity')
            with patch.object(personality, 'PROFILE_PATH', target):
                self.assertIsNone(personality.inspect())
            self.assertFalse(target.exists())
            self.assertFalse(marker.exists())

    def test_importing_personality_module_does_not_create_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'personality.json'
            marker = target.with_suffix('.identity')
            with patch.object(personality, 'PROFILE_PATH', target):
                self.assertFalse(target.exists())
                self.assertFalse(marker.exists())
                self.assertIsNone(personality.inspect())
            self.assertFalse(target.exists())
            self.assertFalse(marker.exists())

    def test_inspect_existing_profile_is_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'personality.json'
            with patch.object(personality, 'PROFILE_PATH', target):
                expected = dict(personality.DEFAULT)
                target.write_text(json.dumps(expected), encoding='utf-8')
                marker = target.with_suffix('.identity')
                marker.write_text(expected['identity_id'], encoding='utf-8')
                profile_before, marker_before = target.read_bytes(), marker.read_bytes()
                self.assertEqual(personality.inspect(), expected)
                self.assertEqual(target.read_bytes(), profile_before)
                self.assertEqual(marker.read_bytes(), marker_before)

    def test_unexpected_identity_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "personality.json"
            target.write_text('{"identity_id":"different"}', encoding="utf-8")
            with patch.object(personality, "PROFILE_PATH", target):
                with self.assertRaises(ValueError):
                    personality.load(profile_path=target, initialize=True)

if __name__ == "__main__":
    unittest.main()
