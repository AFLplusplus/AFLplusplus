"""Tests for local Brain Studio storage; no network or model service required."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core import studio

class StudioTests(unittest.TestCase):
    def test_scenario_feedback_and_document_retrieval(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with patch.object(studio, "DATA", root), patch.object(studio, "DB", root / "brain.sqlite3"):
                turn = studio.add_turn("An uncertain relationship", "Do not jump to conclusions",
                                       {"emotion": "concerned"}, {"caution": .8})
                studio.rate_turn(turn, "good", "Ask about expectations")
                self.assertEqual(studio.recent_turns()[0]["rating"], "good")
                text = studio.decode_document("lesson.txt", b"Attachment and trust require mutual respect.")
                studio.add_document("lesson.txt", text)
                self.assertIn("mutual respect", studio.relevant_context("trust and respect"))
                self.assertEqual(len(studio.documents()), 1)

    def test_reject_large_upload(self):
        with self.assertRaises(ValueError):
            studio.decode_document("sample.md", b"x" * (studio.MAX_UPLOAD + 1))

if __name__ == "__main__":
    unittest.main()
