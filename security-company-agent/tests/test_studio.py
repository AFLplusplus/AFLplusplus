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
                turn = studio.add_turn(
                    "An uncertain relationship", "Do not jump to conclusions",
                    {"emotion": "concerned", "_trainer_approved": True}, {"caution": .8},
                    data_dir=root, db_path=root / "brain.sqlite3")
                studio.rate_turn(turn, "good", "Ask about expectations",
                                 data_dir=root, db_path=root / "brain.sqlite3")
                self.assertEqual(studio.inspect_turns(db_path=root / "brain.sqlite3")[0]["rating"], "good")
                text = studio.decode_document("lesson.txt", b"Attachment and trust require mutual respect.")
                studio.add_document("lesson.txt", text, data_dir=root, db_path=root / "brain.sqlite3")
                self.assertIn("mutual respect", studio.relevant_context(
                    "trust and respect", data_dir=root, db_path=root / "brain.sqlite3"))
                self.assertEqual(len(studio.inspect_documents(db_path=root / "brain.sqlite3")), 1)

    def test_read_only_inspection_does_not_create_database_or_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'not-created'
            db_path = root / 'brain.sqlite3'
            with patch.object(studio, 'DATA', root), patch.object(studio, 'DB', db_path):
                self.assertEqual(studio.inspect_turns(db_path=db_path), [])
                self.assertEqual(studio.inspect_documents(db_path=db_path), [])
                self.assertEqual(studio.inspect_research_items(db_path=db_path), [])
                self.assertEqual(studio.feedback_context('anything', data_dir=root, db_path=db_path), [])
                self.assertEqual(studio.relevant_context('anything', data_dir=root, db_path=db_path), '')
            self.assertFalse(root.exists())
            with patch.object(studio, 'DATA', root), patch.object(studio, 'DB', db_path):
                db_before = studio.DB
                studio.add_turn('fixture', '', {'_trainer_approved': True}, {},
                                data_dir=root, db_path=root / 'isolated.sqlite3')
                self.assertTrue((root / 'isolated.sqlite3').exists())
                self.assertEqual(studio.DB, db_before)

    def test_reject_unreviewed_and_unapproved_records(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with self.assertRaisesRegex(ValueError, 'Unreviewed'):
                studio.add_turn('scenario', '', {'_trainer_pending': True}, {}, db_path=root / 'brain.sqlite3')
            with self.assertRaisesRegex(ValueError, 'explicit trainer approval'):
                studio.add_turn('scenario', '', {'_provenance': {'source': 'approved_training'}}, {},
                                db_path=root / 'brain.sqlite3')
            self.assertFalse((root / 'brain.sqlite3').exists())

    def test_reject_large_upload(self):
        with self.assertRaises(ValueError):
            studio.decode_document("sample.md", b"x" * (studio.MAX_UPLOAD + 1))


if __name__ == "__main__":
    unittest.main()
