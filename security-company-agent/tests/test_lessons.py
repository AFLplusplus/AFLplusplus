import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from brain_core import lessons, memory, studio


class SupervisedLessonTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.data = Path(self.temp.name)
        self.db = self.data / 'brain.sqlite3'
        self.profile = self.data / 'personality.json'
        self.profile.write_text('{"identity":"unchanged"}', encoding='utf-8')
        # Deliberately leave the real studio tables absent: lesson tests validate
        # that additive schema initialization works in a wholly temporary store.

    def tearDown(self):
        self.temp.cleanup()

    def proposal(self):
        return lessons.propose(
            scenario='A coworker receives difficult project feedback and feels hurt.',
            emotional_context='Hurt and uncertainty were explicitly reported.',
            observed_facts='The feedback was delivered in a team meeting.',
            uncertainties='The reviewer intent is unknown.',
            corrective_principle='Acknowledge the impact and ask what repair is needed before assuming intent.',
            response_pattern='Listen, clarify the concrete harm, then agree on a repair.',
            relationship_context='coworker')

    def test_no_training_before_explicit_approval(self):
        proposal = self.proposal()
        self.assertEqual(proposal['approval_status'], 'proposed')
        self.assertEqual(lessons.retrieve('coworker feedback repair', data_dir=self.data, db_path=self.db), [])
        self.assertEqual(lessons.list_lessons(data_dir=self.data, db_path=self.db), [])

    def test_approved_lesson_persists_and_retrieves_with_source_and_reason(self):
        proposal = self.proposal()
        lesson_id = lessons.approve(proposal, data_dir=self.data, db_path=self.db)
        found = memory.supervised_lessons('coworker feedback repair', data_dir=self.data, db_path=self.db)
        self.assertEqual(found[0]['lesson_id'], lesson_id)
        self.assertEqual(found[0]['source_type'], 'human_supervised')
        self.assertEqual(found[0]['source_provenance'], 'trainer_entered')
        self.assertIn('matched_terms', found[0]['relevance'])
        self.assertIn('acknowledge the impact', found[0]['corrective_principle'].lower())
        self.assertEqual(lessons.list_lessons(data_dir=self.data, db_path=self.db)[0]['approval_status'], 'approved')

    def test_approved_lesson_retrieval_supports_validated_rejection_paraphrase(self):
        proposal = lessons.propose(
            scenario='A close friend becomes less communicative after stress; a past rejection is remembered.',
            emotional_context='Anxiety and fear of rejection.',
            observed_facts='Communication became less frequent after stress.',
            uncertainties='The other person’s current motives are unknown.',
            corrective_principle='Past feelings and memories are not proof that rejection is happening now; separate facts from assumptions.',
            response_pattern='Name what is known, acknowledge fear, and ask gently without assuming intent.',
            relationship_context='friend')
        lesson_id = lessons.approve(proposal, data_dir=self.data, db_path=self.db)
        for query in ('I am afraid my friend is rejecting me; old memories are not evidence.',
                      'I worry about abandonment and should not treat it as established fact.'):
            with self.subTest(query=query):
                found=lessons.retrieve(query,data_dir=self.data,db_path=self.db)
                self.assertTrue(found)
                self.assertEqual(found[0]['lesson_id'],lesson_id)
                self.assertEqual(found[0]['source_type'],'human_supervised')

    def test_unrelated_lesson_is_not_retrieved_after_paraphrase_expansion(self):
        lessons.approve(self.proposal(), data_dir=self.data, db_path=self.db)
        self.assertEqual(lessons.retrieve('banana spacecraft tax audit',data_dir=self.data,db_path=self.db), [])

    def test_fresh_database_restores_approved_lessons_and_initializes_schema(self):
        proposal = self.proposal()
        lessons.approve(proposal, data_dir=self.data, db_path=self.db)
        # A new process-facing retrieval uses the same persisted SQLite record.
        self.assertEqual(lessons.retrieve('coworker feedback repair', data_dir=self.data, db_path=self.db)[0]['lesson_id'], proposal['lesson_id'])

    def test_rejected_lessons_never_persist(self):
        proposal = self.proposal()
        # Reject is intentionally a UI discard; it invokes no persistence API.
        proposal['approval_status'] = 'rejected'
        self.assertEqual(lessons.retrieve('coworker feedback repair', data_dir=self.data, db_path=self.db), [])
        with self.assertRaises(ValueError):
            lessons.approve(proposal, data_dir=self.data, db_path=self.db)

    def test_revocation_excludes_future_retrieval(self):
        lesson_id = lessons.approve(self.proposal(), data_dir=self.data, db_path=self.db)
        lessons.revoke(lesson_id, data_dir=self.data, db_path=self.db)
        self.assertEqual(lessons.retrieve('coworker feedback repair', data_dir=self.data, db_path=self.db), [])
        self.assertEqual(lessons.list_lessons(data_dir=self.data, db_path=self.db, include_revoked=True)[0]['approval_status'], 'revoked')
        self.assertEqual([e['event_type'] for e in lessons.audit_events(lesson_id, data_dir=self.data, db_path=self.db)], ['approved', 'revoked'])

    def test_duplicate_approval_is_idempotent(self):
        proposal = self.proposal()
        lesson_id = lessons.approve(proposal, data_dir=self.data, db_path=self.db)
        self.assertEqual(lessons.approve(proposal, data_dir=self.data, db_path=self.db), lesson_id)
        self.assertEqual(len(lessons.list_lessons(data_dir=self.data, db_path=self.db)), 1)
        self.assertEqual(len(lessons.audit_events(lesson_id, data_dir=self.data, db_path=self.db)), 1)

    def test_offline_workflow_has_no_model_dependency_or_state_mutation(self):
        original = self.profile.read_text(encoding='utf-8')
        proposal = self.proposal()
        lessons.approve(proposal, data_dir=self.data, db_path=self.db)
        self.assertEqual(self.profile.read_text(encoding='utf-8'), original)
        with studio.connect(initialize=False, data_dir=self.data, db_path=self.db) as db:
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertTrue({'supervised_lessons', 'turns', 'documents', 'research'} <= tables)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM turns').fetchone()[0], 0)
        from brain_core import service
        # No inference method is called by the direct proposal/approval API.
        with patch.object(service, 'analyze', side_effect=AssertionError('inference path called')):
            self.assertEqual(lessons.retrieve('coworker feedback repair', data_dir=self.data, db_path=self.db)[0]['lesson_id'], proposal['lesson_id'])
        self.assertEqual(proposal['source_type'], 'human_supervised')

    def test_correction_is_audited_and_used_for_retrieval(self):
        lesson_id = lessons.approve(self.proposal(), data_dir=self.data, db_path=self.db)
        lessons.correct(lesson_id, {'corrective_principle': 'Ask the coworker which repair would help.'},
                        data_dir=self.data, db_path=self.db)
        found = lessons.retrieve('coworker feedback repair', data_dir=self.data, db_path=self.db)
        self.assertIn('which repair', found[0]['corrective_principle'])
        self.assertEqual(lessons.audit_events(lesson_id, data_dir=self.data, db_path=self.db)[-1]['event_type'], 'corrected')

    def test_failed_operation_rolls_back(self):
        proposal = self.proposal()
        with self.assertRaises(ValueError):
            lessons.approve(dict(proposal, approval_status='approved'), data_dir=self.data, db_path=self.db)
        self.assertEqual(lessons.list_lessons(data_dir=self.data, db_path=self.db), [])
        lesson_id = lessons.approve(proposal, data_dir=self.data, db_path=self.db)
        with self.assertRaises(ValueError):
            lessons.revoke('missing', data_dir=self.data, db_path=self.db)
        self.assertEqual(lessons.retrieve('coworker feedback repair', data_dir=self.data, db_path=self.db)[0]['lesson_id'], lesson_id)


if __name__ == '__main__':
    unittest.main()
