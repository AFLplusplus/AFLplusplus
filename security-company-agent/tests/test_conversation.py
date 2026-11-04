"""Deterministic conversation routing and isolated local persistence tests."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core import conversation, studio, lessons


class ConversationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / 'brain.sqlite3'
        studio.initialize_store(data_dir=self.root, db_path=self.db)

    def test_explicit_memory_intent_precedes_structured_labels_and_actions(self):
        text = ('Search approved memory for rejection. Scenario summary: not a new lesson. '
                'Emotional context: fear. Observed facts: silence. Assumptions: cause unknown. '
                'Corrective principle: separate facts from assumptions. Response pattern: ask calmly.')
        self.assertEqual(conversation.classify_intent(text).intent, 'memory_recall')

    def test_routes_explicit_training_correction_recall_greeting_and_reasoning(self):
        self.assertEqual(conversation.classify_intent('Brain, I want to teach you that silence is not necessarily rejection.').intent, 'training')
        self.assertEqual(conversation.classify_intent('I want to teach you that silence is ambiguous.').intent, 'training')
        self.assertEqual(conversation.classify_intent('What do you remember about rejection?').intent, 'memory_recall')
        self.assertEqual(conversation.classify_intent('What do I remember about rejection?').intent, 'emotional_reasoning')
        self.assertEqual(conversation.classify_intent(
            'A close friend has suddenly become less communicative after a stressful week. I feel anxious and assume they no longer value our friendship.\n\n'
            'How should I interpret this situation, and what would be a thoughtful response?\n\n'
            'Use any relevant approved memories when reasoning, but do not create or modify a training lesson.'
        ).intent, 'emotional_reasoning')
        self.assertEqual(conversation.classify_intent('Do not create a lesson.').intent, 'emotional_reasoning')
        self.assertEqual(conversation.classify_intent('Do not create a lesson. How should I respond to my friend?').intent, 'emotional_reasoning')
        self.assertEqual(conversation.classify_intent('This is not a training request.').intent, 'emotional_reasoning')
        self.assertEqual(conversation.classify_intent('Do not modify memory.').intent, 'emotional_reasoning')
        self.assertNotEqual(conversation.classify_intent('Use relevant approved memories, but do not create or modify a training lesson.').intent, 'training')
        self.assertEqual(conversation.classify_intent('Cancel this training draft.').intent, 'training_cancel')
        self.assertEqual(conversation.classify_intent('I want to teach you that silence can be ambiguous.').intent, 'training')
        self.assertEqual(conversation.classify_intent('Analyze and teach you a lesson from this.').intent, 'emotional_reasoning')
        self.assertEqual(conversation.classify_intent('How should I respond? Do not create a lesson from this: Scenario summary: x').intent, 'emotional_reasoning')
        for denied in ('Do not create a lesson.', 'This is not a training request.',
                       'Do not modify memory.', 'Use relevant approved memories, but do not create or modify a training lesson.'):
            self.assertNotEqual(conversation.classify_intent(denied).intent, 'training', denied)
        self.assertEqual(conversation.classify_intent('Search approved memory for emotional rejection.').intent, 'memory_recall')
        self.assertEqual(conversation.classify_intent('Recall the lesson about silence.').intent, 'memory_recall')
        self.assertEqual(conversation.classify_intent('What did I teach you previously?').intent, 'memory_recall')
        self.assertEqual(conversation.classify_intent('Show my approved lessons.').intent, 'memory_recall')
        self.assertEqual(conversation.classify_intent('Can you search approved memory for emotional rejection?').intent, 'memory_recall')
        self.assertEqual(conversation.classify_intent('Please continue the training draft.').intent, 'training_resume')
        self.assertEqual(conversation.classify_intent('Cancel this training draft.').intent, 'training_cancel')
        structured = 'Scenario summary: person feels uncertain\\nEmotional context: fear\\nObserved facts: silence\\nAssumptions or uncertainties: cause unknown\\nCorrective principle: do not assume\\nRecommended response pattern: communicate calmly'
        self.assertEqual(conversation.classify_intent(structured).intent, 'training')
        self.assertEqual(conversation.classify_intent('Analyze this structured lesson text instead: ' + structured).intent, 'emotional_reasoning')
        self.assertEqual(conversation.classify_intent('Submit as a lesson: ' + structured).intent, 'training')
        self.assertEqual(conversation.classify_intent('Submit as a lesson: ' + structured).intent, 'training')
        self.assertEqual(conversation.classify_intent('Please teach you this principle, then analyze the following situation.').intent, 'emotional_reasoning')
        self.assertEqual(conversation.classify_intent('Approve this lesson').intent, 'lesson_approval')
        self.assertEqual(conversation.classify_intent('Reject this proposal').intent, 'lesson_rejection')
        self.assertEqual(conversation.classify_intent('Your interpretation was wrong. Silence is not always abandonment.').intent, 'correction')
        self.assertEqual(conversation.classify_intent('What have I taught you about emotional attachment?').intent, 'memory_recall')
        self.assertEqual(conversation.classify_intent('Approve this proposal, then recall the approved lessons').intent, 'memory_recall')
        self.assertEqual(conversation.classify_intent('Hello, Brain. How are you?').intent, 'general')
        self.assertEqual(conversation.classify_intent('Someone I care about stopped responding. How should I interpret this?').intent, 'emotional_reasoning')

    def test_extracts_all_lesson_fields_without_filling_missing_values(self):
        text = '''Scenario summary:\nA person experiences emotional distance.\nEmotional context:\nFear, sadness and uncertainty.\nObserved facts:\nCommunication has decreased.\nAssumptions or uncertainties:\nSilence does not prove rejection.\nCorrective principle:\nPast rejection memories are not evidence of present rejection.\nRecommended response pattern:\nSeek clarification respectfully.'''
        values = conversation.extract_lesson_fields(text)
        self.assertEqual(set(values), {'scenario_summary','emotional_context','observed_facts','assumptions_or_uncertainties','corrective_principle','recommended_response_pattern'})
        self.assertEqual(conversation.extract_lesson_fields(
            'I want to teach you: silence is ambiguous. ' + text)['scenario_summary'],
            'A person experiences emotional distance.')
        proposal, fields = conversation.prepare_lesson(text)
        self.assertEqual(proposal['scenario_summary'], 'A person experiences emotional distance.')
        self.assertEqual(proposal['corrective_principle'], 'Past rejection memories are not evidence of present rejection.')
        self.assertEqual(proposal['emotional_context'], 'Fear, sadness and uncertainty.')
        self.assertEqual(proposal['observed_facts'], 'Communication has decreased.')
        self.assertEqual(proposal['assumptions_or_uncertainties'], 'Silence does not prove rejection.')
        self.assertEqual(proposal['recommended_response_pattern'], 'Seek clarification respectfully.')
        self.assertNotIn('relationship_context', fields)
        self.assertIsNone(conversation.prepare_lesson('Scenario summary: only')[0])
        self.assertEqual(conversation.missing_lesson_fields({'scenario_summary':'x'}),
                         ['Emotional context', 'Observed facts', 'Assumptions or uncertainties',
                          'Corrective principle', 'Recommended response pattern'])

    def test_memory_retrieval_examples_precede_draft_continuation(self):
        draft = {'status': 'incomplete', 'fields': {'scenario_summary': 'unfinished'}}
        for query in ('What do you remember about rejection?',
                      'Search approved memory for emotional rejection.',
                      'Recall the lesson about silence.',
                      'What did I teach you previously?',
                      'Show my approved lessons.'):
            route = conversation.classify_intent(query)
            if draft and draft['status'] == 'incomplete' and route.intent not in (
                    'memory_recall', 'lesson_approval', 'lesson_rejection', 'training_cancel', 'training_resume', 'correction'):
                route = conversation.Route('training_follow_up', 'contextual', 'draft continuation')
            self.assertEqual(route.intent, 'memory_recall', query)

    def test_incomplete_draft_can_be_explicitly_canceled_without_touching_approved_lessons(self):
        session_id = conversation.create_session(data_dir=self.root, db_path=self.db)
        proposal, _ = conversation.prepare_lesson('Scenario summary: existing approved memory\nEmotional context: calm\nObserved facts: none\nAssumptions or uncertainties: none\nCorrective principle: preserve memory\nRecommended response pattern: reflect')
        lesson_id = lessons.approve(proposal, data_dir=self.root, db_path=self.db)
        conversation.save_lesson_state(session_id, {'conversation_id': session_id, 'status': 'incomplete', 'fields': {'scenario_summary': 'unfinished'}}, data_dir=self.root, db_path=self.db)
        self.assertEqual(conversation.classify_intent('Cancel this training draft').intent, 'training_cancel')
        conversation.save_lesson_state(session_id, None, data_dir=self.root, db_path=self.db)
        self.assertIsNone(conversation.load_lesson_state(session_id, data_dir=self.root, db_path=self.db))
        self.assertEqual(lessons.retrieve('existing approved memory', data_dir=self.root, db_path=self.db)[0]['lesson_id'], lesson_id)
        self.assertEqual(len(lessons.audit_events(lesson_id, data_dir=self.root, db_path=self.db)), 1)

    def test_pending_draft_remains_conversation_scoped_while_memory_is_read(self):
        from brain_core import memory
        first = conversation.create_session(data_dir=self.root, db_path=self.db)
        second = conversation.create_session('Another conversation', data_dir=self.root, db_path=self.db)
        proposal, _ = conversation.prepare_lesson(
            'Scenario summary: rejection fears\nEmotional context: uncertainty\nObserved facts: silence\n'
            'Assumptions or uncertainties: cause unknown\nCorrective principle: distinguish facts\n'
            'Recommended response pattern: communicate calmly')
        lesson_id = lessons.approve(proposal, data_dir=self.root, db_path=self.db)
        draft = {'conversation_id': first, 'status': 'incomplete', 'fields': {'scenario_summary': 'unfinished'}}
        conversation.save_lesson_state(first, draft, data_dir=self.root, db_path=self.db)
        # Simulated controller/application reconstruction: use durable APIs, no session globals.
        self.assertEqual(conversation.classify_intent('Search approved memory for rejection').intent, 'memory_recall')
        before = self.db.read_bytes()
        found = memory.supervised_lessons('rejection silence', data_dir=self.root, db_path=self.db)
        self.assertEqual(self.db.read_bytes(), before)
        self.assertEqual(found[0]['lesson_id'], lesson_id)
        self.assertEqual(found[0]['source_type'], 'human_supervised')
        self.assertTrue(found[0]['relevance']['matched_terms'])
        self.assertEqual(conversation.load_lesson_state(first, data_dir=self.root, db_path=self.db), draft)
        self.assertIsNone(conversation.load_lesson_state(second, data_dir=self.root, db_path=self.db))
        self.assertEqual(len(lessons.list_lessons(data_dir=self.root, db_path=self.db)), 1)
        self.assertEqual(len(lessons.audit_events(lesson_id, data_dir=self.root, db_path=self.db)), 1)

    def test_complete_fields_are_recognized_even_without_training_lead_in(self):
        text = ('Scenario summary: Silence is ambiguous. Emotional context: fear and uncertainty. '
                'Observed facts: communication decreased. Assumptions or uncertainties: the cause is unknown. '
                'Corrective principle: distinguish facts from assumptions. '
                'Recommended response pattern: communicate calmly.')
        self.assertEqual(conversation.classify_intent(text).intent, 'training')
        proposal, fields = conversation.prepare_lesson(text)
        self.assertTrue(conversation.lesson_fields_complete(fields))
        self.assertEqual(proposal['observed_facts'], 'communication decreased.')

    def test_lesson_workflow_state_persists_per_conversation(self):
        first = conversation.create_session(data_dir=self.root, db_path=self.db)
        second = conversation.create_session(data_dir=self.root, db_path=self.db)
        state = {'conversation_id': first, 'status': 'incomplete', 'fields': {'scenario_summary': 'Only A'}}
        conversation.save_lesson_state(first, state, data_dir=self.root, db_path=self.db)
        self.assertEqual(conversation.load_lesson_state(first, data_dir=self.root, db_path=self.db), state)
        self.assertIsNone(conversation.load_lesson_state(second, data_dir=self.root, db_path=self.db))
        conversation.save_lesson_state(first, None, data_dir=self.root, db_path=self.db)
        self.assertIsNone(conversation.load_lesson_state(first, data_dir=self.root, db_path=self.db))

    def test_pending_preview_does_not_persist_until_explicit_approval_then_retrieves(self):
        proposal, _ = conversation.prepare_lesson('Scenario summary: fictional distance\nEmotional context: uncertainty\nObserved facts: silence\nAssumptions or uncertainties: reason unknown\nCorrective principle: silence is not necessarily rejection\nRecommended response pattern: ask respectfully')
        self.assertEqual(lessons.list_lessons(data_dir=self.root, db_path=self.db), [])
        with patch('brain_core.model_api.complete', side_effect=AssertionError('inference must not run')):
            lesson_id = lessons.approve(proposal, data_dir=self.root, db_path=self.db)
        found = lessons.retrieve('silence rejection', data_dir=self.root, db_path=self.db)
        self.assertEqual(found[0]['lesson_id'], lesson_id)
        self.assertTrue(found[0]['relevance']['matched_terms'])
        self.assertEqual([event['event_type'] for event in lessons.audit_events(lesson_id, data_dir=self.root, db_path=self.db)], ['approved'])

    def test_session_persistence_idempotency_switching_and_delete_isolated_from_lessons(self):
        session_a = conversation.create_session(data_dir=self.root, db_path=self.db)
        session_b = conversation.create_session('Second', data_dir=self.root, db_path=self.db)
        message_id = 'stable-message-id'
        conversation.save_message(session_a, 'user', 'hello', message_id=message_id, data_dir=self.root, db_path=self.db)
        conversation.save_message(session_a, 'user', 'hello', message_id=message_id, data_dir=self.root, db_path=self.db)
        conversation.save_message(session_b, 'assistant', 'separate', data_dir=self.root, db_path=self.db)
        self.assertEqual(len(conversation.load_messages(session_a, data_dir=self.root, db_path=self.db)), 1)
        self.assertEqual(conversation.load_messages(session_b, data_dir=self.root, db_path=self.db)[0]['content'], 'separate')
        selected = session_a
        selected = session_b
        self.assertEqual(conversation.load_messages(selected, data_dir=self.root, db_path=self.db)[0]['content'], 'separate')
        selected = session_a
        self.assertEqual(conversation.load_messages(selected, data_dir=self.root, db_path=self.db)[0]['content'], 'hello')
        proposal, _ = conversation.prepare_lesson('Scenario summary: retained\nEmotional context: calm\nObserved facts: none\nAssumptions or uncertainties: uncertain\nCorrective principle: retained lesson\nRecommended response pattern: ask')
        lesson_id = lessons.approve(proposal, data_dir=self.root, db_path=self.db)
        with self.assertRaises(ValueError):
            conversation.delete_session(session_a, data_dir=self.root, db_path=self.db)
        conversation.delete_session(session_a, confirmed=True, data_dir=self.root, db_path=self.db)
        self.assertEqual(len(lessons.list_lessons(data_dir=self.root, db_path=self.db)), 1)
        self.assertEqual(lessons.retrieve('retained', data_dir=self.root, db_path=self.db)[0]['lesson_id'], lesson_id)

    def test_general_acknowledgement_does_not_claim_feelings(self):
        answer = conversation.respond_general('Hello, how are you?', {'identity_name': 'Sovereign Brain'})
        self.assertIn('do not', answer)
        self.assertIn('feelings', answer)


if __name__ == '__main__':
    unittest.main()
