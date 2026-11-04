"""Focused decision contract regressions for small-model output."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core import decision, service, studio, trainer
from brain_core.model_api import ModelConfig, ModelOutputError
from quality_fixtures import output

SCENARIO = 'I made a mistake that caused my colleague to be blamed. I feel guilty and fear losing promotion.'

class DecisionQualityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = ModelConfig('http://127.0.0.1:12345/v1', 'controlled-test')
        self.paths()

    def good(self):
        data = output(SCENARIO)
        data['emotion'] = 'guilt and fear'
        data['decision']['conflicting_emotions'] = ['guilt', 'fear']
        data['decision']['evidence'] = 'I made a mistake and my colleague was blamed.'
        data['decision']['options'] = [
            'I will tell my supervisor about my mistake and correct the blame.',
            'I will check the records before discussing the mistake with my supervisor.']
        data['decision']['recommended_action'] = 'I will tell my supervisor about my mistake and correct the blame.'
        data['decision']['rationale'] = 'Guilt favors correcting the blame, while fear makes the reputational cost uncertain.'
        data['operational_rule']['recommended_action'] = 'I will correct the inaccurate blame with my supervisor.'
        return data

    def paths(self):
        return {'state_path': self.root / 'state.json', 'history_path': self.root / 'history.json',
                'db_path': self.root / 'brain.sqlite3', 'data_dir': self.root,
                'profile_path': self.root / 'personality.json'}

    def test_model_output_error_always_has_optional_diagnostic_id(self):
        self.assertIsNone(ModelOutputError('validation failed').diagnostic_id)
        self.assertEqual(ModelOutputError('validation failed', diagnostic_id='ref-123').diagnostic_id,
                         'ref-123')

    def test_diagnostic_logging_failure_keeps_error_safe_and_attribute_defined(self):
        invalid = self.good()
        invalid['decision']['options'] = ['I will tell my supervisor and correct the blame.',
                                          'I will tell the supervisor and fix the blame.']
        with patch.object(trainer, '_write_diagnostic', side_effect=OSError('diagnostic disk unavailable')), \
             patch('brain_core.reasoning_stages.complete', side_effect=[
                 (invalid, {'source': 'local_model'}), (invalid, {'source': 'local_model'})]):
            with self.assertRaises(ModelOutputError) as raised:
                service.analyze(SCENARIO, config=self.config, **self.paths())
        self.assertIsNone(raised.exception.diagnostic_id)
        self.assertNotIn('diagnostic disk', str(raised.exception))

    def test_bare_option_ids_are_rejected(self):
        for value in ('set_boundaries', 'seek_clarity', 'option 1', 'I will set_boundaries'):
            with self.subTest(value=value):
                data = self.good()
                data['decision']['recommended_action'] = value
                with self.assertRaisesRegex(ValueError, 'option ID'):
                    decision.validate_quality(data, SCENARIO)

    def test_valid_concrete_decision_is_accepted(self):
        decision.validate_quality(self.good(), SCENARIO)

    def test_meaningfully_distinct_action_alternatives_are_accepted(self):
        data = self.good()
        data['decision']['options'] = [
            'I will verify the incident records before speaking to the supervisor.',
            'I will promptly disclose my mistake and ask the supervisor to correct the blame.']
        decision.validate_quality(data, SCENARIO)

    def test_repeated_and_equivalent_alternatives_are_rejected(self):
        for options in (
                ['I will tell my supervisor and correct the blame.',
                 'I will tell the supervisor and fix the blame.'],
                ['I will promptly tell my supervisor about my error and correct the blame.',
                 'I will tell my supervisor promptly about the error and correct that blame.']):
            with self.subTest(options=options):
                data = self.good()
                data['decision']['options'] = options
                with self.assertRaisesRegex(ValueError, 'distinct concrete alternatives'):
                    decision.validate_quality(data, SCENARIO)

    def test_repair_validation_is_bounded_to_one_extra_request(self):
        invalid = self.good()
        invalid['decision']['options'] = [
            'I will tell my supervisor and correct the blame.',
            'I will tell the supervisor and fix the blame.']
        with patch('brain_core.reasoning_stages.complete', side_effect=[
                (copy.deepcopy(__import__('tests.test_reasoning_stages', fromlist=['UNDERSTANDING']).UNDERSTANDING), {}),
                (invalid, {}), (invalid, {})]) as complete:
            with self.assertRaises(ModelOutputError):
                service.analyze(SCENARIO, config=self.config, **self.paths())
        self.assertEqual(complete.call_count, 2)

    def test_one_bounded_repair_is_attempted_and_valid_response_remains_pending(self):
        invalid = {'alternatives': [{'action': 'I will tell my supervisor and correct the blame.', 'consequence': 'This may correct the blame.'}, {'action': 'I will tell the supervisor and fix the blame.', 'consequence': 'This may fix the blame.'}]}
        repaired = self.good()
        repaired['decision']['options'] = [
            'I will check the records before discussing the mistake with my supervisor.',
            'I will promptly disclose my error and ask my supervisor to correct the blame.']
        understanding = {'facts': ['I made a mistake that caused my colleague to be blamed.', 'I feel guilty and fear losing promotion.', 'They explicitly say I can correct the blame.'], 'emotions': [{'label': 'guilt', 'trigger': 'I made a mistake that caused my colleague to be blamed.'}, {'label': 'fear', 'trigger': 'I fear losing promotion.'}], 'assumptions': ['The promotion outcome is unknown.']}
        alternatives = {'alternatives': [{'action': 'I will tell my supervisor about my mistake and correct the blame.', 'consequence': 'Correcting the blame may reduce harm to my colleague.'}, {'action': 'I will check the report details with my supervisor before correcting the blame.', 'consequence': 'Checking details may help ensure an accurate correction.'}]}
        final = {'selected_action': alternatives['alternatives'][0]['action'], 'rationale': 'My mistake caused my colleague to be blamed, so I should correct the record.', 'emotional_tradeoff': 'Guilt supports repair while fear about promotion makes speaking up difficult.'}
        invalid_stage2 = {'alternatives': [{'action':'I will tell my supervisor and correct the blame.','consequence':'This may correct the blame.'},{'action':'I will tell the supervisor and fix the blame.','consequence':'This may fix the blame.'}]}
        with patch('brain_core.reasoning_stages.complete', side_effect=[
                (understanding, {'source': 'local_model', 'model': 'controlled-test'}),
                (invalid_stage2, {'source': 'local_model', 'model': 'controlled-test'}),
                (alternatives, {'source': 'local_model', 'model': 'controlled-test'}),
                (final, {'source': 'local_model', 'model': 'controlled-test'})]) as complete:
            turn_id, state, result, _ = service.analyze('I made a mistake that caused my colleague to be blamed. I feel guilty and fear losing promotion. They explicitly say I can correct the blame.', config=self.config, **self.paths())
        self.assertEqual(complete.call_count, 4)
        self.assertTrue(result['_trainer_pending'])
        self.assertTrue(result['_stage_repair_attempts']['alternatives'])
        self.assertFalse(result['_stage_repair_attempts']['understanding'])
        self.assertIsNone(turn_id)
        self.assertEqual(studio.inspect_turns(db_path=self.root / 'brain.sqlite3'), [])
        self.assertFalse((self.root / 'state.json').exists())
        self.assertFalse((self.root / 'history.json').exists())

    def test_unapproved_approved_training_proposal_does_not_persist(self):
        pending = self.good()
        pending['_provenance'] = {'source': 'approved_training', 'model': 'controlled-test'}
        pending['_trainer_approved'] = True
        pending['_trainer_pending'] = True
        before_state = (self.root / 'state.json').read_bytes() if (self.root / 'state.json').exists() else None
        before_history = (self.root / 'history.json').read_bytes() if (self.root / 'history.json').exists() else None
        with self.assertRaisesRegex(ValueError, 'Review and explicitly approve'):
            service.analyze(SCENARIO, config=self.config, approved_result=pending, **self.paths())
        self.assertEqual(studio.inspect_turns(db_path=self.root / 'brain.sqlite3'), [])
        self.assertEqual((self.root / 'state.json').read_bytes() if (self.root / 'state.json').exists() else None, before_state)
        self.assertEqual((self.root / 'history.json').read_bytes() if (self.root / 'history.json').exists() else None, before_history)

    @unittest.skip('Legacy-shaped output is covered by tests.test_diagnostics with field-level diagnostic assertions.')
    def test_failed_repair_has_separate_sanitized_diagnostic_and_no_memory_write(self):
        (self.root / 'state.json').write_text(json.dumps({'iterations': 0, 'emotions': {}}), encoding='utf-8')
        (self.root / 'history.json').write_text(json.dumps({'iterations': 0, 'rules': []}), encoding='utf-8')
        before_state = (self.root / 'state.json').read_bytes()
        before_history = (self.root / 'history.json').read_bytes()
        invalid = self.good()
        invalid['decision']['recommended_action'] = 'seek_clarity'
        diagnostic_dir = self.root / 'diagnostics'
        with patch.dict(os.environ, {'BRAIN_DIAGNOSTIC_DIR': str(diagnostic_dir)}), \
             patch('brain_core.reasoning_stages.complete', side_effect=[
                 (invalid, {'source': 'local_model', 'model': 'controlled-test'}),
                 (invalid, {'source': 'local_model', 'model': 'controlled-test'})]):
            with self.assertRaises(ModelOutputError) as raised:
                service.analyze(SCENARIO, config=self.config, **self.paths())
        self.assertTrue(raised.exception.diagnostic_id)
        self.assertEqual((self.root / 'state.json').read_bytes(), before_state)
        self.assertEqual((self.root / 'history.json').read_bytes(), before_history)
        record_path, = diagnostic_dir.glob('*.json')
        record = json.loads(record_path.read_text(encoding='utf-8'))
        self.assertIn('validation_error', record)
        self.assertIn('failed_criterion', record)
        self.assertIn('repair_error', record)
        self.assertNotIn('scenario', record)
        self.assertEqual(record['failed_criterion'], record['validation_error'])
        self.assertNotIn(SCENARIO, record_path.read_text(encoding='utf-8'))
        self.assertEqual(studio.inspect_turns(db_path=self.root / 'brain.sqlite3'), [])

    def test_explicit_approval_workflow_is_preserved(self):
        self.paths()
        pending = self.good()
        pending['_provenance'] = {'source': 'local_model', 'model': 'controlled-test'}
        pending['_trainer_pending'] = True
        with self.assertRaisesRegex(ValueError, 'Explicit trainer approval'):
            service.analyze(SCENARIO, config=self.config, approved_result=pending, **self.paths())
        approved = copy.deepcopy(pending)
        approved.pop('_trainer_pending')
        approved['_trainer_approved'] = True
        approved['_provenance']['source'] = 'approved_training'
        with patch.object(trainer, 'STATE_PATH', self.root / 'state.json'), \
             patch.object(trainer, 'HISTORY_PATH', self.root / 'history.json'):
            _, state, result = trainer.train(SCENARIO, config=self.config,
                                              proposed_result=approved, feedback='Approved after review.',
                                              **self.paths())
            service.analyze(SCENARIO, config=self.config, approved_result=approved, **self.paths())
        self.assertTrue(result['_trainer_approved'])
        self.assertFalse(result.get('_trainer_pending', False))
        self.assertEqual(state['iterations'], 1)
        self.assertEqual(len(studio.inspect_turns(db_path=self.root / 'brain.sqlite3')), 1)

if __name__ == '__main__':
    unittest.main()
