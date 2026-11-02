"""Privacy-safe failure diagnostics; uses mocked model replies only."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core import trainer, decision
from brain_core.model_api import ModelConfig, ModelOutputError
from brain_core.reasoning_stages import run_stage


class DiagnosticTests(unittest.TestCase):
    def test_invalid_verbosity_falls_back_to_minimal(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {
                'BRAIN_DIAGNOSTIC_DIR': folder, 'BRAIN_DIAGNOSTIC_VERBOSITY': 'unexpected'}):
            trainer._write_diagnostic('invalid-level', 'scenario', {}, 'failed')
            record = json.loads((Path(folder) / 'invalid-level.json').read_text(encoding='utf-8'))
            self.assertEqual(record['verbosity'], 'minimal')

    def test_minimal_diagnostic_has_allowlisted_grounding_summary_and_no_text(self):
        with tempfile.TemporaryDirectory() as folder:
            response = {'alternatives': [
                {'action': 'Ask [PERSON] at [EMAIL] using token=[AUTH_SECRET]',
                 'consequence': 'Meet at [STREET_ADDRESS].'},
                {'action': 'Give her space today.', 'consequence': 'Support remains available.'},
            ], 'private_prompt': 'do not persist'}
            details = {
                'stage_duration_seconds': 1.25, 'repair_duration_seconds': 0.4,
                'validation_passed': False, 'original_validation': 'Stage 2 action is not grounded.',
                'repair_attempted': True, 'repair_validation': 'Still not grounded.',
                'repair_succeeded': False, 'failed_field': 'alternatives[1]',
                'validator_details': {'alternative_grounding': [
                    {'scenario_relevance_score': 0, 'scenario_overlap_passed': False,
                     'scenario_threshold': 1, 'validated_fact_scores': [0],
                     'validated_fact_overlap_passed': False, 'validated_fact_threshold': 1,
                     'passed': False, 'private': 'do not store'}]},
            }
            with patch.dict(os.environ, {'BRAIN_DIAGNOSTIC_DIR': folder,
                                         'BRAIN_DIAGNOSTIC_VERBOSITY': 'minimal'}):
                ref = trainer._write_diagnostic('fixture-id', 'A colleague is quiet.', response,
                                                'Stage 2 action is not grounded.', 'repair failed',
                                                stage='decision alternatives', details=details)
            self.assertEqual(ref, 'fixture-id')
            record = json.loads((Path(folder) / 'fixture-id.json').read_text(encoding='utf-8'))
            self.assertEqual(record['stage'], 'decision alternatives')
            self.assertEqual(record['stage_duration_seconds'], 1.25)
            self.assertEqual(record['repair_duration_seconds'], 0.4)
            self.assertFalse(record['validation_passed'])
            self.assertTrue(record['repair_attempted'])
            self.assertFalse(record['repair_succeeded'])
            self.assertEqual(record['failed_field'], 'alternatives[1]')
            self.assertEqual(record['failed_alternative_index'], 1)
            self.assertFalse(record['validator_details']['alternative_grounding'][0]['passed'])
            self.assertEqual(record['alternatives'], [])
            content = (Path(folder) / 'fixture-id.json').read_text(encoding='utf-8')
            self.assertNotIn('private_prompt', content)
            for marker in ('[PERSON]', '[EMAIL]', '[AUTH_SECRET]', '[STREET_ADDRESS]'):
                self.assertNotIn(marker, content)

    def test_local_debug_preserves_only_redacted_stage_two_alternatives(self):
        with tempfile.TemporaryDirectory() as folder:
            response = {'alternatives': [
                {'action': 'Ask Alice whether she wants to talk.', 'consequence': 'She can decline.'},
                {'action': 'Give Alice space today.', 'consequence': 'She can reach out later.'}],
                'raw_prompt': 'private prompt'}
            with patch.dict(os.environ, {'BRAIN_DIAGNOSTIC_DIR': folder,
                                         'BRAIN_DIAGNOSTIC_VERBOSITY': 'local_debug'}):
                trainer._write_diagnostic('debug-id', 'colleague is quiet', response,
                                          'criterion', stage='decision alternatives', details={})
            content = (Path(folder) / 'debug-id.json').read_text(encoding='utf-8')
            record = json.loads(content)
            self.assertEqual(len(record['alternatives']), 2)
            self.assertNotIn('Alice', content)
            self.assertNotIn('raw_prompt', content)

    def test_single_person_names_are_redacted_in_debug_text(self):
        self.assertNotIn('Alice', trainer._sanitize_diagnostic_text('Ask Alice to join.'))

    def test_off_verbosity_does_not_write(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {
                'BRAIN_DIAGNOSTIC_DIR': folder, 'BRAIN_DIAGNOSTIC_VERBOSITY': 'off'}):
            self.assertIsNone(trainer._write_diagnostic('off-id', 'scenario', {}, 'failed'))
            self.assertEqual(list(Path(folder).glob('*.json')), [])

    def test_missing_stage_two_fields_are_reported_without_crashing(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {
                'BRAIN_DIAGNOSTIC_DIR': folder, 'BRAIN_DIAGNOSTIC_VERBOSITY': 'local_debug'}):
            trainer._write_diagnostic('missing-id', 'scenario', {'alternatives': [None]},
                                      'missing field', stage='decision alternatives', details={})
            record = json.loads((Path(folder) / 'missing-id.json').read_text(encoding='utf-8'))
            self.assertEqual(record['alternatives'], [{'action': '[missing]', 'consequence': '[missing]'}])
            self.assertEqual(record['repair_alternatives'], [])

    def test_successful_repair_records_validation_outcome(self):
        with tempfile.TemporaryDirectory() as folder:
            invalid = {'alternatives': [
                {'action': 'Pursue an unrelated hobby after work.', 'consequence': 'This is relaxing.'},
                {'action': 'Buy a new bicycle today.', 'consequence': 'This is enjoyable.'}]}
            valid = {'alternatives': [
                {'action': 'I will privately check on my colleague.', 'consequence': 'They can choose to talk.'},
                {'action': 'I will give my colleague space today.', 'consequence': 'They can approach me later.'}]}
            facts = ['A colleague has been quiet after disappointing project news.']
            scenario = 'A colleague has been quiet after disappointing project news.'
            with patch.dict(os.environ, {'BRAIN_DIAGNOSTIC_DIR': folder,
                                         'BRAIN_DIAGNOSTIC_VERBOSITY': 'local_debug'}), \
                 patch('brain_core.reasoning_stages.complete', side_effect=[(invalid, {}), (valid, {})]):
                result, _, repaired = run_stage('decision alternatives', [], decision.ALTERNATIVES_SCHEMA,
                    lambda value: decision.validate_alternatives(value, facts, scenario),
                    ModelConfig(), scenario, facts=facts)
            self.assertTrue(repaired)
            self.assertEqual(result, valid)
            self.assertEqual(list(Path(folder).glob('*.json')), [])

    def test_run_stage_failed_repair_records_both_outcomes_and_alternatives(self):
        with tempfile.TemporaryDirectory() as folder:
            bad = {'alternatives': [
                {'action': 'Pursue an unrelated hobby after work.', 'consequence': 'This is relaxing.'},
                {'action': 'Buy a new bicycle today.', 'consequence': 'This is enjoyable.'}]}
            config = ModelConfig()
            facts = ['A colleague has been quiet after disappointing project news.']
            with patch.dict(os.environ, {'BRAIN_DIAGNOSTIC_DIR': folder,
                                         'BRAIN_DIAGNOSTIC_VERBOSITY': 'local_debug'}), \
                 patch('brain_core.reasoning_stages.complete', side_effect=[(bad, {}), (bad, {})]):
                with self.assertRaises(ModelOutputError):
                    run_stage('decision alternatives', [], decision.ALTERNATIVES_SCHEMA,
                              lambda value: decision.validate_alternatives(value, facts,
                                  'A colleague has been quiet after disappointing project news.'),
                              config, 'A colleague has been quiet after disappointing project news.', facts=facts)
            record_path, = Path(folder).glob('*.json')
            record = json.loads(record_path.read_text(encoding='utf-8'))
            self.assertEqual(record['original_validation'], 'Stage 2 action is not grounded in the scenario.')
            self.assertEqual(record['repair_validation'], 'Stage 2 action is not grounded in the scenario.')
            self.assertEqual(record['failed_field'], 'alternatives[1]')
            self.assertEqual(record['failed_alternative_index'], 1)
            self.assertEqual(record['repair_failed_field'], 'alternatives[1]')
            self.assertEqual(record['repair_failed_alternative_index'], 1)
            self.assertEqual(record['validation_error'], record['failed_criterion'])
            self.assertEqual(record['repair_error'], record['repair_validation'])
            self.assertTrue(record['repair_attempted'])
            self.assertFalse(record['repair_succeeded'])
            self.assertEqual(len(record['alternatives']), 2)
            self.assertEqual(len(record['repair_alternatives']), 2)
            self.assertEqual(len(record['validator_details']['original']['alternative_grounding']), 2)
            self.assertEqual(len(record['validator_details']['repair']['alternative_grounding']), 2)
            self.assertIsNotNone(record['repair_duration_seconds'])


if __name__ == '__main__':
    unittest.main()
