"""Offline regressions for the three-stage reasoning pipeline."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core import decision, personality, trainer, studio
from brain_core.model_api import ModelConfig, ModelOutputError
from brain_core.reasoning_stages import (
    assemble_result, progressive_reasoning, run_stage,
)

SCENARIO = ("Someone you love asks for a day alone after a stressful experience. "
            "A past relationship ended after a similar request, so you fear this person may leave too. "
            "They explicitly say they still care about you. Decide how to respond without assuming "
            "that your past experience predicts their intentions.")

UNDERSTANDING = {
    'facts': [
        'The person asks for a day alone after a stressful experience.',
        'A past relationship ended after a similar request.',
        'They explicitly say they still care about you.'
    ],
    'emotions': [
        {'label': 'fear', 'trigger': 'The similar request recalls a past relationship ending.'},
        {'label': 'trust', 'trigger': 'The person explicitly says they still care about you.'}
    ],
    'assumptions': [
        'It is unknown whether this request predicts what will happen to the current relationship.'
    ]
}
ALTERNATIVES = {'alternatives': [
    {'action': 'I will acknowledge the request and give them the day alone they asked for.',
     'consequence': 'Respecting the request for a day alone gives them space after the stressful experience.'},
    {'action': 'I will ask when they would feel comfortable reconnecting after their day alone.',
     'consequence': 'Agreeing on when to reconnect creates a check-in while respecting their request for space.'}
]}
FINAL = {
    'selected_action': ALTERNATIVES['alternatives'][0]['action'],
    'rationale': 'They asked for a day alone after a stressful experience, so I can respect that stated need.',
    'emotional_tradeoff': 'Giving space may ease pressure, while fear from my past relationship makes waiting difficult.'
}

class ReasoningStageTests(unittest.TestCase):
    def setUp(self):
        self.config = ModelConfig('http://127.0.0.1:12345/v1', 'controlled-test')
        self.profile = copy.deepcopy(personality.DEFAULT)
        self.context = {'appraised_emotions_before_decision': dict(__import__(
            'brain_core.appraisal', fromlist=['NEUTRAL']).NEUTRAL)}

    def test_stage_one_accepts_grounded_facts_and_paraphrased_triggers(self):
        value = copy.deepcopy(UNDERSTANDING)
        value['facts'][0] = 'After a difficult experience, they request some quiet time by themselves.'
        value['emotions'][0]['trigger'] = 'The request for solitude echoes an earlier relationship ending.'
        decision.validate_emotional_understanding(value, SCENARIO)

    def test_emotion_synonyms_normalize_only_with_scenario_support(self):
        for label, canonical, scenario in (
                ('Worried!', 'fear', 'They worry about whether the project will succeed.'),
                ('disappointed', 'sadness', 'The colleague is disappointed about the project news.'),
                ('irritated', 'anger', 'The colleague is irritated by an unfair decision.'),
                ('calm', 'emotional_regulation', 'They pause to stay calm before replying.'),
                ('love', 'attachment', 'They feel love for their partner.'),
                ('concern', 'empathy', 'The colleague needs help with the difficult news.')):
            self.assertEqual(decision._normalize_emotion_label(label)[0], canonical)
            self.assertTrue(decision._emotion_grounding_support(canonical, scenario))
        value = copy.deepcopy(UNDERSTANDING)
        value['emotions'][0]['label'] = 'Worried!'
        personality_before = copy.deepcopy(personality.inspect() or personality.DEFAULT)
        decision.validate_emotional_understanding(value, SCENARIO)
        self.assertEqual(value['emotions'][0]['label'], 'fear')
        self.assertEqual(value['emotions'][1]['label'], 'trust')
        self.assertEqual(personality.inspect() or personality.DEFAULT, personality_before)

    def test_negated_labels_and_substring_only_grounding_are_rejected(self):
        self.assertEqual(decision._normalize_emotion_label('not worried'), (None, 'negated'))
        self.assertEqual(decision._normalize_emotion_label('guilt and fear'), (None, 'ambiguous'))
        self.assertEqual(decision._normalize_emotion_label('affection and jealousy'), (None, 'ambiguous'))
        self.assertFalse(decision._emotion_grounding_support('empathy', 'The careless stranger arrived.'))
        self.assertFalse(decision._emotion_grounding_support('trust', 'They do not trust anyone.'))

    def test_compound_emotion_labels_are_rejected_even_during_assembly(self):
        value = copy.deepcopy(UNDERSTANDING)
        value['emotions'][0]['label'] = 'guilt and fear'
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            decision.validate_emotional_understanding(value, SCENARIO)
        with self.assertRaisesRegex(ValueError, 'unrecognized emotional appraisal'):
            assemble_result(value, copy.deepcopy(ALTERNATIVES), copy.deepcopy(FINAL), SCENARIO,
                            self.profile, self.context, {}, {})

    def test_unsupported_known_emotion_is_rejected(self):
        value = copy.deepcopy(UNDERSTANDING)
        value['emotions'][0]['label'] = 'jealousy'
        with self.assertRaisesRegex(ValueError, 'jealousy appraisal is unsupported'):
            decision.validate_emotional_understanding(value, SCENARIO)

    def test_unknown_ambiguous_and_negated_emotions_are_rejected(self):
        for label, reason in (('bad vibes', 'ambiguous'), ('ecstatic', 'unknown'),
                              ('not worried', 'negated')):
            value = copy.deepcopy(UNDERSTANDING)
            value['emotions'][0]['label'] = label
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, reason):
                decision.validate_emotional_understanding(value, SCENARIO)

    def test_emotion_synonym_mapping_is_deterministic_and_existing_state_only(self):
        self.assertEqual(set(decision.EMOTION_SYNONYMS), set(__import__(
            'brain_core.appraisal', fromlist=['EMOTIONS']).EMOTIONS))
        for synonym, canonical in (('worried', 'fear'), ('concern', 'empathy'),
                                   ('disappointed', 'sadness'), ('irritated', 'anger'),
                                   ('care', 'unknown')):
            actual = decision._normalize_emotion_label(synonym)[0]
            self.assertEqual(actual, None if canonical == 'unknown' else canonical)
        self.assertIsNone(decision._normalize_emotion_label('bad vibes')[0])

    def test_stage_one_rejects_unrelated_facts_and_contradictory_triggers(self):
        value = copy.deepcopy(UNDERSTANDING)
        value['facts'][0] = 'A sports team celebrated its championship victory.'
        with self.assertRaisesRegex(ValueError, 'not sufficiently grounded'):
            decision.validate_emotional_understanding(value, SCENARIO)
        value = copy.deepcopy(UNDERSTANDING)
        value['emotions'][1]['trigger'] = 'The person says they no longer care about you.'
        with self.assertRaisesRegex(ValueError, 'contradicts'):
            decision.validate_emotional_understanding(value, SCENARIO)

    def test_stage_one_accepts_uncertainty_paraphrases_about_scenario_details(self):
        for assumption in (
                'It is unclear whether they want to reconnect after the day alone.',
                'I do not know if the request for solitude predicts the future of the current relationship.'):
            value = copy.deepcopy(UNDERSTANDING)
            value['assumptions'] = [assumption]
            decision.validate_emotional_understanding(value, SCENARIO)

    def test_stage_one_rejects_unsupported_assumptions(self):
        value = copy.deepcopy(UNDERSTANDING)
        value['assumptions'] = ['The colleague plans to resign next month.']
        with self.assertRaisesRegex(ValueError, 'assumption is disconnected'):
            decision.validate_emotional_understanding(value, SCENARIO)

    def test_stage_one_contract_bounds_output_size(self):
        schema = decision.EMOTION_UNDERSTANDING_SCHEMA
        self.assertEqual(schema['properties']['assumptions']['maxItems'], 2)
        self.assertEqual(schema['properties']['facts']['items']['maxLength'], 240)
        self.assertEqual(schema['properties']['emotions']['items']['properties']['trigger']['maxLength'], 240)

    def test_stage_three_reasonable_rationale_paraphrase_is_accepted(self):
        paraphrase = copy.deepcopy(FINAL)
        paraphrase['rationale'] = 'After a difficult event they want quiet time, so honoring the request respects their need.'
        decision.validate_final_decision(paraphrase, ALTERNATIVES, SCENARIO, UNDERSTANDING['facts'])

    def test_stage_two_accepts_distinct_actions_and_rejects_equivalent_or_ungrounded(self):
        decision.validate_alternatives(copy.deepcopy(ALTERNATIVES), UNDERSTANDING['facts'], SCENARIO)
        duplicate = copy.deepcopy(ALTERNATIVES)
        duplicate['alternatives'][1]['action'] = 'I will acknowledge their request and give them the day alone they asked for.'
        with self.assertRaisesRegex(ValueError, 'meaningfully distinct'):
            decision.validate_alternatives(duplicate, UNDERSTANDING['facts'], SCENARIO)
        unrelated = copy.deepcopy(ALTERNATIVES)
        unrelated['alternatives'][1]['action'] = 'I will organize the quarterly sales report for the director.'
        unrelated['alternatives'][1]['consequence'] = 'This may increase the quarterly sales results.'
        with self.assertRaisesRegex(ValueError, 'not grounded'):
            decision.validate_alternatives(unrelated, UNDERSTANDING['facts'], SCENARIO)

    def test_stage_three_accepts_selected_action_and_rejects_contradiction(self):
        decision.validate_final_decision(copy.deepcopy(FINAL), ALTERNATIVES, SCENARIO, UNDERSTANDING['facts'])
        contradictory = copy.deepcopy(FINAL)
        contradictory['rationale'] = 'They did not ask for space and they no longer care about me.'
        with self.assertRaisesRegex(ValueError, 'contradicts'):
            decision.validate_final_decision(contradictory, ALTERNATIVES, SCENARIO, UNDERSTANDING['facts'])
        invalid = copy.deepcopy(FINAL)
        invalid['selected_action'] = 'I will call repeatedly until they answer.'
        with self.assertRaisesRegex(ValueError, 'must select'):
            decision.validate_final_decision(invalid, ALTERNATIVES, SCENARIO, UNDERSTANDING['facts'])

    def test_deterministic_assembly_uses_stage_outputs_without_inventing_decision(self):
        result = assemble_result(copy.deepcopy(UNDERSTANDING), copy.deepcopy(ALTERNATIVES),
                                 copy.deepcopy(FINAL), SCENARIO, self.profile, self.context,
                                 {'source': 'unit_test_mock', 'model': 'controlled-test', 'seconds': 1.0},
                                 {'understanding': False, 'alternatives': False, 'final_decision': False})
        self.assertEqual(result['decision']['recommended_action'], FINAL['selected_action'])
        self.assertEqual(result['decision']['options'], [item['action'] for item in ALTERNATIVES['alternatives']])
        expected_understanding = copy.deepcopy(UNDERSTANDING)
        expected_understanding['emotions'][1]['label'] = 'trust'
        self.assertEqual(result['_stage_outputs']['understanding'], expected_understanding)
        self.assertTrue(result['_trainer_pending'])
        self.assertEqual(result['narrative'], f"I would choose {FINAL['selected_action'].rstrip('.')} because {FINAL['rationale'].rstrip('.')}.")
        self.assertEqual(result['emotion'], 'fear and trust')
        self.assertEqual(result['decision']['conflicting_emotions'], ['fear', 'trust'])

    def test_assembled_conflicting_emotions_are_distinct_and_expanded(self):
        understanding = copy.deepcopy(UNDERSTANDING)
        understanding['emotions'][0]['label'] = 'guilt'
        result = assemble_result(understanding, copy.deepcopy(ALTERNATIVES), copy.deepcopy(FINAL),
                                 SCENARIO, self.profile, self.context,
                                 {'source': 'unit_test_mock', 'model': 'controlled-test', 'seconds': 0}, {})
        self.assertEqual(result['decision']['conflicting_emotions'], ['guilt', 'trust'])

    def test_successful_pipeline_calls_and_validates_all_three_stages(self):
        responses = [copy.deepcopy(UNDERSTANDING), copy.deepcopy(ALTERNATIVES), copy.deepcopy(FINAL)]
        with patch('brain_core.reasoning_stages.complete', side_effect=[
                (responses[0], {'source': 'unit_test_mock', 'seconds': .1}),
                (responses[1], {'source': 'unit_test_mock', 'seconds': .2}),
                (responses[2], {'source': 'unit_test_mock', 'seconds': .3})]) as complete:
            result = progressive_reasoning(SCENARIO, config=self.config,
                cognitive_context=self.context, persistent_profile=self.profile)
        self.assertEqual(complete.call_count, 3)
        self.assertTrue(result['_trainer_pending'])
        self.assertEqual(result['_stage_repair_attempts'], {
            'understanding': False, 'alternatives': False, 'final_decision': False})
        self.assertEqual(result['_provenance']['seconds'], .6)

    def test_assembled_conflicting_emotions_are_distinct_and_expanded(self):
        understanding = copy.deepcopy(UNDERSTANDING)
        understanding['emotions'] = [
            {'label': 'guilt', 'trigger': 'I made a mistake and fear the effect.'},
            {'label': 'trust', 'trigger': 'They explicitly say they still care.'}]
        result = assemble_result(understanding, copy.deepcopy(ALTERNATIVES), copy.deepcopy(FINAL),
                                 SCENARIO, self.profile, self.context,
                                 {'source': 'unit_test_mock', 'model': 'controlled-test', 'seconds': 0}, {})
        self.assertEqual(result['decision']['conflicting_emotions'], ['guilt', 'trust'])

    def test_stage_repair_is_limited_to_one_attempt(self):
        invalid = copy.deepcopy(UNDERSTANDING)
        invalid['facts'][0] = 'A sports team won a trophy.'
        with patch('brain_core.reasoning_stages.complete', side_effect=[
                (invalid, {}), (invalid, {})]) as complete:
            with self.assertRaises(ModelOutputError):
                run_stage('emotional understanding', [], decision.EMOTION_UNDERSTANDING_SCHEMA,
                          lambda value: decision.validate_emotional_understanding(value, SCENARIO),
                          self.config, SCENARIO)
        self.assertEqual(complete.call_count, 2)

    def test_stage_one_prompt_is_compact_and_does_not_duplicate_context(self):
        with patch('brain_core.reasoning_stages.run_stage', side_effect=[
                (copy.deepcopy(UNDERSTANDING), {}, False),
                (copy.deepcopy(ALTERNATIVES), {}, False),
                (copy.deepcopy(FINAL), {}, False)]) as stage:
            progressive_reasoning(SCENARIO, config=self.config,
                                  cognitive_context=self.context, persistent_profile=self.profile)
        messages = stage.call_args_list[0].args[1]
        system, user = messages[0]['content'], json.loads(messages[1]['content'])
        self.assertLess(len(system) + len(messages[1]['content']), 1700)
        self.assertEqual(user['scenario'], SCENARIO)
        self.assertEqual(set(user), {'scenario', 'output_budget_hint'})

    def test_stage_one_repair_prompt_is_bounded_and_targets_failed_field(self):
        invalid = copy.deepcopy(UNDERSTANDING)
        invalid['assumptions'] = ['A distant unrelated sporting event determines their plans.']
        with patch('brain_core.reasoning_stages.complete', side_effect=[
                (invalid, {}), (copy.deepcopy(UNDERSTANDING), {})]) as complete:
            _, _, repaired = run_stage('emotional understanding', [], decision.EMOTION_UNDERSTANDING_SCHEMA,
                                       lambda value: decision.validate_emotional_understanding(value, SCENARIO),
                                       self.config, SCENARIO)
        self.assertTrue(repaired)
        repair_messages = complete.call_args_list[1].args[0]
        repair_text = ' '.join(item['content'] for item in repair_messages)
        self.assertLess(len(repair_text), 1600)
        self.assertIn('failed_field', repair_text)
        self.assertIn('assumptions', repair_text)
        self.assertNotIn('original_stage_output', repair_text)

    def test_failed_stage_diagnostic_records_bounded_emotion_evidence_and_repair(self):
        with tempfile.TemporaryDirectory() as temp:
            invalid = copy.deepcopy(UNDERSTANDING)
            invalid['emotions'][0]['label'] = 'Omar confidential project'
            with patch.dict(os.environ, {'BRAIN_DIAGNOSTIC_DIR': temp,
                                         'BRAIN_DIAGNOSTIC_VERBOSITY': 'local_debug'}), \
                 patch('brain_core.reasoning_stages.complete', side_effect=[(invalid, {}), (invalid, {})]):
                with self.assertRaises(ModelOutputError):
                    run_stage('emotional understanding', [], decision.EMOTION_UNDERSTANDING_SCHEMA,
                              lambda value: decision.validate_emotional_understanding(value, SCENARIO),
                              self.config, SCENARIO)
            record = json.loads(next(Path(temp).glob('*.json')).read_text(encoding='utf-8'))
            self.assertEqual(record['failed_field'], 'emotions')
            self.assertTrue(record['repair_attempted'])
            self.assertFalse(record['repair_succeeded'])
            self.assertEqual(record['emotion_labels'][0]['label'], '[unrecognized]')
            self.assertEqual(record['emotion_labels'][0]['classification'], 'ambiguous')
            self.assertNotIn('Omar', json.dumps(record))
            self.assertNotIn('confidential project', json.dumps(record))

    def test_failed_stage_does_not_modify_persistent_memory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            profile_path = root / 'personality.json'
            state_path = root / 'state.json'
            history_path = root / 'history.json'
            profile_path.write_text(json.dumps(self.profile), encoding='utf-8')
            state_path.write_text(json.dumps({'iterations': 0, 'emotion': 'neutral', 'metrics': dict(trainer.BASE), 'emotions': dict(__import__('brain_core.appraisal', fromlist=['NEUTRAL']).NEUTRAL)}), encoding='utf-8')
            history_path.write_text(json.dumps({'iterations': 0, 'rules': [], 'history': []}), encoding='utf-8')
            paths = (profile_path, state_path, history_path)
            db_path = root / 'studio.sqlite3'
            db_path.write_bytes(b'unchanged test database sentinel')
            paths = (*paths, db_path)
            before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
            invalid = copy.deepcopy(UNDERSTANDING)
            invalid['facts'][0] = 'An unrelated event occurred at work.'
            with patch.dict(os.environ, {'BRAIN_DIAGNOSTIC_DIR': str(root / 'diagnostics')}), \
                 patch('brain_core.reasoning_stages.complete', side_effect=[(invalid, {}), (invalid, {})]):
                with self.assertRaises(ModelOutputError):
                    trainer.infer(SCENARIO, '', {'emotions': {}}, {}, config=self.config,
                                  profile_path=profile_path, state_path=state_path,
                                  history_path=history_path, db_path=db_path, data_dir=root)
            after = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
            self.assertEqual(before, after)
            self.assertEqual(len(list((root / 'diagnostics').glob('*.json'))), 1)

if __name__ == '__main__':
    unittest.main()
