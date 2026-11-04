"""Contract-driven conversational response checks across all synthetic scenarios."""
import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.test_emotional_benchmark import SCENARIOS
from brain_core.reasoning_stages import conversational_response
from brain_core.model_api import ModelOutputError


def validated_for(key, scenario):
    emotions = {'jealousy_without_evidence': ('jealousy', 'I feel jealous'),
                'apology_accountability': ('guilt', 'I made a mistake'),
                'shame_guilt': ('guilt', 'I feel guilty'),
                'anger_regulation': ('anger', 'I am angry'),
                'boundaries': ('caution', 'I want to respect that boundary'),
                'workplace_conflict': ('frustration', 'I feel frustrated'),
                'fear_rejection': ('fear', 'I fear rejection'),
                'silence_uncertainty': ('caution', 'I do not know why'),
                'unknown_motives': ('caution', 'I do not want to guess')}
    label, trigger = emotions.get(key, ('fear', scenario.split('.')[0]))
    fact = scenario.split('.')[0]
    assumptions = ['The other person’s reason or motive is unknown.']
    if key == 'workplace_conflict':
        assumptions = ['The coworker’s reason for disagreeing is unclear.']
    if key == 'silence_uncertainty':
        assumptions = ['The reason for the silence is unknown.', 'Silence alone does not establish rejection.']
    action = ('I will acknowledge my part and apologize for the impact.' if key == 'apology_accountability' else
              'I will respect their stated boundary and not pressure them.' if key == 'boundaries' else
              'I will ask a calm, specific question before deciding what happened.')
    consequence = ('This gives them room to clarify without assuming a motive.' if key != 'apology_accountability'
                   else 'Taking responsibility can acknowledge the impact while allowing them to respond.')
    return {'decision': {'recommended_action': action},
            '_stage_outputs': {'understanding': {'facts': [fact], 'emotions': [{'label': label, 'trigger': trigger}],
                                'assumptions': assumptions},
                              'alternatives': {'alternatives': [{'action': action, 'consequence': consequence}]},
                              'final_decision': {'selected_action': action, 'rationale': consequence}},
            '_provenance': {'approved_lessons': []}, '_validation': {'schema_passed': True}}


class ResponseGeneration8L5Tests(unittest.TestCase):
    def test_every_synthetic_category_renders_with_validated_fields(self):
        self.assertEqual(len(SCENARIOS), 15)
        for key, scenario in SCENARIOS:
            with self.subTest(category=key):
                response = conversational_response(validated_for(key, scenario))
                self.assertTrue(response)
                self.assertIn('One proportionate next step', response)

    def test_jealousy_and_workplace_do_not_get_relationship_specific_boilerplate(self):
        scenarios = dict(SCENARIOS)
        jealousy = conversational_response(validated_for('jealousy_without_evidence', scenarios['jealousy_without_evidence']))
        work = conversational_response(validated_for('workplace_conflict', scenarios['workplace_conflict']))
        for response in (jealousy, work):
            self.assertNotIn('no longer values', response.casefold())
            self.assertNotIn('your friend', response.casefold())
        self.assertIn('coworker', work.casefold())
        self.assertIn('meeting', work.casefold())

    def test_apology_uses_accountability_and_boundaries_preserve_autonomy(self):
        scenarios = dict(SCENARIOS)
        apology = conversational_response(validated_for('apology_accountability', scenarios['apology_accountability']))
        boundary = conversational_response(validated_for('boundaries', scenarios['boundaries']))
        self.assertIn('apologize', apology.casefold())
        self.assertIn('respect', boundary.casefold())
        self.assertIn('respect their stated boundary', boundary.casefold())
        self.assertNotIn('insist', boundary.casefold())

    def test_silence_and_unknown_motives_keep_uncertainty_explicit(self):
        scenarios = dict(SCENARIOS)
        silence = conversational_response(validated_for('silence_uncertainty', scenarios['silence_uncertainty']))
        motive = conversational_response(validated_for('unknown_motives', scenarios['unknown_motives']))
        self.assertIn('unknown', silence.casefold())
        self.assertIn('unknown', motive.casefold())
        self.assertNotIn('they intended', motive.casefold())

    def test_lesson_provenance_is_guidance_not_evidence(self):
        scenario = dict(SCENARIOS)['past_emotional_memory']
        result = validated_for('past_emotional_memory', scenario)
        result['_provenance']['approved_lessons'] = [{'lesson_id': 'L5', 'source_type': 'human_supervised',
            'corrective_principle': 'Past emotional memories are not proof of another person’s intentions.'}]
        response = conversational_response(result)
        self.assertIn('L5', response)
        self.assertIn('human_supervised', response)
        self.assertIn('guidance, not evidence', response)

    def test_missing_fields_fail_closed(self):
        with self.assertRaises(ValueError):
            conversational_response({'_stage_outputs': {'understanding': {'facts': [], 'emotions': [], 'assumptions': []}}})

    def test_emotion_and_fact_are_rendered_only_from_contract(self):
        scenario = dict(SCENARIOS)['jealousy_without_evidence']
        result = validated_for('jealousy_without_evidence', scenario)
        result['_stage_outputs']['understanding']['emotions'] = [{'label': 'jealousy', 'trigger': 'I feel jealous'}]
        response = conversational_response(result)
        self.assertIn('jealousy', response.casefold())
        self.assertNotIn('cheating', response.casefold())
        self.assertNotIn('trust', response.casefold())

if __name__ == '__main__':
    unittest.main()
