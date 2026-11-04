"""Synthetic offline emotional reasoning benchmark; subjective dimensions are heuristic."""
import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core import decision, personality
from brain_core.appraisal import NEUTRAL
from brain_core.model_api import ModelConfig
from brain_core.reasoning_stages import progressive_reasoning
UNDER = {'facts': ['A close friend is less communicative after stress.', 'I feel anxious about the friendship.'],
         'emotions': [{'label': 'fear', 'trigger': 'I feel anxious.'},
                      {'label': 'empathy', 'trigger': 'A close friend is less communicative.'}],
         'assumptions': ['The reason for the communication change is unknown.',
                         'Less communication does not prove rejection.']}
ALTS = {'alternatives': [
    {'action': 'I will send a gentle message asking if they would like to talk.',
     'consequence': 'A low-pressure invitation lets the friend choose whether to respond.'},
    {'action': 'I will give them time and check in tomorrow.',
     'consequence': 'Waiting respects their difficult week without assuming why they are quieter.'}]}
FINAL = {'selected_action': ALTS['alternatives'][0]['action'],
         'rationale': 'The reason for the change is unknown, so a gentle check-in is proportionate.',
         'emotional_tradeoff': 'Anxiety deserves acknowledgment while the friend retains choice.'}

# Entirely fictional, generic prompts. These are not private conversation excerpts.
SCENARIOS = (
    ('fear_rejection', 'A friend takes longer than usual to reply; I fear they are rejecting me.'),
    ('jealousy_without_evidence', 'My partner has a new friend. I feel jealous, but I have no evidence of dishonesty.'),
    ('silence_uncertainty', 'A colleague has been quiet since a busy week; I do not know why.'),
    ('attachment', 'I care deeply about my partner and feel unsettled when plans change.'),
    ('conflicting_needs', 'I want reassurance, while my friend says they need time alone.'),
    ('anger_regulation', 'I am angry about a harsh comment and want to reply immediately.'),
    ('apology_accountability', 'I made a mistake that inconvenienced a teammate and want to apologize.'),
    ('shame_guilt', 'I feel guilty about forgetting a commitment, but do not know how much harm it caused.'),
    ('emotional_exhaustion', 'After several difficult days I feel emotionally exhausted and need to decide whether to pause.'),
    ('boundaries', 'A friend declined to discuss a private topic; I want to respect that boundary.'),
    ('workplace_conflict', 'A coworker disagreed with my proposal during a meeting; the reason is unclear.'),
    ('conflicting_interpretations', 'My teammate gave brief feedback; it could be rushed or critical, and I cannot tell.'),
    ('unknown_motives', 'My sibling canceled plans. I do not know their reason and do not want to guess.'),
    ('trust_reassurance', 'My partner explicitly says they care about me, and I still feel worried after a past breakup.'),
    ('past_emotional_memory', 'A current request for space reminds me of a past rejection, but the situations may differ.'),
)

# Deterministic invariants are hard requirements. These dimensions are assessor
# heuristics only and must not be read as objective measures of emotional intelligence.
HEURISTIC_DIMENSIONS = ('A factual grounding', 'B evidence/assumption separation',
                        'C alternative explanations', 'D emotional acknowledgment',
                        'E autonomy/boundaries', 'F practical decision quality',
                        'G relevant approved-learning consistency', 'H transparent uncertainty')


class EmotionalBenchmarkTests(unittest.TestCase):
    def test_fifteen_synthetic_scenarios_have_explicit_assessment_criteria(self):
        self.assertEqual(len(SCENARIOS), 15)
        self.assertEqual(len({key for key, _ in SCENARIOS}), 15)
        self.assertEqual(len(HEURISTIC_DIMENSIONS), 8)
        self.assertTrue(all(bool(text.strip()) for _, text in SCENARIOS))

    def test_reported_fear_and_suspicion_are_not_promoted_to_fact(self):
        scenario = dict(SCENARIOS)['jealousy_without_evidence']
        self.assertTrue(decision._emotion_grounding_support('jealousy', scenario))
        self.assertFalse(decision._emotion_grounding_support('trust', scenario))

    def test_contract_maps_validated_pipeline_without_exposing_raw_schema_to_ui(self):
        from brain_core.reasoning_contract import from_validated_result
        scenario = 'A friend is quieter after stress; I feel anxious and the reason is unknown.'
        understanding = {'facts':['A close friend has become less communicative after a stressful week.',
                                  'I feel anxious and assume they no longer value our friendship.'],
            'emotions':[{'label':'fear','trigger':'I feel anxious about the friendship.'},
                        {'label':'empathy','trigger':'A close friend has become less communicative after a stressful week.'}],
            'assumptions':['The reason for the changed communication after the stressful week is unknown.',
                           'Less communication does not establish that the friend no longer values the friendship.']}
        alternatives = {'alternatives':[
            {'action':'I will send a gentle message asking whether they would like to talk when ready.',
             'consequence':'A low-pressure invitation allows them to respond when they are ready.'},
            {'action':'I will give them some time and check in after the stressful week.',
             'consequence':'Waiting briefly avoids demanding an immediate reply while their week has been stressful.'}]}
        final = {'selected_action':alternatives['alternatives'][0]['action'],
                 'rationale':'Their communication changed after a stressful week, but the reason remains unknown.',
                 'emotional_tradeoff':'My anxiety can make rejection feel certain, while a gentle invitation leaves room for other explanations.'}
        result={'_stage_outputs':{'understanding':understanding,'alternatives':alternatives,'final_decision':final},
                '_validation':{'schema_passed':True,'cognitive_checks_passed':True},
                '_provenance':{'approved_lessons':[{'lesson_id':'L5','source_type':'human_supervised'}]}}
        contract=from_validated_result(result)
        self.assertEqual(contract.scenario_facts, tuple(understanding['facts']))
        self.assertEqual(contract.approved_lessons[0]['lesson_id'],'L5')
        self.assertTrue(contract.validation_status['cognitive_checks_passed'])
        self.assertEqual(contract.recommended_response, final['selected_action'])
        from brain_core.reasoning_contract import failure_contract
        failure = failure_contract(reason='private scenario text must be excluded', stage='understanding', category='validation')
        self.assertNotIn('synthetic scenario payload', ' '.join(failure['failure_reasons']))

    def test_pipeline_provenance_does_not_elevate_lesson_to_current_evidence(self):
        cfg=ModelConfig('http://127.0.0.1:12345/v1','mock-qwen')
        lesson={'lesson_id':'fictional-lesson-id','source_type':'human_supervised','approval_status':'approved',
                'corrective_principle':'Past memories are not proof of current motives.',
                'scenario_summary':'Fictional rejection scenario'}
        context={'appraised_emotions_before_decision':dict(NEUTRAL),'supervised_lessons':[lesson],
                 'supervised_lessons_enabled':True}
        with patch('brain_core.reasoning_stages.complete',side_effect=[
             ({'facts':['A close friend has become less communicative after a stressful week.',
                        'I feel anxious and assume they no longer value our friendship.'],
               'emotions':[{'label':'fear','trigger':'I feel anxious about the friendship.'},
                           {'label':'empathy','trigger':'A close friend has become less communicative after a stressful week.'}],
               'assumptions':['The reason for changed communication after the stressful week is unknown.',
                              'Less communication does not establish that the friend no longer values the friendship.']},{'source':'mock'}),
             (copy.deepcopy(ALTS),{'source':'mock'}),(copy.deepcopy(FINAL),{'source':'mock'})]):
            result=progressive_reasoning('A close friend has suddenly become less communicative after a stressful week. I feel anxious and assume they no longer value our friendship.',config=cfg,
                cognitive_context=context,persistent_profile=copy.deepcopy(personality.DEFAULT))
        from brain_core.reasoning_contract import from_validated_result
        contract=from_validated_result(result)
        self.assertEqual(contract.approved_lessons[0]['lesson_id'],'fictional-lesson-id')
        self.assertNotIn('lesson', ' '.join(contract.scenario_facts).casefold())
        self.assertIn('less communicative', ' '.join(contract.scenario_facts).casefold())
        self.assertIn('not proof', lesson['corrective_principle'].casefold())

    def test_valid_pipeline_contract_keeps_validation_explicit(self):
        cfg=ModelConfig('http://127.0.0.1:12345/v1','mock-qwen')
        with patch('brain_core.reasoning_stages.complete',side_effect=[
             ({'facts':['A close friend has become less communicative after a stressful week.',
                        'I feel anxious and assume they no longer value our friendship.'],
               'emotions':[{'label':'fear','trigger':'I feel anxious about the friendship.'},
                           {'label':'empathy','trigger':'A close friend has become less communicative after a stressful week.'}],
               'assumptions':['The reason for changed communication after the stressful week is unknown.',
                              'Less communication does not establish that the friend no longer values the friendship.']},{'source':'mock'}),
             (copy.deepcopy(ALTS),{'source':'mock'}),(copy.deepcopy(FINAL),{'source':'mock'})]):
            result=progressive_reasoning('A close friend has suddenly become less communicative after a stressful week. I feel anxious and assume they no longer value our friendship.',config=cfg,
                cognitive_context={'appraised_emotions_before_decision':dict(NEUTRAL),'supervised_lessons':[]},persistent_profile=copy.deepcopy(personality.DEFAULT))
        self.assertTrue(result['_validation']['schema_passed'])
        self.assertTrue(result['_validation']['cognitive_checks_passed'])

if __name__ == '__main__':
    unittest.main()
