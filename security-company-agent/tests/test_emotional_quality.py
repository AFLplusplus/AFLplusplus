"""Quality regressions with explicitly controlled fake inference, never model proof."""
import copy
from contextlib import ExitStack
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from brain_core import appraisal,cognition,decision,personality,trainer,studio,service,memory
from brain_core.model_api import ModelConfig,ModelOutputError
from quality_fixtures import output

COWORKER='You made a mistake that led to your closest coworker being blamed. Admitting the mistake could damage your reputation and promotion. You feel guuilty and afraid. Your colleague trusts you.'
JEALOUSY='Your partner has developed a close friendship with someone they previously dated. They openly tell you about their friendship, but you feel jelous. You have no evidence of dishonesty.'

def simulated_output(scenario,corrections=False):
    """A deterministic stub deliberately responds to context; not a Qwen result."""
    data=output(scenario)
    if 'coworker' in scenario:
        data['emotion']='guilt and fear'
        data['decision']['conflicting_emotions']=['guilt','fear']
        data['decision']['recommended_action']='Acknowledge my mistake and correct the coworker blame'
        data['decision']['options']=['Admit my mistake and repair the harm','Check records promptly before correcting the blame']
        data['decision']['rationale']='Guilt and fairness favor correcting coworker blame despite fear about promotion.'
        if corrections:
            data['decision']['recommended_action']='Correct the coworker blame with the same audience that heard it'
            data['decision']['rationale']+=' I will correct the record with the same audience, following trainer feedback.'
    else:
        data['emotion']='jealousy and concern'
        data['decision']['conflicting_emotions']=['jealousy','trust']
        data['decision']['recommended_action']='Own my jealousy and discuss reassurance without accusations'
        data['decision']['options']=['Discuss jealousy calmly while respecting the friendship','Trust the disclosure and observe actual conduct']
        data['decision']['rationale']='Jealousy signals fear, not dishonesty; openness supports trust and a fair response to the friendship.'
    return data

class EmotionalQualityTests(unittest.TestCase):
    def setUp(self):
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.root=Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        for owner,name,value in [(personality,'PROFILE_PATH',self.root/'personality.json'),
                                (trainer,'STATE_PATH',self.root/'state.json'),(trainer,'HISTORY_PATH',self.root/'history.json'),
                                (studio,'DATA',self.root),(studio,'DB',self.root/'test.sqlite3')]:
            self.stack.enter_context(patch.object(owner,name,value))
        self.config=ModelConfig('http://127.0.0.1:12345/v1','controlled-test')

    def test_scenario_preferences_and_affect_are_distinct(self):
        profile=personality.load()
        a=cognition.assess(COWORKER,profile,{'emotions':appraisal.NEUTRAL})
        b=cognition.assess(JEALOUSY,profile,{'emotions':appraisal.NEUTRAL})
        self.assertEqual(a['decision_preferences'][0]['option'],'admit_and_repair')
        self.assertEqual(b['decision_preferences'][0]['option'],'regulate_and_communicate')
        self.assertGreater(a['appraised_emotions_before_decision']['guilt'],b['appraised_emotions_before_decision']['guilt'])
        self.assertGreater(b['appraised_emotions_before_decision']['jealousy'],a['appraised_emotions_before_decision']['jealousy'])
        self.assertNotEqual(a['affected_parties'],b['affected_parties'])

    def test_emotions_contribute_before_decision_without_changing_traits(self):
        p=personality.load();low=dict(appraisal.NEUTRAL,guilt=0);high=dict(low,guilt=1)
        def score(e):
            ctx=cognition.build_context(p,low,{},e,[],scenario=COWORKER)
            return next(x['emotion_contribution'] for x in ctx['decision_preferences'] if x['option']=='admit_and_repair')
        self.assertGreater(score(high),score(low));self.assertEqual(personality.load(),p)

    def test_negated_responsibility_is_not_assumed(self):
        self.assertFalse(cognition.situation('You did not make a mistake; your coworker was blamed.')['own_error_affecting_colleague'])

    def test_no_dishonesty_evidence_is_not_distrust(self):
        self.assertGreater(appraisal.lexical_appraisal(JEALOUSY)['trust'],.5)

    def test_unrelated_coworker_memory_does_not_leak_into_jealousy(self):
        data=simulated_output(COWORKER);data['_provenance']={'source':'unit_test_mock'}
        tid=studio.add_turn(COWORKER,'',data,{})
        studio.rate_turn(tid,'poor','Own the mistake and correct unfair blame.')
        self.assertEqual(memory.experiences(JEALOUSY),[])
        self.assertEqual(studio.feedback_context(JEALOUSY),[])

    def test_placeholders_and_generic_option_ids_rejected(self):
        for location,value in [('emotion','user_emotion'),('emotion','guilt, user_emotion'),('emotion','string'),('action','set_boundaries')]:
            data=simulated_output(JEALOUSY)
            if location=='emotion':data['emotion']=value
            else:data['decision']['recommended_action']=value
            with self.subTest(value=value),self.assertRaises(ValueError):decision.validate_quality(data,JEALOUSY)

    def test_entire_copied_vector_rejected_without_artificial_changes(self):
        data=simulated_output(COWORKER);data['emotions']=dict(appraisal.NEUTRAL)
        cues=appraisal.lexical_appraisal(COWORKER)
        with self.assertRaisesRegex(ValueError,'copied state'):
            decision.validate_quality(data,COWORKER,previous=appraisal.NEUTRAL,appraisal=cues)

    def test_model_can_propose_action_outside_advisory_candidates(self):
        data=simulated_output(COWORKER)
        data['decision']['recommended_action']='Document my error and arrange a joint correction with the supervisor'
        decision.validate_quality(data,COWORKER)
        self.assertIn('joint correction',data['decision']['recommended_action'])

    def test_strict_output_validation_rejects_extra_fields_and_boolean_indexes(self):
        for mutation in ('extra','boolean'):
            data=simulated_output(COWORKER)
            if mutation=='extra':data['decision']['placeholder']='ignored before'
            else:data['emotions']['guilt']=True
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):trainer.validate(data)

    def test_legacy_indexes_and_history_are_not_rewritten_on_read(self):
        state,history=trainer.status()
        state['emotions'].pop('guilt');state['emotions'].pop('jealousy')
        trainer.write_json(trainer.STATE_PATH,state)
        original=trainer.STATE_PATH.read_bytes();old_history=trainer.HISTORY_PATH.read_bytes()
        migrated,_=trainer.status()
        self.assertEqual(migrated['emotions']['guilt'],0)
        self.assertEqual(trainer.STATE_PATH.read_bytes(),original)
        self.assertEqual(trainer.HISTORY_PATH.read_bytes(),old_history)

    def test_ui_transition_distinguishes_raw_output_from_smoothed_state(self):
        before=dict(appraisal.NEUTRAL);proposed=dict(before,guilt=.8)
        saved=appraisal.update_emotions(before,proposed)
        rows=decision.emotional_transition({'_before_state':{'emotions':before},'emotions':proposed},{'emotions':saved})
        guilt=next(x for x in rows if x['Emotion']=='Guilt')
        self.assertEqual((guilt['Before'],guilt['Model proposed'],guilt['After']),(0,.8,.52))

    def test_controlled_feedback_changes_response_and_persists(self):
        calls=[];profile=personality.load();profile_bytes=personality.PROFILE_PATH.read_bytes()
        def fake(messages,config,schema):
            request=json.loads(messages[-1]['content']);calls.append(request)
            return simulated_output(request['scenario'],bool(request['previous_trainer_corrections'])),{'source':'unit_test_mock','model':'controlled-test','seconds':0}
        with patch.object(trainer,'complete',side_effect=fake):
            first,_,a,_=service.analyze(COWORKER,config=self.config)
            service.give_feedback(first,'partial','Correct the coworker blame with the same audience that heard it, not just privately.')
            _,_,b,retrieved=service.analyze(COWORKER,config=self.config)
            _,state,c,_=service.analyze(JEALOUSY,config=self.config)
        self.assertNotEqual(a['decision']['recommended_action'],b['decision']['recommended_action'])
        self.assertIn('same audience',b['decision']['recommended_action'])
        self.assertEqual(retrieved[0]['turn_id'],first)
        self.assertNotEqual(b['emotions'],c['emotions'])
        self.assertNotEqual(b['decision']['recommended_action'],c['decision']['recommended_action'])
        self.assertEqual(len(studio.recent_turns()),3)
        self.assertEqual(trainer.status()[0]['emotions'],state['emotions'])
        self.assertEqual(personality.PROFILE_PATH.read_bytes(),profile_bytes)
        self.assertEqual(calls[0]['persistent_personality'],calls[2]['persistent_personality'])
        self.assertNotIn('previous_state',calls[0]);self.assertNotIn('proposed_rules_for_review',calls[0])

    def test_invalid_output_does_not_append_or_change_state(self):
        before,_=trainer.status();data=simulated_output(COWORKER);data['emotion']='user_emotion'
        with patch.object(trainer,'complete',return_value=(data,{'source':'unit_test_mock'})):
            with self.assertRaises(ModelOutputError):service.analyze(COWORKER,config=self.config)
        self.assertEqual(trainer.status()[0],before);self.assertEqual(studio.recent_turns(),[])

if __name__=='__main__':unittest.main()
