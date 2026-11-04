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
        self.profile_path=self.root/'personality.json'
        self.state_path=self.root/'state.json'; self.history_path=self.root/'history.json'
        self.data_dir=self.root/'studio'; self.db_path=self.data_dir/'test.sqlite3'
        self.paths=dict(state_path=self.state_path,history_path=self.history_path,data_dir=self.data_dir,
                        db_path=self.db_path,profile_path=self.profile_path)
        for owner,name,value in [(personality,'PROFILE_PATH',self.profile_path),
                                (trainer,'STATE_PATH',self.state_path),(trainer,'HISTORY_PATH',self.history_path),
                                (studio,'DATA',self.data_dir),(studio,'DB',self.db_path)]:
            self.stack.enter_context(patch.object(owner,name,value))
        self.config=ModelConfig('http://127.0.0.1:12345/v1','controlled-test')

    def test_scenario_preferences_and_affect_are_distinct(self):
        profile=personality.load(profile_path=self.profile_path, initialize=True)
        a=cognition.assess(COWORKER,profile,{'emotions':appraisal.NEUTRAL})
        b=cognition.assess(JEALOUSY,profile,{'emotions':appraisal.NEUTRAL})
        self.assertEqual(a['decision_preferences'][0]['option'],'admit_and_repair')
        self.assertEqual(b['decision_preferences'][0]['option'],'regulate_and_communicate')
        self.assertGreater(a['appraised_emotions_before_decision']['guilt'],b['appraised_emotions_before_decision']['guilt'])
        self.assertGreater(b['appraised_emotions_before_decision']['jealousy'],a['appraised_emotions_before_decision']['jealousy'])
        self.assertNotEqual(a['affected_parties'],b['affected_parties'])

    def test_emotions_contribute_before_decision_without_changing_traits(self):
        p=personality.load(profile_path=self.profile_path,initialize=True);low=dict(appraisal.NEUTRAL,guilt=0);high=dict(low,guilt=1)
        def score(e):
            ctx=cognition.build_context(p,low,{},e,[],scenario=COWORKER)
            return next(x['emotion_contribution'] for x in ctx['decision_preferences'] if x['option']=='admit_and_repair')
        self.assertGreater(score(high),score(low));self.assertEqual(personality.inspect(profile_path=self.profile_path),p)

    def test_negated_responsibility_is_not_assumed(self):
        self.assertFalse(cognition.situation('You did not make a mistake; your coworker was blamed.')['own_error_affecting_colleague'])

    def test_no_dishonesty_evidence_is_not_distrust(self):
        self.assertGreater(appraisal.lexical_appraisal(JEALOUSY)['trust'],.5)

    def test_unrelated_coworker_memory_does_not_leak_into_jealousy(self):
        data=simulated_output(COWORKER);data['_provenance']={'source':'unit_test_mock'};data['_trainer_approved']=True
        tid=studio.add_turn(COWORKER,'',data,{},data_dir=self.data_dir,db_path=self.db_path)
        studio.rate_turn(tid,'poor','Own the mistake and correct unfair blame.',data_dir=self.data_dir,db_path=self.db_path)
        self.assertEqual(memory.experiences(JEALOUSY,data_dir=self.data_dir,db_path=self.db_path),[])
        self.assertEqual(studio.feedback_context(JEALOUSY,data_dir=self.data_dir,db_path=self.db_path),[])

    def test_bare_option_ids_in_recommendation_fields_are_rejected(self):
        for location,value in [('emotion','user_emotion'),('emotion','guilt, user_emotion'),('emotion','string'),
                               ('action','set_boundaries'),('action','seek_clarity'),('action','option 1')]:
            data=simulated_output(JEALOUSY)
            if location=='emotion':data['emotion']=value
            else:data['decision']['recommended_action']=value
            with self.subTest(value=value),self.assertRaises(ValueError):decision.validate_quality(data,JEALOUSY)

    def test_entire_copied_vector_rejected_without_artificial_changes(self):
        data=simulated_output(COWORKER);data['emotions']=dict(appraisal.NEUTRAL)
        cues=appraisal.lexical_appraisal(COWORKER)
        with self.assertRaisesRegex(ValueError,'copied state'):
            decision.validate_quality(data,COWORKER,previous=appraisal.NEUTRAL,appraisal=cues)

    def test_concrete_action_sentence_is_accepted(self):
        data = simulated_output(COWORKER)
        data['decision']['recommended_action'] = 'I will document my error and arrange a joint correction with the supervisor'
        decision.validate_quality(data, COWORKER)

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
        trainer.write_json(self.state_path, {'iterations':0,'emotion':'neutral','metrics':dict(trainer.BASE),'emotions':dict(appraisal.NEUTRAL)})
        trainer.write_json(self.history_path, {'iterations':0,'rules':[],'history':[]})
        state,history=trainer.inspect_status(state_path=self.state_path,history_path=self.history_path)
        state['emotions'].pop('guilt');state['emotions'].pop('jealousy')
        trainer.write_json(trainer.STATE_PATH,state)
        original=trainer.STATE_PATH.read_bytes();old_history=trainer.HISTORY_PATH.read_bytes()
        migrated,_=trainer.inspect_status(state_path=self.state_path,history_path=self.history_path)
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
        calls=[];profile=personality.load(profile_path=self.profile_path,initialize=True);profile_bytes=self.profile_path.read_bytes()
        def fake(messages,config,schema):
            request=json.loads(messages[-1]['content']);calls.append(request)
            if schema.get('properties',{}).get('facts'):
                if 'coworker' in request['scenario']:
                    facts=['I made a mistake that caused my closest coworker to be blamed.','Admitting the mistake could damage my reputation and promotion.','My colleague trusts me.']
                    emotions=[{'label':'guilt','trigger':'I feel guilty and fear promotion damage.'},{'label':'fear','trigger':'I feel guilty and fear promotion damage.'},{'label':'trust','trigger':'My colleague trusts me.'}]
                    assumption='The promotion outcome is unknown.'
                else:
                    facts=['My partner has developed a close friendship with someone they previously dated.','They openly tell me about their friendship.','I feel jealous and have no evidence of dishonesty.']
                    emotions=[{'label':'jealousy','trigger':'I feel jealous about the friendship.'},{'label':'trust','trigger':'The partner openly tells me about their friendship.'}]
                    assumption='There is no evidence that my partner has been dishonest.'
                return {'facts':facts,'emotions':emotions,'assumptions':[assumption]},{'source':'unit_test_mock'}
            if 'alternatives' in schema.get('properties',{}):
                if 'coworker' in request['scenario']:
                    action='I will correct the blame with the same audience that heard it, not just privately.' if request.get('previous_trainer_corrections') else 'I will acknowledge the blame and correct it with my supervisor.'
                    second='I will check the report facts with my supervisor before deciding how to correct the blame.'
                    consequences=['Correcting the blame may reduce harm to my coworker.','Checking facts may help ensure an accurate correction.']
                else:
                    action='I will ask my partner how they understand this friendship.'
                    second='I will tell my partner I feel jealous and ask for reassurance.'
                    consequences=['A direct question may clarify how my partner sees the friendship.','Sharing my jealousy may open an honest conversation.']
                return {'alternatives':[{'action':action,'consequence':consequences[0]},{'action':second,'consequence':consequences[1]}]},{'source':'unit_test_mock'}
            options=request.get('validated_alternatives',{}).get('alternatives',[])
            action=options[0]['action']
            if 'coworker' in request['scenario']:
                rationale='My mistake led to my closest coworker being blamed, so I should correct the record.'
                tradeoff='Guilt urges repair while fear about promotion makes disclosure difficult.'
            else:
                rationale='My partner has a close friendship with someone they dated before, so I should ask about it.'
                tradeoff='Jealousy can make me uneasy while trust supports an open conversation.'
            return {'selected_action':action,'rationale':rationale,'emotional_tradeoff':tradeoff},{'source':'unit_test_mock'}
        with patch('brain_core.reasoning_stages.complete',side_effect=fake):
            paths=self.paths
            first,_,a,_=service.analyze(COWORKER,config=self.config,**paths)
            approved_first=dict(a);approved_first.pop('_trainer_pending',None);approved_first['_trainer_approved']=True
            first=studio.add_turn(COWORKER,'',approved_first,{},data_dir=self.data_dir,db_path=self.db_path)
            service.give_feedback(first,'partial','Correct the coworker blame with the same audience that heard it, not just privately.', data_dir=self.data_dir, db_path=self.db_path)
            _,_,pending_b,retrieved=service.analyze(COWORKER,config=self.config,**paths)
            self.assertTrue(pending_b['_trainer_pending'])
            b=dict(pending_b);b.pop('_trainer_pending',None);b['_trainer_approved']=True
            b['_provenance']={'source':'approved_training','model':'controlled-test','seconds':0}
            b['_cognitive_context']=cognition.assess(COWORKER,profile,{'emotions':dict(appraisal.NEUTRAL)})
            _,_,b=trainer.train(COWORKER,persistent_profile=profile,proposed_result=b,
                              state_path=self.state_path,history_path=self.history_path,
                              data_dir=self.data_dir,db_path=self.db_path,profile_path=self.profile_path,
                              feedback='Apply the approved correction.')
            _,_,pending_c,_=service.analyze(JEALOUSY,config=self.config,**paths)
            c=dict(pending_c);c.pop('_trainer_pending',None);c['_trainer_approved']=True
            c['_provenance']={'source':'approved_training','model':'controlled-test','seconds':0}
            c['_cognitive_context']=cognition.assess(JEALOUSY,profile,{'emotions':dict(appraisal.NEUTRAL)})
            _,state,c=trainer.train(JEALOUSY,persistent_profile=profile,proposed_result=c,
                                  state_path=self.state_path,history_path=self.history_path,
                                  data_dir=self.data_dir,db_path=self.db_path,profile_path=self.profile_path,
                                  feedback='Apply the approved correction.')
        self.assertNotEqual(a['decision']['recommended_action'],b['decision']['recommended_action'])
        self.assertTrue(retrieved[0]['correction'].startswith('Correct the coworker blame'))
        self.assertEqual(retrieved[0]['correction'].startswith('Correct the coworker blame'),True)
        self.assertNotEqual(b['emotions'],c['emotions'])
        self.assertNotEqual(b['decision']['recommended_action'],c['decision']['recommended_action'])
        self.assertEqual(len(studio.inspect_turns(db_path=self.db_path)),1)
        self.assertEqual(trainer.inspect_status(state_path=self.state_path,history_path=self.history_path)[0]['emotions'],state['emotions'])
        self.assertEqual(self.profile_path.read_bytes(),profile_bytes)
        self.assertEqual(calls[0]['scenario'],calls[3]['scenario'])
        self.assertNotIn('previous_state',calls[0]);self.assertNotIn('proposed_rules_for_review',calls[0])

    def test_bounded_repair_accepts_concrete_recommendation(self):
        understanding = {'facts':['You made a mistake that led to your closest coworker being blamed.','Admitting the mistake could damage your reputation and promotion.','Your colleague trusts you.'], 'emotions':[{'label':'guilt','trigger':'You feel guuilty and afraid.'},{'label':'fear','trigger':'You feel guuilty and afraid.'},{'label':'trust','trigger':'Your colleague trusts you.'}], 'assumptions':['The promotion outcome is unknown.']}
        alternatives = {'alternatives':[{'action':'I will acknowledge my mistake and correct the blame with my supervisor.','consequence':'Correcting the blame may reduce harm to my coworker.'},{'action':'I will check the report facts with my supervisor before deciding how to correct the blame.','consequence':'Checking facts may help ensure an accurate correction.'}]}
        final = {'selected_action':alternatives['alternatives'][0]['action'],'rationale':'My mistake led to my closest coworker being blamed, so I should correct the record.','emotional_tradeoff':'Guilt urges repair while fear about promotion makes disclosure difficult.'}
        calls=[]
        outputs=[understanding,understanding,alternatives,final]
        def fake(messages,config,schema):
            calls.append(messages)
            request=json.loads(messages[-1]['content'])
            if len(calls)==1:
                invalid=copy.deepcopy(understanding);invalid['facts'][0]='An unrelated sports team won.';return invalid,{'source':'unit_test_mock'}
            if 'validated_understanding' in request:
                return {'alternatives':[{'action':'I will acknowledge my mistake and correct the blame with my supervisor.','consequence':'Correcting the blame may reduce harm to my coworker.'},{'action':'I will check the report facts with my supervisor before deciding how to correct the blame.','consequence':'Checking facts may help ensure an accurate correction.'}]},{'source':'unit_test_mock'}
            if 'validated_alternatives' in request:
                opts=request['validated_alternatives']['alternatives']
                return {'selected_action':opts[0]['action'],'rationale':'My mistake led to my closest coworker being blamed, so I should correct the record.','emotional_tradeoff':'Guilt urges repair while fear about promotion makes disclosure difficult.'},{'source':'unit_test_mock'}
            return copy.deepcopy(understanding),{'source':'unit_test_mock'}
        with patch('brain_core.reasoning_stages.complete',side_effect=fake):
            _, _, result, _ = service.analyze(COWORKER, config=self.config, **self.paths)
        self.assertEqual(len(calls), 4)
        self.assertTrue(result['_trainer_pending'])
        self.assertTrue(result['_stage_repair_attempts']['understanding'])
        self.assertEqual(studio.inspect_turns(db_path=self.db_path), [])

    def test_failed_repair_does_not_change_persistent_memory_and_records_diagnostic(self):
        trainer.write_json(self.state_path, {'iterations': 0, 'emotion': 'neutral', 'metrics': dict(trainer.BASE), 'emotions': dict(appraisal.NEUTRAL)})
        trainer.write_json(self.history_path, {'iterations': 0, 'rules': [], 'history': []})
        before_state = self.state_path.read_bytes()
        before_history = self.history_path.read_bytes()
        invalid = {'facts': ['An unrelated event occurred at work.'], 'emotions': [{'label': 'guilt', 'trigger': 'my mistake led to blame'}, {'label': 'fear', 'trigger': 'promotion risk'}], 'assumptions': ['The promotion outcome is unknown.']}
        diagnostics = self.root / 'diagnostics'
        with patch.dict('os.environ', {'BRAIN_DIAGNOSTIC_DIR': str(diagnostics)}), \
             patch('brain_core.reasoning_stages.complete', side_effect=[
                 (invalid, {'source': 'local_model', 'model': 'controlled-test'}),
                 (invalid, {'source': 'local_model', 'model': 'controlled-test'})]):
            with self.assertRaises(ModelOutputError) as caught:
                service.analyze(COWORKER, config=self.config, **self.paths)
        self.assertIsNotNone(caught.exception.diagnostic_id)
        self.assertEqual(self.state_path.read_bytes(), before_state)
        self.assertEqual(self.history_path.read_bytes(), before_history)
        self.assertEqual(studio.inspect_turns(db_path=self.db_path), [])
        records = list(diagnostics.glob('*.json'))
        self.assertEqual(len(records), 1)
        record = json.loads(records[0].read_text(encoding='utf-8'))
        self.assertIn('validation_error', record)
        self.assertNotIn('scenario', record)

    def test_invalid_output_does_not_append_or_change_state(self):
        trainer.load_or_init(state_path=self.state_path,history_path=self.history_path)
        before,_=trainer.inspect_status(state_path=self.state_path,history_path=self.history_path);data=simulated_output(COWORKER);data['emotion']='user_emotion'
        with patch('brain_core.reasoning_stages.complete',side_effect=[(data,{'source':'unit_test_mock'}),(data,{'source':'unit_test_mock'})]):
            with self.assertRaises(ModelOutputError):service.analyze(COWORKER,config=self.config,state_path=self.state_path,history_path=self.history_path,data_dir=self.data_dir,db_path=self.db_path,profile_path=self.profile_path,persist_fixture_state=False)
        self.assertEqual(trainer.inspect_status(state_path=self.state_path,history_path=self.history_path)[0],before);self.assertEqual(studio.inspect_turns(db_path=self.db_path),[])

if __name__=='__main__':unittest.main()
