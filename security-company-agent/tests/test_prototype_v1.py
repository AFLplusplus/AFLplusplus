"""Prototype persistence and causal-planning tests. All inference is mocked."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from brain_core import personality, trainer, studio, service, cognition, memory
from brain_core.appraisal import NEUTRAL
from brain_core.model_api import ModelConfig
from quality_fixtures import output

class PrototypeTests(unittest.TestCase):
    def setUp(self):
        self.context=ExitStack()
        self.addCleanup(self.context.close)
        self.root=Path(self.context.enter_context(tempfile.TemporaryDirectory()))
        for owner,name,value in ((personality,'PROFILE_PATH',self.root/'personality.json'),
                                  (trainer,'STATE_PATH',self.root/'state.json'),
                                  (trainer,'HISTORY_PATH',self.root/'history.json'),
                                  (studio,'DATA',self.root),(studio,'DB',self.root/'brain.sqlite3')):
            self.context.enter_context(patch.object(owner,name,value))

    def test_identity_is_supplied_in_context(self):
        profile=personality.load(profile_path=self.root/'personality.json',initialize=True)
        self.assertEqual(profile['identity_id'],personality.model_context(profile)['identity_id'])

    def test_invalid_traits_are_not_reset(self):
        profile=personality.load(profile_path=self.root/'personality.json',initialize=True)
        profile['traits']['curiosity']=float('inf')
        personality.PROFILE_PATH.write_text(json.dumps(profile),encoding='utf-8')
        original=personality.PROFILE_PATH.read_bytes()
        with self.assertRaises(personality.PersonalityError):
            personality.load(profile_path=personality.PROFILE_PATH,initialize=True)
        self.assertEqual(personality.PROFILE_PATH.read_bytes(),original)

    def test_corrupted_personality_is_preserved(self):
        personality.PROFILE_PATH.write_text('{broken',encoding='utf-8')
        with self.assertRaises(personality.PersonalityError):
            personality.load(profile_path=personality.PROFILE_PATH,initialize=True)
        self.assertEqual(personality.PROFILE_PATH.read_text(),'{broken')

    def test_deleted_established_identity_is_not_recreated(self):
        personality.load(profile_path=personality.PROFILE_PATH,initialize=True)
        personality.PROFILE_PATH.unlink()  # this test owns its isolated temporary data
        with self.assertRaisesRegex(personality.PersonalityError,'missing'):
            personality.load(profile_path=personality.PROFILE_PATH,initialize=True)
        self.assertFalse(personality.PROFILE_PATH.exists())

    def test_concurrent_reads_retain_one_profile(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            profiles=list(pool.map(lambda _:personality.load(profile_path=self.root/'personality.json',initialize=True),range(12)))
        self.assertTrue(all(item==profiles[0] for item in profiles))

    def test_profile_and_traits_survive_a_fresh_python_process(self):
        profile=personality.load(profile_path=self.root/'personality.json',initialize=True)
        profile['traits']['curiosity']=0.73
        personality.PROFILE_PATH.write_text(json.dumps(profile),encoding='utf-8')
        code=('import sys,json; from pathlib import Path; '
              f'sys.path.insert(0,{str(ROOT)!r}); from brain_core import personality; '
              f'personality.PROFILE_PATH=Path({str(personality.PROFILE_PATH)!r}); '
              'print(json.dumps(personality.inspect()))')
        fresh=json.loads(subprocess.check_output([sys.executable,'-B','-c',code],text=True))
        self.assertEqual(fresh,profile)

    def test_offline_fixtures_do_not_persist_mood_or_change_stable_traits(self):
        profile=personality.load(profile_path=self.root/'personality.json',initialize=True)
        original=personality.PROFILE_PATH.read_bytes()
        _,first,_=trainer.train('I feel love, anger, fear and hurt.',mock=True,
                              state_path=self.root/'state.json',history_path=self.root/'history.json',
                              data_dir=self.root,db_path=self.root/'brain.sqlite3',
                              persistent_profile=profile,persist_fixture_state=True)
        _,second,_=trainer.train('A calm peaceful day.',mock=True,
                               state_path=self.root/'state.json',history_path=self.root/'history.json',
                               data_dir=self.root,db_path=self.root/'brain.sqlite3',
                               persistent_profile=profile,persist_fixture_state=True)
        self.assertEqual(first['emotions'],second['emotions'])
        self.assertEqual(personality.inspect(profile_path=self.root/'personality.json'),profile)
        self.assertEqual(personality.PROFILE_PATH.read_bytes(),original)
        self.assertEqual(trainer.inspect_status(state_path=self.root/'state.json', history_path=self.root/'history.json'),
                         (None, {'history': [], 'rules': []}))
        self.assertFalse((self.root/'state.json').exists())
        self.assertFalse((self.root/'history.json').exists())
        self.assertFalse((self.root/'brain.sqlite3').exists())

    def test_anger_changes_pre_decision_ranking(self):
        profile=personality.load(profile_path=self.root/'personality.json',initialize=True)
        low=dict(NEUTRAL)
        high=dict(low,anger=1)
        first=cognition.build_context(profile,NEUTRAL,{},low,[])['decision_preferences']
        second=cognition.build_context(profile,NEUTRAL,{},high,[])['decision_preferences']
        self.assertEqual(second[0]['option'],'pause_and_regulate')
        a=next(x['emotion_contribution'] for x in first if x['option']=='pause_and_regulate')
        b=next(x['emotion_contribution'] for x in second if x['option']=='pause_and_regulate')
        self.assertGreater(b,a)
        self.assertEqual(profile,personality.inspect(profile_path=self.root/'personality.json'))

    def test_relationship_emotions_are_separate(self):
        with studio.connect(initialize=True,data_dir=self.root,db_path=self.root/'brain.sqlite3'):
            pass
        memory.save_relationship('Partner',dict(NEUTRAL,trust=.2),data_dir=self.root,db_path=self.root/'brain.sqlite3')
        memory.save_relationship('Friend',dict(NEUTRAL,trust=.9),data_dir=self.root,db_path=self.root/'brain.sqlite3')
        self.assertEqual(memory.relationship('partner',data_dir=self.root,db_path=self.root/'brain.sqlite3')['trust'],.2)
        self.assertEqual(memory.relationship('friend',data_dir=self.root,db_path=self.root/'brain.sqlite3')['trust'],.9)
        self.assertEqual(memory.relationship(''),{})

    def test_two_mocked_model_sessions_share_identity_and_retrieve_experience(self):
        calls=[]
        def fake_complete(messages,config,schema):
            calls.append(json.loads(messages[-1]['content']))
            result=output(calls[-1]['scenario'])
            result['_trainer_approved']=True
            return result,{'source':'unit_test_mock','model':'fake','seconds':0}
        config=ModelConfig('http://127.0.0.1:12345/v1','unit-test')
        with patch('brain_core.reasoning_stages.complete',side_effect=[
             ({'facts':['Relationship love is present.','There is anger and uncertainty.'],'emotions':[{'label':'love','trigger':'Relationship love and anger are present.'},{'label':'anger','trigger':'Relationship love and anger are present.'},{'label':'anger','trigger':'Relationship love, anger and uncertainty are present.'}],'assumptions':['Love, anger and uncertainty appear in the scenario.']},{'source':'unit_test_mock'}),
             ({'alternatives':[{'action':'I will ask my partner what they need from me right now.','consequence':'Asking may clarify what support they want.'},{'action':'I will pause and write down what I need before talking with my partner.','consequence':'Pausing may help me sort through love, anger and uncertainty.'}]},{'source':'unit_test_mock'}),
             ({'selected_action':'I will ask my partner what they need from me right now.','rationale':'They feel hurt and afraid I may leave, so asking what they need can clarify the situation.','emotional_tradeoff':'Love encourages care while anger and fear make listening more difficult.'},{'source':'unit_test_mock'}),
             ({'facts':['Relationship love is present.','There is anger and uncertainty.'],'emotions':[{'label':'love','trigger':'Relationship love and anger are present.'},{'label':'anger','trigger':'Relationship love and anger are present.'},{'label':'anger','trigger':'Relationship love, anger and uncertainty are present.'}],'assumptions':['Love, anger and uncertainty appear in the scenario.']},{'source':'unit_test_mock'}),
             ({'alternatives':[{'action':'I will ask my partner what they need from me right now.','consequence':'Asking may clarify what support they want.'},{'action':'I will pause and write down what I need before talking with my partner.','consequence':'Pausing may help me sort through love, anger and uncertainty.'}]},{'source':'unit_test_mock'}),
             ({'selected_action':'I will ask my partner what they need from me right now.','rationale':'They feel hurt and afraid I may leave, so asking what they need can clarify the situation.','emotional_tradeoff':'Love encourages care while anger and fear make listening more difficult.'},{'source':'unit_test_mock'})]), \
             patch('subprocess.Popen',side_effect=AssertionError('Operational execution is forbidden')):
            paths=dict(state_path=self.root/'state.json',history_path=self.root/'history.json',
                       data_dir=self.root,db_path=self.root/'brain.sqlite3',profile_path=self.root/'personality.json',
                       initialize_profile=True)
            first,_,pending,_=service.analyze('Relationship love, anger and uncertainty',config=config,
                                              relationship_label='Partner',**paths)
            approved=dict(pending);approved.pop('_trainer_pending',None);approved['_trainer_approved']=True
            approved['_cognitive_context']=cognition.assess(
                'Relationship love, anger and uncertainty',
                personality.inspect(profile_path=paths['profile_path']), {'emotions':dict(NEUTRAL)})
            with studio.connect(initialize=True,data_dir=paths['data_dir'],db_path=paths['db_path']):
                pass
            memory.save_relationship('Partner', approved['_cognitive_context']['appraised_emotions_before_decision'],
                                     data_dir=paths['data_dir'],db_path=paths['db_path'])
            _, _, approved = trainer.train('Relationship love, anger and uncertainty',
                                        persistent_profile=personality.inspect(profile_path=paths['profile_path']),
                                        proposed_result=approved, state_path=paths['state_path'],
                                        history_path=paths['history_path'], data_dir=paths['data_dir'],
                                        db_path=paths['db_path'], profile_path=paths['profile_path'], feedback='Approved after review.')
            first=studio.add_turn('Relationship love, anger and uncertainty','',approved,{},
                                  data_dir=paths['data_dir'],db_path=paths['db_path'])
            service.give_feedback(first,'partial','Consider a trial boundary; suspicion is not proof.',
                                  data_dir=paths['data_dir'],db_path=paths['db_path'])
            second,_,pending_second,_=service.analyze('Relationship love, anger and uncertainty',config=config,
                                                      relationship_label='Partner',**paths)
            result=dict(pending_second);result.pop('_trainer_pending',None);result['_trainer_approved']=True
            result['_provenance']={'source':'approved_training','model':'fake','seconds':0}
            result['_cognitive_context']=trainer.cognition.assess(
                'Relationship love, anger and uncertainty',
                personality.inspect(profile_path=paths['profile_path']), {'emotions':dict(NEUTRAL)})
            _, _, result=trainer.train('Relationship love, anger and uncertainty',
                                    persistent_profile=personality.inspect(profile_path=paths['profile_path']),
                                    proposed_result=result, state_path=paths['state_path'],
                                    history_path=paths['history_path'], feedback='Approved after review.', data_dir=paths['data_dir'],
                                    db_path=paths['db_path'], profile_path=paths['profile_path'])
        self.assertEqual(len(studio.inspect_turns(db_path=paths['db_path'])),2)
        self.assertEqual(result.get('_personality_id', personality.DEFAULT['identity_id']),'sovereign-brain-001')
        self.assertEqual(len(studio.inspect_turns(db_path=paths['db_path'])),2)
        self.assertEqual(trainer.status(state_path=paths['state_path'],history_path=paths['history_path'])[0]['iterations'],1)

    def test_mock_sessions_do_not_teach_relationship_memory(self):
        service.analyze('Love and anger',mock=True,relationship_label='Partner',
                        state_path=self.root/'state.json',history_path=self.root/'history.json',
                        data_dir=self.root,db_path=self.root/'brain.sqlite3',profile_path=self.root/'personality.json')
        self.assertEqual(memory.relationship('Partner',data_dir=self.root,db_path=self.root/'brain.sqlite3'),{})

if __name__=='__main__':
    unittest.main()
