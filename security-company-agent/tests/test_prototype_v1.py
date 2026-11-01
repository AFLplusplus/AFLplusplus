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
        self.assertEqual(personality.load()['identity_id'],personality.model_context()['identity_id'])

    def test_invalid_traits_are_not_reset(self):
        profile=personality.load()
        profile['traits']['curiosity']=float('inf')
        personality.PROFILE_PATH.write_text(json.dumps(profile),encoding='utf-8')
        original=personality.PROFILE_PATH.read_bytes()
        with self.assertRaises(personality.PersonalityError):
            personality.load()
        self.assertEqual(personality.PROFILE_PATH.read_bytes(),original)

    def test_corrupted_personality_is_preserved(self):
        personality.PROFILE_PATH.write_text('{broken',encoding='utf-8')
        with self.assertRaises(personality.PersonalityError):
            personality.load()
        self.assertEqual(personality.PROFILE_PATH.read_text(),'{broken')

    def test_deleted_established_identity_is_not_recreated(self):
        personality.load()
        personality.PROFILE_PATH.unlink()  # this test owns its isolated temporary data
        with self.assertRaisesRegex(personality.PersonalityError,'missing'):
            personality.load()
        self.assertFalse(personality.PROFILE_PATH.exists())

    def test_concurrent_reads_retain_one_profile(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            profiles=list(pool.map(lambda _:personality.load(),range(12)))
        self.assertTrue(all(item==profiles[0] for item in profiles))

    def test_profile_and_traits_survive_a_fresh_python_process(self):
        profile=personality.load()
        profile['traits']['curiosity']=0.73
        personality.PROFILE_PATH.write_text(json.dumps(profile),encoding='utf-8')
        code=('import sys,json; from pathlib import Path; '
              f'sys.path.insert(0,{str(ROOT)!r}); from brain_core import personality; '
              f'personality.PROFILE_PATH=Path({str(personality.PROFILE_PATH)!r}); '
              'print(json.dumps(personality.load()))')
        fresh=json.loads(subprocess.check_output([sys.executable,'-B','-c',code],text=True))
        self.assertEqual(fresh,profile)

    def test_moods_change_without_changing_stable_traits(self):
        profile=personality.load()
        original=personality.PROFILE_PATH.read_bytes()
        first,_=trainer.train('I feel love, anger, fear and hurt.',mock=True)
        second,_=trainer.train('A calm peaceful day.',mock=True)
        self.assertNotEqual(first['emotions'],second['emotions'])
        self.assertEqual(personality.load(),profile)
        self.assertEqual(personality.PROFILE_PATH.read_bytes(),original)

    def test_anger_changes_pre_decision_ranking(self):
        profile=personality.load()
        low=dict(NEUTRAL)
        high=dict(low,anger=1)
        first=cognition.build_context(profile,NEUTRAL,{},low,[])['decision_preferences']
        second=cognition.build_context(profile,NEUTRAL,{},high,[])['decision_preferences']
        self.assertEqual(first[0]['option'],'seek_clarity')
        self.assertEqual(second[0]['option'],'set_boundaries')
        self.assertEqual(profile,personality.load())

    def test_relationship_emotions_are_separate(self):
        memory.save_relationship('Partner',dict(NEUTRAL,trust=.2))
        memory.save_relationship('Friend',dict(NEUTRAL,trust=.9))
        self.assertEqual(memory.relationship('partner')['trust'],.2)
        self.assertEqual(memory.relationship('friend')['trust'],.9)
        self.assertEqual(memory.relationship(''),{})

    def test_two_mocked_model_sessions_share_identity_and_retrieve_experience(self):
        calls=[]
        fixture=trainer.infer('fixture','',{}, {},mock=True)
        def fake_complete(messages,config,schema):
            calls.append(json.loads(messages[-1]['content']))
            return copy.deepcopy(fixture),{'source':'unit_test_mock','model':'fake','seconds':0}
        config=ModelConfig('http://127.0.0.1:12345/v1','unit-test')
        with patch.object(trainer,'complete',side_effect=fake_complete), \
             patch('subprocess.Popen',side_effect=AssertionError('Operational execution is forbidden')):
            first,_,_,_=service.analyze('Relationship love, anger and uncertainty',config=config,
                                       relationship_label='Partner')
            service.give_feedback(first,'partial','Consider a trial boundary; suspicion is not proof.')
            second,_,result,_=service.analyze('Relationship love, anger and uncertainty',config=config,
                                             relationship_label='Partner')
        self.assertEqual(calls[0]['persistent_personality'],calls[1]['persistent_personality'])
        self.assertEqual(calls[1]['pre_decision_appraisal']['previous_experiences'][0]['turn_id'],first)
        self.assertEqual(calls[1]['previous_trainer_corrections'][0]['turn_id'],first)
        self.assertTrue(calls[1]['pre_decision_appraisal']['relationship_emotions'])
        self.assertEqual(result['_personality_id'],'sovereign-brain-001')
        self.assertEqual(len(studio.recent_turns()),2)
        self.assertEqual(trainer.status()[0]['iterations'],2)

    def test_mock_sessions_do_not_teach_relationship_memory(self):
        service.analyze('Love and anger',mock=True,relationship_label='Partner')
        self.assertEqual(memory.relationship('Partner'),{})

if __name__=='__main__':
    unittest.main()
