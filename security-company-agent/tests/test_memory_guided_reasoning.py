"""Lesson 5 retrieval and guidance integrity against isolated stores."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from brain_core import lessons, memory, service
from brain_core.reasoning_stages import progressive_reasoning
from brain_core.model_api import ModelConfig, ModelOutputError

LESSON_ID='b95028bf-bef1-49e6-be53-ccc99d935689'
class MemoryGuidedReasoningTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name); self.db=self.root/'brain.sqlite3'
  record=lessons.propose(scenario='A past rejection memory is triggered by a friend becoming quiet.',
      emotional_context='Fear and anxiety are reported.',observed_facts='The friend is quieter than usual.',
      uncertainties='The reason for the change is unknown.',
      corrective_principle='Past emotional memories can influence the present, but are not proof of another person’s intentions. Separate reported facts from assumptions.',
      response_pattern='Acknowledge the feeling, distinguish observations from assumptions, and ask gently without pressure.',relationship_context='friend')
  record['lesson_id']=LESSON_ID
  lessons.approve(record,data_dir=self.root,db_path=self.db)
 def tearDown(self): self.temp.cleanup()
 def test_direct_and_paraphrased_queries_retrieve_provenance_and_guidance(self):
  for query in ('past rejection memory does not prove intentions',
                'old abandonment feelings are not established evidence about my friend'):
   found=memory.supervised_lessons(query,data_dir=self.root,db_path=self.db)
   self.assertTrue(found,query); self.assertEqual(found[0]['lesson_id'],LESSON_ID)
   self.assertEqual(found[0]['source_type'],'human_supervised')
   self.assertIn('not proof',found[0]['corrective_principle'])
 def test_unrelated_lesson_excluded(self):
  self.assertEqual(memory.supervised_lessons('aircraft accounting recipe',data_dir=self.root,db_path=self.db),[])
 def test_service_passes_lesson_as_context_and_failed_inference_is_non_mutating(self):
  with patch('brain_core.trainer.infer',side_effect=ModelOutputError('synthetic failure')):
   with self.assertRaises(ModelOutputError):
    service.analyze('A friend is quiet and an old rejection memory makes me afraid; what should I do?',
      data_dir=self.root,db_path=self.db,profile_path=self.root/'profile.json',state_path=self.root/'state.json',history_path=self.root/'history.json')
  lesson=lessons.list_lessons(data_dir=self.root,db_path=self.db)[0]
  self.assertEqual((lesson['lesson_id'],lesson['approval_status']),(LESSON_ID,'approved'))
  self.assertEqual(len(lessons.retrieve('old rejection fear intentions',data_dir=self.root,db_path=self.db)),1)
  self.assertFalse(list(self.root.glob('**/*pending*')))

if __name__=='__main__': unittest.main()
