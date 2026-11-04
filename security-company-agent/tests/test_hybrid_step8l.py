"""Step 8L isolated provider, consent, grounding, and exact-request regressions."""
import copy, json, sys, unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from brain_core.cloud_consent import CloudApprovalManager, CloudApprovalRequired, CloudBudget, approximate_token_count
from brain_core.providers import AlibabaQwenProvider, InferenceRequest, sanitized_cloud_context
from brain_core import decision, personality
from brain_core.appraisal import NEUTRAL
from brain_core.model_api import ModelConfig, ModelOutputError, MemoryGuardError
from brain_core.reasoning_stages import progressive_reasoning

SCENARIO=('A close friend has suddenly become less communicative after a stressful week. '
'I feel anxious and assume they no longer value our friendship. How should I interpret this situation, '
'and what would be a thoughtful response? Use any relevant approved memories when reasoning, '
'but do not create or modify a training lesson.')
UNDER={'facts':['A close friend has become less communicative after a stressful week.','I feel anxious and assume they no longer value our friendship.'],
'emotions':[{'label':'fear','trigger':'I feel anxious about the friendship.'},{'label':'empathy','trigger':'A close friend has become less communicative after a stressful week.'}],
'assumptions':['It is unknown why communication has changed after the stressful week.','Less communication does not establish that the friend no longer values the friendship.']}
ALTS={'alternatives':[{'action':'I will send a gentle message asking whether they would like to talk when ready.','consequence':'A low-pressure invitation allows them to respond when they are ready.'},{'action':'I will give them some time and check in after the stressful week.','consequence':'Waiting briefly avoids demanding an immediate reply while their week has been stressful.'}]}
FINAL={'selected_action':ALTS['alternatives'][0]['action'],'rationale':'Their communication changed after a stressful week, but the reason remains unknown.','emotional_tradeoff':'My anxiety can make rejection feel certain, while a gentle invitation leaves room for other explanations.'}

class Step8LTests(unittest.TestCase):
    def test_exact_emotional_reproduction_stages_and_natural_response(self):
        cfg=ModelConfig('http://127.0.0.1:12345/v1','mock-qwen')
        with patch('brain_core.reasoning_stages.complete',side_effect=[(copy.deepcopy(UNDER),{'source':'mock'}),(copy.deepcopy(ALTS),{'source':'mock'}),(copy.deepcopy(FINAL),{'source':'mock'})]) as call:
            result=progressive_reasoning(SCENARIO,config=cfg,cognitive_context={'appraised_emotions_before_decision':dict(NEUTRAL),'supervised_lessons':[]},persistent_profile=copy.deepcopy(personality.DEFAULT))
        self.assertEqual(call.call_count,3)
        self.assertTrue(result['_validation']['schema_passed'])
        self.assertTrue(result['_validation']['cognitive_checks_passed'])
        response=result['conversational_response'].casefold()
        self.assertIn('you described feeling fear',response)
        self.assertNotIn('no longer values',response)
        self.assertIn('unknown',response)

    def test_emotional_label_reported_anxiety_supported_but_motive_not_fact(self):
        self.assertTrue(decision._emotion_grounding_support('fear',SCENARIO))
        self.assertEqual(decision._semantic_grounding_score(SCENARIO,'The friend is secretly rejecting the speaker.'),0)

    def test_schema_validation_stays_independent_from_cognitive_validation(self):
        malformed=copy.deepcopy(UNDER); malformed['unexpected']='field'
        with self.assertRaises(ValueError): decision.validate_emotional_understanding(malformed,SCENARIO)
        decision.validate_emotional_understanding(copy.deepcopy(UNDER),SCENARIO)

    def test_ram_and_schema_errors_are_distinct(self):
        from brain_core.providers import category_for_error
        self.assertEqual(category_for_error(MemoryGuardError('held')),'resource_limit')
        self.assertEqual(category_for_error(ModelOutputError('invalid')),'invalid_or_unvalidated_output')

    def test_no_cloud_request_before_approval_and_decline_sends_nothing(self):
        request=InferenceRequest(({'role':'user','content':'synthetic'},),'qwen-configured',32,5)
        provider=AlibabaQwenProvider(base_url='https://workspace.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1',model='qwen-configured',region='ap-southeast-1',api_key='test-only',allowed_hosts=('workspace.ap-southeast-1.maas.aliyuncs.com',))
        with patch('urllib.request.urlopen',side_effect=AssertionError('must not call before approval')) as net:
            with self.assertRaises(PermissionError): provider.infer(request)
            self.assertEqual(net.call_count,0)

    def test_cloud_authorization_does_not_expand_to_research_or_memory_mutation(self):
        manager=CloudApprovalManager(); payload={'messages':[{'role':'user','content':'synthetic'}]}
        approval=manager.prepare(provider='alibaba_qwen_cloud',model='qwen-plus',region='singapore',payload=payload,session_id='s',token_estimate=5); manager.register(approval)
        with self.assertRaises(CloudApprovalRequired): manager.consume(approval.approval_id,provider='internet_research',model='qwen-plus',region='singapore',payload=payload,session_id='s',user_approved=True)
        manager.consume(approval.approval_id,provider='alibaba_qwen_cloud',model='qwen-plus',region='singapore',payload=payload,session_id='s',user_approved=True,success=False)
        self.assertEqual(len(manager.events),1)

    def test_approval_once_exact_payload_and_rerun_idempotence(self):
        mgr=CloudApprovalManager(); payload={'messages':[{'role':'user','content':'synthetic'}]}
        approval=mgr.prepare(provider='alibaba_qwen_cloud',model='qwen',region='region',payload=payload,session_id='s',token_estimate=100,budget=CloudBudget()); mgr.register(approval)
        mgr.consume(approval.approval_id,provider='alibaba_qwen_cloud',model='qwen',region='region',payload=payload,session_id='s',user_approved=True,success=True)
        with self.assertRaises(CloudApprovalRequired): mgr.consume(approval.approval_id,provider='alibaba_qwen_cloud',model='qwen',region='region',payload=payload,session_id='s',user_approved=True)
        self.assertEqual(len(mgr.events),1)

    def test_changed_payload_provider_model_and_conversation_invalidate(self):
        for field, changed in [('payload',{'a':2}),('provider','openai'),('model','qwen-next'),('session_id','other')]:
            with self.subTest(field=field):
                mgr=CloudApprovalManager(); payload={'a':1}
                approval=mgr.prepare(provider='cloud',model='qwen',region='r',payload=payload,session_id='s',token_estimate=2); mgr.register(approval)
                args={'provider':'cloud','model':'qwen','region':'r','payload':payload,'session_id':'s','user_approved':True}
                if field in ('payload','session_id'):
                    args[field]=changed
                else:
                    args[field]=changed
                with self.assertRaises(CloudApprovalRequired): mgr.consume(approval.approval_id,**args)

    def test_decline_expiry_and_cancel_are_single_use(self):
        mgr=CloudApprovalManager(); payload={'a':1}
        declined=mgr.prepare(provider='cloud',model='qwen',region='r',payload=payload,session_id='s',token_estimate=2); mgr.register(declined)
        with self.assertRaises(CloudApprovalRequired): mgr.consume(declined.approval_id,provider='cloud',model='qwen',region='r',payload=payload,session_id='s',user_approved=False)
        with self.assertRaises(CloudApprovalRequired): mgr.consume(declined.approval_id,provider='cloud',model='qwen',region='r',payload=payload,session_id='s',user_approved=True)
        expired=mgr.prepare(provider='cloud',model='qwen',region='r',payload=payload,session_id='s',token_estimate=2); mgr.register(expired)
        with patch('brain_core.cloud_consent.time.time',return_value=expired.created_at+601):
            with self.assertRaises(CloudApprovalRequired): mgr.consume(expired.approval_id,provider='cloud',model='qwen',region='r',payload=payload,session_id='s',user_approved=True)

    def test_budget_guard_blocks_large_request_and_prompt_cost_is_estimate(self):
        mgr=CloudApprovalManager()
        with self.assertRaises(ValueError): mgr.prepare(provider='cloud',model='q',region='r',payload={},session_id='s',token_estimate=20,prompt_tokens=20,budget=CloudBudget(max_prompt_tokens=10))
        self.assertGreater(approximate_token_count('rough estimate'),0)

    def test_context_minimization_retains_lesson_provenance_not_archives(self):
        lesson={'lesson_id':'lesson-5','source_type':'human_supervised','corrective_principle':'Past feelings are not proof.'}
        envelope=sanitized_cloud_context(scenario=SCENARIO,identity_name='Sovereign Brain',identity_mission='Preserve identity',approved_lessons=[lesson],recent_turns=[{'role':'user','content':'unrelated archive','relevant':False}])
        serialized=json.dumps(envelope)
        self.assertIn('lesson-5',serialized); self.assertIn('human_supervised',serialized)
        self.assertNotIn('unrelated archive',serialized); self.assertIn(SCENARIO,envelope['scenario'])

    def test_regional_endpoint_mismatch_rejected(self):
        with self.assertRaises(ValueError): AlibabaQwenProvider(base_url='https://workspace.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1',model='q',region='cn-hangzhou',api_key='test',allowed_hosts=('workspace.cn-hangzhou.maas.aliyuncs.com',))

if __name__=='__main__': unittest.main()
