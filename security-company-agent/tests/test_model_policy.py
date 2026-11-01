"""Model selection, resource boundaries and local configuration; no model loading."""
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from brain_core import model_api, model_policy, local_runtime, trainer
from brain_core.decision import SCHEMA

class PolicyTests(unittest.TestCase):
    def test_default_is_authorized_qwen06(self):
        self.assertEqual(model_api.ModelConfig().model,'qwen3:0.6b')
        with patch.dict(os.environ,{},clear=True):
            self.assertEqual(model_policy.selected_local_model(),'qwen3:0.6b')
            self.assertEqual(model_api.ModelConfig.from_env().model,'qwen3:0.6b')

    def test_model_identifiers_remain_configurable(self):
        with patch.dict(os.environ,{'BRAIN_LOCAL_MODEL':'qwen3:1.7b','BRAIN_MODEL':'approved-gateway-model'}):
            self.assertEqual(model_policy.selected_local_model(),'qwen3:1.7b')
            self.assertEqual(model_api.ModelConfig.from_env().model,'approved-gateway-model')

    def test_model_policies_are_distinct(self):
        small=model_policy.policy_for('qwen3:0.6b')
        large=model_policy.policy_for('qwen3:1.7b')
        self.assertEqual(small.minimum_available_gib,1.5)
        self.assertEqual(small.context_tokens,2048)
        self.assertEqual(small.output_tokens,768)
        self.assertEqual(small.parallel_requests,1)
        self.assertEqual(small.keep_alive_seconds,0)
        self.assertEqual(large.minimum_available_gib,2.5)
        self.assertEqual(model_policy.policy_for('unrecognized-model').minimum_available_gib,2.5)

    def test_below_15_gib_prevents_all_network_requests(self):
        with patch.object(model_api,'available_memory_gib',return_value=1.499), \
             patch.object(model_api,'opener_for') as opener:
            with self.assertRaisesRegex(model_api.MemoryGuardError,'1.5 GiB'):
                model_api.complete([],model_api.ModelConfig(),SCHEMA)
            opener.assert_not_called()

    def test_unavailable_ram_check_fails_closed(self):
        with patch.object(model_api,'available_memory_gib',return_value=None), \
             patch.object(model_api,'opener_for') as opener:
            with self.assertRaisesRegex(model_api.MemoryGuardError,'cannot be verified'):
                model_api.complete([],model_api.ModelConfig(),SCHEMA)
            opener.assert_not_called()

    def test_exact_threshold_permits_only_fake_request(self):
        fixture=trainer.infer('fixture','',{}, {},mock=True)
        response=json.dumps({'choices':[{'message':{'content':json.dumps(fixture)},'finish_reason':'stop'}]}).encode()
        with patch.object(model_api,'available_memory_gib',return_value=1.5), \
             patch.object(model_api,'opener_for') as opener:
            opener.return_value.open.return_value=io.BytesIO(response)
            result,_=model_api.complete([],model_api.ModelConfig(),SCHEMA)
            request=opener.return_value.open.call_args.args[0]
        body=json.loads(request.data)
        self.assertEqual(body['model'],'qwen3:0.6b')
        self.assertEqual(body['max_tokens'],768)
        self.assertEqual(body['reasoning_effort'],'none')
        self.assertEqual(body['stream'],False)
        self.assertEqual(result['emotion'],'curious')

    def test_17b_guard_is_not_lowered(self):
        with patch.object(model_api,'available_memory_gib',return_value=1.9), \
             patch.object(model_api,'opener_for') as opener:
            with self.assertRaisesRegex(model_api.MemoryGuardError,'2.5 GiB'):
                model_api.complete([],model_api.ModelConfig(model='qwen3:1.7b'),SCHEMA)
            opener.assert_not_called()

    def test_runtime_config_is_local_and_does_not_preload(self):
        with patch.dict(os.environ,{'BRAIN_LOCAL_MODEL':'qwen3:0.6b'}):
            env=local_runtime.runtime_environment()
        self.assertEqual(env['OLLAMA_HOST'],'127.0.0.1:11434')
        self.assertEqual(env['OLLAMA_CONTEXT_LENGTH'],'2048')
        self.assertEqual(env['OLLAMA_NUM_PARALLEL'],'1')
        self.assertEqual(env['OLLAMA_MAX_LOADED_MODELS'],'1')
        self.assertEqual(env['OLLAMA_KEEP_ALIVE'],'0')
        self.assertEqual(env['OLLAMA_NO_CLOUD'],'1')
        self.assertEqual(env['OLLAMA_DEBUG_LOG_REQUESTS'],'false')

if __name__=='__main__':
    unittest.main()
