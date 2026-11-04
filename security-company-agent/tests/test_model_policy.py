"""Model selection, resource boundaries and local configuration; no model loading."""
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from brain_core import model_api, model_policy, local_runtime, trainer, personality, studio
from brain_core.decision import SCHEMA

class PolicyTests(unittest.TestCase):
    def test_explicit_lower_output_limit_is_respected_and_cannot_raise_policy(self):
        config = model_api.ModelConfig(max_output_tokens=400, context_tokens=4096,
                                       keep_alive_seconds=60)
        policy = model_policy.policy_for(config.model)
        self.assertEqual(min(policy.output_tokens, config.max_output_tokens), 400)
        self.assertEqual(min(policy.context_tokens, config.context_tokens), 2048)
        self.assertEqual(min(policy.keep_alive_seconds, config.keep_alive_seconds), 0)

    def test_default_is_authorized_qwen06(self):
        self.assertEqual(model_api.ModelConfig().model,'qwen3:0.6b')
        with patch.dict(os.environ,{},clear=True):
            self.assertEqual(model_policy.selected_local_model(),'qwen3:0.6b')
            self.assertEqual(model_api.ModelConfig.from_env().model,'qwen3:0.6b')

    def test_model_environment_runtime_limits_are_read(self):
        with patch.dict(os.environ, {'BRAIN_MAX_OUTPUT_TOKENS': '400', 'BRAIN_CONTEXT_TOKENS': '1024',
                                    'BRAIN_KEEP_ALIVE_SECONDS': '12'}):
            config = model_api.ModelConfig.from_env()
        self.assertEqual(config.max_output_tokens, 400)
        self.assertEqual(config.context_tokens, 1024)
        self.assertEqual(config.keep_alive_seconds, 0)

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
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture = trainer.infer('fixture', '', {}, {}, mock=True,
                                    state_path=root / 'state.json', history_path=root / 'history.json',
                                    data_dir=root, db_path=root / 'brain.sqlite3')
        response=json.dumps({'message': {'content': json.dumps(fixture)}, 'done': True,
                             'done_reason': 'stop'}).encode()
        local_config = model_api.ModelConfig()
        with patch.object(model_api,'available_memory_gib',return_value=1.5), \
             patch.object(model_api,'opener_for') as opener:
            opener.return_value.open.return_value=io.BytesIO(response)
            result,_=model_api.complete([],local_config,SCHEMA)
            request=opener.return_value.open.call_args.args[0]
        body=json.loads(request.data)
        self.assertEqual(request.full_url, 'http://127.0.0.1:11434/api/chat')
        self.assertEqual(body['model'],'qwen3:0.6b')
        self.assertIs(body['think'], False)
        self.assertEqual(body['options']['num_ctx'],2048)
        self.assertEqual(body['options']['num_predict'],768)
        self.assertEqual(body['keep_alive'],0)
        self.assertEqual(body['stream'],False)
        self.assertEqual(result['emotion'],'curious')

    def test_thinking_only_native_response_is_not_parsed_as_json(self):
        response = json.dumps({'message': {'content': '', 'thinking': 'internal thoughts'},
                               'done': True, 'done_reason': 'stop'}).encode()
        with patch.object(model_api, 'available_memory_gib', return_value=4), \
             patch.object(model_api, 'opener_for') as opener:
            opener.return_value.open.return_value = io.BytesIO(response)
            with self.assertRaisesRegex(model_api.ModelOutputError, 'reasoning without a structured answer'):
                model_api.complete([], model_api.ModelConfig(),
                                   {'type': 'object', 'properties': {'partial': {'type': 'string'}},
                                    'required': ['partial'], 'additionalProperties': False})

    def test_truncated_native_response_is_reported(self):
        response = json.dumps({'message': {'content': '{"partial":'},
                               'done': True, 'done_reason': 'length'}).encode()
        with patch.object(model_api, 'available_memory_gib', return_value=4), \
             patch.object(model_api, 'opener_for') as opener:
            opener.return_value.open.return_value = io.BytesIO(response)
            with self.assertRaisesRegex(model_api.ModelOutputError, 'reached its configured output limit'):
                model_api.complete([], model_api.ModelConfig(),
                                   {'type': 'object', 'properties': {'partial': {'type': 'string'}},
                                    'required': ['partial'], 'additionalProperties': False})

    def test_non_qwen_native_requests_do_not_receive_qwen_thinking_option(self):
        config = model_api.ModelConfig(model='controlled-test')
        response = json.dumps({'message': {'content': json.dumps({'ok': True})},
                               'done': True, 'done_reason': 'stop'}).encode()
        with patch.object(model_api, 'available_memory_gib', return_value=4), \
             patch.object(model_api, 'opener_for') as opener:
            opener.return_value.open.return_value = io.BytesIO(response)
            model_api.complete([], config, {'type': 'object', 'properties': {'ok': {'type': 'boolean'}},
                                             'required': ['ok'], 'additionalProperties': False})
            body = json.loads(opener.return_value.open.call_args.args[0].data)
        self.assertNotIn('think', body)

    def test_lower_output_cap_is_honored_and_policy_settings_cannot_be_raised(self):
        config = model_api.ModelConfig(max_output_tokens=400, context_tokens=4096,
                                       keep_alive_seconds=60)
        policy = model_policy.policy_for(config.model)
        self.assertEqual(min(policy.output_tokens, config.max_output_tokens or policy.output_tokens), 400)
        self.assertEqual(min(policy.context_tokens, config.context_tokens or policy.context_tokens), 2048)
        self.assertEqual(min(policy.keep_alive_seconds, config.keep_alive_seconds), 0)

    def test_17b_guard_is_not_lowered(self):
        with patch.object(model_api,'available_memory_gib',return_value=1.9), \
             patch.object(model_api,'opener_for') as opener:
            with self.assertRaisesRegex(model_api.MemoryGuardError,'2.5 GiB'):
                model_api.complete([],model_api.ModelConfig(model='qwen3:1.7b'),SCHEMA)
            opener.assert_not_called()

    def test_native_server_info_is_read_only_and_marks_parallel_setting_unknown(self):
        class Response:
            def __init__(self, value): self.value = value
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self): return json.dumps(self.value).encode()
        with patch.object(model_api, 'opener_for') as factory:
            factory.return_value.open.side_effect = [Response({'version': 'test'}),
                                                       Response({'models': [{'name': 'qwen3:0.6b'}]})]
            info = model_api.ollama_server_info()
        self.assertEqual(info['version'], 'test')
        self.assertEqual(info['loaded_models'][0]['name'], 'qwen3:0.6b')
        self.assertEqual(info['parallel_setting'], 'unknown')
        self.assertEqual(factory.return_value.open.call_count, 2)

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
