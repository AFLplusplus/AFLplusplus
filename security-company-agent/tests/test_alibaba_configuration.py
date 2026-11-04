"""Network-free, secret-safe tests for Alibaba settings."""
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core.model_api import alibaba_configuration


class AlibabaConfigurationTests(unittest.TestCase):
    def read(self, **values):
        env = {
            'SOVEREIGN_ALIBABA_REGION': '',
            'SOVEREIGN_ALIBABA_WORKSPACE_ID': '',
            'SOVEREIGN_ALIBABA_MODEL': '',
            'SOVEREIGN_ALIBABA_BASE_URL': '',
            'DASHSCOPE_API_KEY': '',
        }
        env.update(values)
        with patch.dict(os.environ, env, clear=False):
            for name, value in env.items():
                if value == '':
                    os.environ.pop(name, None)
            return alibaba_configuration()

    def test_all_settings_missing_are_reported_without_crashing(self):
        config = self.read()
        self.assertFalse(config.configured)
        self.assertFalse(config.api_key_configured)
        self.assertEqual(config.endpoint, '')
        self.assertTrue(any('region' in error for error in config.errors))
        self.assertTrue(any('workspace' in error for error in config.errors))
        self.assertTrue(any('API key' in error for error in config.errors))

    def test_valid_settings_derive_endpoint_and_only_report_key_presence(self):
        secret = 'not-a-real-key-DO-NOT-PRINT'
        config = self.read(SOVEREIGN_ALIBABA_REGION='cn-beijing',
                           SOVEREIGN_ALIBABA_WORKSPACE_ID='workspace-123',
                           SOVEREIGN_ALIBABA_MODEL='qwen-plus', DASHSCOPE_API_KEY=secret)
        self.assertTrue(config.configured)
        self.assertTrue(config.api_key_configured)
        self.assertEqual(config.endpoint,
                         'https://workspace-123.cn-beijing.maas.aliyuncs.com/compatible-mode/v1')
        self.assertNotIn(secret, repr(config))
        self.assertNotIn(secret, str(config.errors))

    def test_missing_region_or_workspace_remains_incomplete(self):
        config = self.read(SOVEREIGN_ALIBABA_WORKSPACE_ID='workspace-123',
                           SOVEREIGN_ALIBABA_MODEL='qwen-plus', DASHSCOPE_API_KEY='key')
        self.assertFalse(config.configured)
        self.assertEqual(config.endpoint, '')
        self.assertTrue(any('region' in error for error in config.errors))

    def test_singapore_alias_uses_official_api_region_endpoint(self):
        config = self.read(SOVEREIGN_ALIBABA_REGION='singapore',
                           SOVEREIGN_ALIBABA_WORKSPACE_ID='workspace-123',
                           SOVEREIGN_ALIBABA_MODEL='qwen-plus', DASHSCOPE_API_KEY='key')
        self.assertTrue(config.configured)
        self.assertIn('workspace-123.ap-southeast-1.maas.aliyuncs.com', config.endpoint)

    def test_endpoint_must_match_configured_workspace_and_region(self):
        config = self.read(SOVEREIGN_ALIBABA_REGION='cn-beijing',
                           SOVEREIGN_ALIBABA_WORKSPACE_ID='workspace-123',
                           SOVEREIGN_ALIBABA_MODEL='qwen-plus', DASHSCOPE_API_KEY='key',
                           SOVEREIGN_ALIBABA_BASE_URL='https://attacker.example/compatible-mode/v1')
        self.assertFalse(config.configured)
        self.assertTrue(any('endpoint' in error for error in config.errors))

    def test_workspace_endpoint_sample_is_accepted_with_trailing_slash(self):
        endpoint = 'https://ws-example123.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1/'
        config = self.read(SOVEREIGN_ALIBABA_REGION='ap-southeast-1',
                           SOVEREIGN_ALIBABA_WORKSPACE_ID='ws-example123',
                           SOVEREIGN_ALIBABA_MODEL='qwen-plus', DASHSCOPE_API_KEY='synthetic',
                           SOVEREIGN_ALIBABA_BASE_URL=endpoint)
        self.assertTrue(config.configured, config.errors)
        self.assertEqual(config.endpoint, endpoint)

    def test_region_workspace_and_endpoint_cannot_be_relabelled(self):
        config = self.read(SOVEREIGN_ALIBABA_REGION='cn-beijing',
                           SOVEREIGN_ALIBABA_WORKSPACE_ID='ws-example123',
                           SOVEREIGN_ALIBABA_MODEL='qwen-plus', DASHSCOPE_API_KEY='synthetic',
                           SOVEREIGN_ALIBABA_BASE_URL='https://ws-example123.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1')
        self.assertFalse(config.configured)
        self.assertTrue(any('endpoint' in error for error in config.errors))

    def test_endpoint_rejects_credentials_and_unexpected_url_components(self):
        endpoints = (
            'https://user:password@ws-example123.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1',
            'https://ws-example123.ap-southeast-1.maas.aliyuncs.com:443/compatible-mode/v1',
            'https://ws-example123.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1?debug=1',
            'https://ws-example123.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1#fragment',
            'https://ws-example123.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v2',
        )
        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint):
                config = self.read(SOVEREIGN_ALIBABA_REGION='ap-southeast-1',
                                   SOVEREIGN_ALIBABA_WORKSPACE_ID='ws-example123',
                                   SOVEREIGN_ALIBABA_MODEL='qwen-plus', DASHSCOPE_API_KEY='synthetic',
                                   SOVEREIGN_ALIBABA_BASE_URL=endpoint)
                self.assertFalse(config.configured)

    def test_endpoint_hostname_comparison_is_case_normalized(self):
        endpoint = 'https://WS-EXAMPLE123.AP-SOUTHEAST-1.MAAS.ALIYUNCS.COM/compatible-mode/v1'
        config = self.read(SOVEREIGN_ALIBABA_REGION='ap-southeast-1',
                           SOVEREIGN_ALIBABA_WORKSPACE_ID='ws-example123',
                           SOVEREIGN_ALIBABA_MODEL='qwen-plus', DASHSCOPE_API_KEY='synthetic',
                           SOVEREIGN_ALIBABA_BASE_URL=endpoint)
        self.assertTrue(config.configured, config.errors)

    def test_endpoint_explicit_configuration_is_retained(self):
        endpoint = 'https://ws-example123.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1'
        config = self.read(SOVEREIGN_ALIBABA_REGION='ap-southeast-1',
                           SOVEREIGN_ALIBABA_WORKSPACE_ID='ws-example123',
                           SOVEREIGN_ALIBABA_MODEL='qwen-plus', DASHSCOPE_API_KEY='synthetic',
                           SOVEREIGN_ALIBABA_BASE_URL=endpoint)
        self.assertEqual(config.endpoint, endpoint)

    def test_module_import_and_config_read_make_no_network_calls(self):
        with patch('urllib.request.urlopen', side_effect=AssertionError('network forbidden')):
            config = self.read()
        self.assertEqual(config.provider, 'alibaba_qwen_cloud')


if __name__ == '__main__':
    unittest.main()
