"""Offline unit tests for local OpenAI configuration readiness."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core.openai_provider import OpenAIConfiguration, openai_readiness


class OpenAIReadinessTests(unittest.TestCase):
    def test_ready_configuration_is_available_not_verified_connectivity(self):
        config = OpenAIConfiguration('gpt-test', True, (), api_key='synthetic-test-key')
        with patch('brain_core.openai_provider.urllib.request.urlopen', side_effect=AssertionError('network used')):
            self.assertEqual(openai_readiness(config), {'status': 'AVAILABLE', 'reason': None})

    def test_missing_key(self):
        config = OpenAIConfiguration('', False, ('OpenAI API key is not configured.',
                                                  'OpenAI model is not configured.'))
        self.assertEqual(openai_readiness(config), {'status': 'UNAVAILABLE', 'reason': 'missing_key'})

    def test_missing_model(self):
        config = OpenAIConfiguration('', True,
                                     ('OpenAI model is not configured; set SOVEREIGN_OPENAI_MODEL.',),
                                     api_key='synthetic-test-key')
        self.assertEqual(openai_readiness(config), {'status': 'UNAVAILABLE', 'reason': 'missing_model'})

    def test_invalid_configuration(self):
        config = OpenAIConfiguration('gpt-test', True,
                                     ('OpenAI endpoint configuration is invalid.',),
                                     endpoint='http://untrusted.invalid/v1/responses',
                                     api_key='synthetic-test-key')
        self.assertEqual(openai_readiness(config),
                         {'status': 'UNAVAILABLE', 'reason': 'invalid_configuration'})

    def test_malformed_existing_configuration_is_invalid_not_live_access(self):
        with patch('brain_core.openai_provider.openai_configuration', side_effect=ValueError('invalid settings')):
            self.assertEqual(openai_readiness(),
                             {'status': 'UNAVAILABLE', 'reason': 'invalid_configuration'})

    def test_environment_configuration_is_used_without_network_verification(self):
        with patch('brain_core.openai_provider.openai_configuration', return_value=OpenAIConfiguration(
                'gpt-test', True, (), api_key='synthetic-test-key')) as config:
            self.assertEqual(openai_readiness(), {'status': 'AVAILABLE', 'reason': None})
            config.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
