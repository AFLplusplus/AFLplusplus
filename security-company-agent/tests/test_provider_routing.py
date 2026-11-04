"""Offline tests for request-journey provider selection and blocking."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import brain_studio as app
from brain_core.providers import ProviderID


@unittest.skip('Future sequential-routing feature; not part of Step 8M manual provider selection.')
class ProviderRoutingTests(unittest.TestCase):
    def setUp(self):
        self.health = (dict(app.PROVIDER_STATUS), dict(app.PROVIDER_FAILURE), set(app.PROVIDER_BLOCKED))
        app.PROVIDER_STATUS.update({key: 'UNTESTED' for key in app.PROVIDER_STATUS})
        app.PROVIDER_FAILURE.clear()
        app.PROVIDER_BLOCKED.clear()
        self.config = patch.object(app, 'openai_configuration')
        self.openai = self.config.start()
        self.addCleanup(self.config.stop)
        self.alibaba_config = patch.object(app, 'alibaba_configuration')
        self.alibaba = self.alibaba_config.start()
        self.addCleanup(self.alibaba_config.stop)
        from types import SimpleNamespace
        self.openai.return_value = SimpleNamespace(configured=True)
        self.alibaba.return_value = SimpleNamespace(configured=True)
        self.addCleanup(self.restore_health)

    def restore_health(self):
        status, failure, blocked = self.health
        app.PROVIDER_STATUS.clear()
        app.PROVIDER_STATUS.update(status)
        app.PROVIDER_FAILURE.clear()
        app.PROVIDER_FAILURE.update(failure)
        app.PROVIDER_BLOCKED.clear()
        app.PROVIDER_BLOCKED.update(blocked)

    def test_priority_local_then_openai_then_alibaba(self):
        journey = {'attempted': [ProviderID.LOCAL_OLLAMA.value],
                   'preferred_provider': ProviderID.LOCAL_OLLAMA.value}
        self.assertEqual(app._next_provider(journey), ProviderID.OPENAI_CLOUD.value)
        journey['attempted'].append(ProviderID.OPENAI_CLOUD.value)
        self.assertEqual(app._next_provider(journey), ProviderID.ALIBABA_QWEN_CLOUD.value)
        journey['attempted'].append(ProviderID.ALIBABA_QWEN_CLOUD.value)
        self.assertIsNone(app._next_provider(journey))

    def test_explicit_cloud_preference_precedes_other_cloud(self):
        journey = {'attempted': [], 'preferred_provider': ProviderID.ALIBABA_QWEN_CLOUD.value}
        self.assertEqual(app._next_provider(journey), ProviderID.ALIBABA_QWEN_CLOUD.value)

    def test_authentication_and_403_failures_block_provider(self):
        app._mark_provider_result(ProviderID.OPENAI_CLOUD.value,
                                  category='PROVIDER_AUTHENTICATION_FAILED')
        self.assertEqual(app.PROVIDER_STATUS[ProviderID.OPENAI_CLOUD.value], 'AUTHENTICATION_BLOCKED')
        journey = {'attempted': [ProviderID.LOCAL_OLLAMA.value], 'preferred_provider': None}
        self.assertEqual(app._next_provider(journey), ProviderID.ALIBABA_QWEN_CLOUD.value)
        app._mark_provider_result(ProviderID.ALIBABA_QWEN_CLOUD.value, category='authentication')
        self.assertEqual(app.PROVIDER_STATUS[ProviderID.ALIBABA_QWEN_CLOUD.value], 'ACCESS_DENIED')
        self.assertIsNone(app._next_provider(journey))

    def test_alibaba_401_and_403_are_access_denied_and_skipped(self):
        for response in ('HTTP 401 authentication failed', 'HTTP 403 forbidden'):
            category = app._failure_category(RuntimeError(response),
                                             provider=ProviderID.ALIBABA_QWEN_CLOUD.value)
            self.assertEqual(category, 'PROVIDER_ACCESS_DENIED')
            app._mark_provider_result(ProviderID.ALIBABA_QWEN_CLOUD.value, category=category)
            journey = {'attempted': [ProviderID.LOCAL_OLLAMA.value,
                                     ProviderID.OPENAI_CLOUD.value],
                       'preferred_provider': ProviderID.LOCAL_OLLAMA.value}
            self.assertIsNone(app._next_provider(journey))
            app._reset_provider_health(ProviderID.ALIBABA_QWEN_CLOUD.value)

    def test_explicit_revalidation_only_clears_local_block_record(self):
        provider = ProviderID.ALIBABA_QWEN_CLOUD.value
        app._mark_provider_result(provider, category='PROVIDER_ACCESS_DENIED')
        app._reset_provider_health(provider)
        self.assertEqual(app.PROVIDER_STATUS[provider], 'UNTESTED')
        self.assertNotIn(provider, app.PROVIDER_BLOCKED)
        self.alibaba.assert_not_called()

    def test_failure_categories_do_not_include_sensitive_error_text(self):
        from brain_core.model_api import MemoryGuardError, ModelOutputError
        self.assertEqual(app._failure_category(MemoryGuardError('low ram')),
                         'LOCAL_RAM_INSUFFICIENT')
        self.assertEqual(app._failure_category(ModelOutputError('bad format')),
                         'REASONING_VALIDATION_FAILED')
        self.assertEqual(app._failure_category(RuntimeError('HTTP 403 Forbidden')),
                         'PROVIDER_ACCESS_DENIED')
        self.assertEqual(app._failure_category(RuntimeError('HTTP 401 invalid API key')),
                         'PROVIDER_AUTHENTICATION_FAILED')


if __name__ == '__main__':
    unittest.main()
