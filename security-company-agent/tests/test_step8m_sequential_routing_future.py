"""Unimplemented sequential-routing acceptance tests, preserved for future development.

Run the provider expectations: python -m unittest discover -s tests -p test_provider_routing.py
Run the journey expectations: python -m unittest discover -s tests -p test_step8m_sequential_routing_future.py
"""
import unittest
import test_provider_routing
from test_studio_ui import StudioUITests


class SequentialRoutingProviderTests(unittest.TestCase):
    """Original provider-routing acceptance tests, isolated for future implementation."""
    def setUp(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        app = test_provider_routing.app
        self.health = (dict(app.PROVIDER_STATUS), dict(app.PROVIDER_FAILURE), set(app.PROVIDER_BLOCKED))
        app.PROVIDER_STATUS.update({key: 'UNTESTED' for key in app.PROVIDER_STATUS})
        app.PROVIDER_FAILURE.clear()
        app.PROVIDER_BLOCKED.clear()
        self.configs = [patch.object(app, name) for name in ('openai_configuration', 'alibaba_configuration')]
        self.openai, self.alibaba = [context.start() for context in self.configs]
        self.openai.return_value = SimpleNamespace(configured=True)
        self.alibaba.return_value = SimpleNamespace(configured=True)
        for context in self.configs:
            self.addCleanup(context.stop)
        self.addCleanup(self._restore_health)

    def _restore_health(self):
        app = test_provider_routing.app
        status, failure, blocked = self.health
        app.PROVIDER_STATUS.clear()
        app.PROVIDER_STATUS.update(status)
        app.PROVIDER_FAILURE.clear()
        app.PROVIDER_FAILURE.update(failure)
        app.PROVIDER_BLOCKED.clear()
        app.PROVIDER_BLOCKED.update(blocked)

    @unittest.skip('Known future-routing helper absent from production scope.')
    def test_priority_local_then_openai_then_alibaba(self):
        from brain_core.providers import ProviderID
        app = test_provider_routing.app
        journey = {'attempted': [ProviderID.LOCAL_OLLAMA.value],
                   'preferred_provider': ProviderID.LOCAL_OLLAMA.value}
        self.assertEqual(app._next_provider(journey), ProviderID.OPENAI_CLOUD.value)
        journey['attempted'].append(ProviderID.OPENAI_CLOUD.value)
        self.assertEqual(app._next_provider(journey), ProviderID.ALIBABA_QWEN_CLOUD.value)
        journey['attempted'].append(ProviderID.ALIBABA_QWEN_CLOUD.value)
        self.assertIsNone(app._next_provider(journey))

    @unittest.skip('Known future-routing helper absent from production scope.')
    def test_explicit_cloud_preference_precedes_other_cloud(self):
        from brain_core.providers import ProviderID
        journey = {'attempted': [], 'preferred_provider': ProviderID.ALIBABA_QWEN_CLOUD.value}
        self.assertEqual(test_provider_routing.app._next_provider(journey), ProviderID.ALIBABA_QWEN_CLOUD.value)

    @unittest.skip('Known future-routing helper absent from production scope.')
    def test_authentication_and_403_failures_block_provider(self):
        from brain_core.providers import ProviderID
        app = test_provider_routing.app
        app._mark_provider_result(ProviderID.OPENAI_CLOUD.value, category='PROVIDER_AUTHENTICATION_FAILED')
        self.assertEqual(app.PROVIDER_STATUS[ProviderID.OPENAI_CLOUD.value], 'AUTHENTICATION_BLOCKED')
        journey = {'attempted': [ProviderID.LOCAL_OLLAMA.value], 'preferred_provider': None}
        self.assertEqual(app._next_provider(journey), ProviderID.ALIBABA_QWEN_CLOUD.value)
        app._mark_provider_result(ProviderID.ALIBABA_QWEN_CLOUD.value, category='authentication')
        self.assertEqual(app.PROVIDER_STATUS[ProviderID.ALIBABA_QWEN_CLOUD.value], 'ACCESS_DENIED')
        self.assertIsNone(app._next_provider(journey))

    @unittest.skip('Known future-routing helper absent from production scope.')
    def test_alibaba_401_and_403_are_access_denied_and_skipped(self):
        from brain_core.providers import ProviderID
        app = test_provider_routing.app
        for response in ('HTTP 401 authentication failed', 'HTTP 403 forbidden'):
            category = app._failure_category(RuntimeError(response), provider=ProviderID.ALIBABA_QWEN_CLOUD.value)
            self.assertEqual(category, 'PROVIDER_ACCESS_DENIED')
            app._mark_provider_result(ProviderID.ALIBABA_QWEN_CLOUD.value, category=category)
            journey = {'attempted': [ProviderID.LOCAL_OLLAMA.value, ProviderID.OPENAI_CLOUD.value],
                       'preferred_provider': ProviderID.LOCAL_OLLAMA.value}
            self.assertIsNone(app._next_provider(journey))
            app._reset_provider_health(ProviderID.ALIBABA_QWEN_CLOUD.value)

    @unittest.skip('Known future-routing helper absent from production scope.')
    def test_explicit_revalidation_only_clears_local_block_record(self):
        from brain_core.providers import ProviderID
        app = test_provider_routing.app
        provider = ProviderID.ALIBABA_QWEN_CLOUD.value
        app._mark_provider_result(provider, category='PROVIDER_ACCESS_DENIED')
        app._reset_provider_health(provider)
        self.assertEqual(app.PROVIDER_STATUS[provider], 'UNTESTED')
        self.assertNotIn(provider, app.PROVIDER_BLOCKED)
        self.alibaba.assert_not_called()

    @unittest.skip('Known future-routing helper absent from production scope.')
    def test_failure_categories_do_not_include_sensitive_error_text(self):
        from brain_core.model_api import MemoryGuardError, ModelOutputError
        app = test_provider_routing.app
        self.assertEqual(app._failure_category(MemoryGuardError('low ram')), 'LOCAL_RAM_INSUFFICIENT')
        self.assertEqual(app._failure_category(ModelOutputError('bad format')), 'REASONING_VALIDATION_FAILED')
        self.assertEqual(app._failure_category(RuntimeError('HTTP 403 Forbidden')), 'PROVIDER_ACCESS_DENIED')
        self.assertEqual(app._failure_category(RuntimeError('HTTP 401 invalid API key')),
                         'PROVIDER_AUTHENTICATION_FAILED')

    def _restore_health(self):
        app = test_provider_routing.app
        app.PROVIDER_STATUS.clear()
        app.PROVIDER_STATUS.update(self.status)
        app.PROVIDER_FAILURE.clear()
        app.PROVIDER_FAILURE.update(self.failures)
        app.PROVIDER_BLOCKED.clear()
        app.PROVIDER_BLOCKED.update(self.blocked)


class SequentialRoutingUITests(StudioUITests):
    """The four original UI journey assertions, run only as future-feature tests."""
    test_local_failure_prepares_openai_preview_but_sends_nothing_until_approval = StudioUITests.test_local_failure_prepares_openai_preview_but_sends_nothing_until_approval
    test_local_openai_alibaba_journey_requires_separate_action_then_consent = StudioUITests.test_local_openai_alibaba_journey_requires_separate_action_then_consent
    test_cloud_decline_requires_explicit_continue_before_next_preview = StudioUITests.test_cloud_decline_requires_explicit_continue_before_next_preview
    test_blocked_alibaba_is_not_prepared_and_only_explicit_revalidation_unblocks = StudioUITests.test_blocked_alibaba_is_not_prepared_and_only_explicit_revalidation_unblocks


if __name__ == '__main__':
    unittest.main()
