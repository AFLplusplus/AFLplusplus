"""Offline policy tests for backend-only provider selection."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core.provider_selection import ProviderSelection, SelectionReason, select_provider
from brain_core.providers import ProviderID


class ProviderSelectionTests(unittest.TestCase):
    def test_local_ready_selects_local_without_checking_clouds(self):
        with patch('brain_core.model_api.check_local_readiness') as local, \
                patch('brain_core.openai_provider.openai_readiness') as openai:
            result = select_provider(local_readiness={'status': 'AVAILABLE', 'reason': None})
            self.assertEqual(result, ProviderSelection(ProviderID.LOCAL_OLLAMA,
                                                       SelectionReason.LOCAL_AVAILABLE))
            local.assert_not_called()
            openai.assert_not_called()

    def test_local_unavailable_selects_configured_openai(self):
        result = select_provider(local_readiness={'status': 'UNAVAILABLE', 'reason': 'service_offline'},
                                 openai_readiness={'status': 'AVAILABLE', 'reason': None})
        self.assertEqual(result.provider, ProviderID.OPENAI_CLOUD)
        self.assertEqual(result.status, 'SELECTED')
        self.assertEqual(result.reason, SelectionReason.LOCAL_UNAVAILABLE_OPENAI_CONFIGURED)

    def test_neither_ready_returns_no_provider(self):
        result = select_provider(local_readiness={'status': 'UNAVAILABLE', 'reason': 'model_missing'},
                                 openai_readiness={'status': 'UNAVAILABLE', 'reason': 'missing_key'})
        self.assertIsNone(result.provider)
        self.assertEqual(result.status, 'NO_PROVIDER')
        self.assertEqual(result.reason, SelectionReason.NO_CONFIGURED_PROVIDER)

    def test_alibaba_readiness_is_deferred_and_never_selected(self):
        result = select_provider(local_readiness={'status': 'UNAVAILABLE', 'reason': 'unknown'},
                                 openai_readiness={'status': 'UNAVAILABLE', 'reason': 'missing_model'},
                                 alibaba_readiness={'status': 'AVAILABLE', 'reason': None})
        self.assertIsNone(result.provider)
        self.assertEqual(result.status, 'NO_PROVIDER')
        self.assertNotEqual(result.provider, ProviderID.ALIBABA_QWEN_CLOUD)

    def test_result_reason_is_sanitized_enum_not_readiness_detail(self):
        result = select_provider(local_readiness={'status': 'UNAVAILABLE', 'reason': 'sensitive local detail'},
                                 openai_readiness={'status': 'UNAVAILABLE', 'reason': 'key value leak'})
        self.assertIsInstance(result, ProviderSelection)
        self.assertIsInstance(result.reason, SelectionReason)
        self.assertNotIn('sensitive', result.reason.value)
        self.assertNotIn('leak', result.reason.value)


if __name__ == '__main__':
    unittest.main()
