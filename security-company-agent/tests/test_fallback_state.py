"""Pure offline tests for Local-to-OpenAI fallback state transitions."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core.fallback_state import FallbackState, transition_fallback
from brain_core.provider_selection import SelectionReason, ProviderSelection
from brain_core.providers import ProviderID


class FallbackStateTests(unittest.TestCase):
    def test_failure_uses_supplied_fallback_selection_without_reselecting(self):
        selection = ProviderSelection(ProviderID.LOCAL_OLLAMA, SelectionReason.LOCAL_AVAILABLE)
        fallback = ProviderSelection(
            ProviderID.OPENAI_CLOUD, SelectionReason.LOCAL_UNAVAILABLE_OPENAI_CONFIGURED)
        with patch('brain_core.fallback_state.select_provider', side_effect=AssertionError(
                'must use supplied fallback selection')):
            result = transition_fallback(
                selection=selection, outcome='FAILED', provider=ProviderID.LOCAL_OLLAMA,
                attempted=(), fallback_selection=fallback)
        self.assertEqual(result.state, FallbackState.AWAITING_CLOUD_APPROVAL)
        self.assertEqual(result.attempted, (ProviderID.LOCAL_OLLAMA,))

    def test_success_is_terminal_and_does_not_retry(self):
        result = transition_fallback(
            selection=ProviderSelection(ProviderID.LOCAL_OLLAMA, SelectionReason.LOCAL_AVAILABLE),
            state=FallbackState.SUCCESS, provider=ProviderID.LOCAL_OLLAMA,
            attempted=(ProviderID.LOCAL_OLLAMA,))
        self.assertEqual(result.state, FallbackState.SUCCESS)
        self.assertIsNone(result.next_provider)
        self.assertEqual(result.attempted, (ProviderID.LOCAL_OLLAMA,))

    def test_local_failure_selects_openai_and_waits_for_consent(self):
        selection = ProviderSelection(ProviderID.LOCAL_OLLAMA, SelectionReason.LOCAL_AVAILABLE)
        with patch('brain_core.fallback_state.select_provider', return_value=ProviderSelection(
                None, SelectionReason.NO_CONFIGURED_PROVIDER)) as no_openai:
            unavailable = transition_fallback(selection=selection, outcome='FAILED',
                                              provider=ProviderID.LOCAL_OLLAMA,
                                              failure_category='connection',
                                              attempted=(ProviderID.LOCAL_OLLAMA,))
        self.assertEqual(unavailable.state, FallbackState.EXHAUSTED)
        self.assertIsNone(unavailable.next_provider)
        self.assertEqual(unavailable.attempted, (ProviderID.LOCAL_OLLAMA,))
        no_openai.assert_called_once()

        with patch('brain_core.fallback_state.select_provider', return_value=ProviderSelection(
                ProviderID.OPENAI_CLOUD, SelectionReason.LOCAL_UNAVAILABLE_OPENAI_CONFIGURED)) as select:
            result = transition_fallback(selection=selection, outcome='FAILED',
                                         provider=ProviderID.LOCAL_OLLAMA,
                                         failure_category='connection',
                                         attempted=(ProviderID.LOCAL_OLLAMA,))
        self.assertEqual(result.state, FallbackState.AWAITING_CLOUD_APPROVAL)
        self.assertEqual(result.next_provider, ProviderID.OPENAI_CLOUD)
        self.assertTrue(result.requires_cloud_approval)
        self.assertEqual(result.failure_category, 'connection')
        select.assert_called_once()

    def test_approval_pending_does_not_add_cloud_attempt_or_execute(self):
        selection = ProviderSelection(ProviderID.OPENAI_CLOUD,
                                      SelectionReason.LOCAL_UNAVAILABLE_OPENAI_CONFIGURED)
        with patch('brain_core.fallback_state.select_provider') as select:
            result = transition_fallback(selection=selection)
        self.assertEqual(result.state, FallbackState.AWAITING_CLOUD_APPROVAL)
        self.assertEqual(result.next_provider, ProviderID.OPENAI_CLOUD)
        self.assertEqual(result.attempted, ())
        self.assertTrue(result.requires_cloud_approval)
        select.assert_not_called()

    def test_openai_failure_exhausts_and_records_only_sanitized_category(self):
        selection = ProviderSelection(ProviderID.OPENAI_CLOUD,
                                      SelectionReason.LOCAL_UNAVAILABLE_OPENAI_CONFIGURED)
        result = transition_fallback(selection=selection, outcome='FAILED',
                                     provider=ProviderID.OPENAI_CLOUD,
                                     failure_category='Bearer secret-value')
        self.assertEqual(result.state, FallbackState.EXHAUSTED)
        self.assertIsNone(result.next_provider)
        self.assertEqual(result.failure_category, 'unknown')
        self.assertEqual(result.attempted, (ProviderID.OPENAI_CLOUD,))

    def test_repeated_failed_transition_is_exhausted_and_attempt_is_not_duplicated(self):
        selection = ProviderSelection(ProviderID.LOCAL_OLLAMA, SelectionReason.LOCAL_AVAILABLE)
        with patch('brain_core.fallback_state.select_provider', return_value=ProviderSelection(
                ProviderID.OPENAI_CLOUD, SelectionReason.LOCAL_UNAVAILABLE_OPENAI_CONFIGURED)):
            first = transition_fallback(selection=selection, outcome='FAILED',
                                        provider=ProviderID.LOCAL_OLLAMA,
                                        attempted=(ProviderID.LOCAL_OLLAMA,), failure_category='timeout')
        second = transition_fallback(selection=selection, outcome='FAILED',
                                     provider=ProviderID.LOCAL_OLLAMA,
                                     attempted=first.attempted + (ProviderID.OPENAI_CLOUD,),
                                     failure_category='timeout')
        self.assertEqual(second.state, FallbackState.EXHAUSTED)
        self.assertEqual(second.attempted.count(ProviderID.LOCAL_OLLAMA), 1)
        self.assertEqual(second.attempted.count(ProviderID.OPENAI_CLOUD), 1)

    def test_no_provider_exhausts_without_attempt(self):
        selection = ProviderSelection(None, SelectionReason.NO_CONFIGURED_PROVIDER)
        result = transition_fallback(selection=selection)
        self.assertEqual(result.state, FallbackState.EXHAUSTED)
        self.assertIsNone(result.selected_provider)
        self.assertEqual(result.attempted, ())

    def test_duplicate_local_attempt_does_not_select_openai_again(self):
        selection = ProviderSelection(ProviderID.LOCAL_OLLAMA, SelectionReason.LOCAL_AVAILABLE)
        result = transition_fallback(selection=selection, outcome='FAILED',
                                     provider=ProviderID.LOCAL_OLLAMA,
                                     attempted=(ProviderID.LOCAL_OLLAMA, ProviderID.OPENAI_CLOUD),
                                     failure_category='timeout')
        self.assertEqual(result.state, FallbackState.EXHAUSTED)
        self.assertIsNone(result.next_provider)
        self.assertEqual(result.attempted, (ProviderID.LOCAL_OLLAMA, ProviderID.OPENAI_CLOUD))


if __name__ == '__main__':
    unittest.main()
