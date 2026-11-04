"""Offline tests for backend Local-to-OpenAI journey state transitions."""
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core.fallback_state import FallbackState
from brain_core.intelligence_journey import IntelligenceJourneyController
from brain_core.provider_selection import ProviderSelection, SelectionReason
from brain_core.providers import ProviderID


class IntelligenceJourneyTests(unittest.TestCase):
    REQUEST = {'messages': ({'role': 'user', 'content': 'synthetic request'},),
               'request_id': 'request-original'}

    def _controller(self, selection, runner):
        def selector(*, local_readiness=None, openai_readiness=None):
            if local_readiness and local_readiness.get('status') == 'UNAVAILABLE':
                return ProviderSelection(ProviderID.OPENAI_CLOUD,
                    SelectionReason.LOCAL_UNAVAILABLE_OPENAI_CONFIGURED)
            return selection
        return IntelligenceJourneyController(local_runner=runner, selector=selector)

    def test_local_success_is_terminal_and_retains_original_request(self):
        local = Mock(return_value={'status': 'success'})
        selection = ProviderSelection(ProviderID.LOCAL_OLLAMA, SelectionReason.LOCAL_AVAILABLE)
        journey = self._controller(selection, local).start(self.REQUEST)
        self.assertEqual(journey.request, self.REQUEST)
        self.assertIs(journey.request, self.REQUEST)
        self.assertEqual(journey.state, FallbackState.SUCCESS)
        self.assertEqual(journey.attempted, (ProviderID.LOCAL_OLLAMA,))
        self.assertIsNone(journey.current_provider)
        local.assert_called_once_with(self.REQUEST)

    def test_local_failure_advances_internally_to_openai_approval(self):
        local = Mock(return_value={'status': 'failed', 'error_category': 'timeout',
                                   'error': 'secret raw provider failure'})
        selection = ProviderSelection(ProviderID.LOCAL_OLLAMA, SelectionReason.LOCAL_AVAILABLE)
        journey = self._controller(selection, local).start(self.REQUEST)
        self.assertEqual(journey.state, FallbackState.AWAITING_CLOUD_APPROVAL)
        self.assertEqual(journey.current_provider, ProviderID.OPENAI_CLOUD)
        self.assertEqual(journey.attempted, (ProviderID.LOCAL_OLLAMA,))
        self.assertEqual(journey.diagnostic, 'timeout')
        self.assertNotIn('secret', repr(journey))

    def test_openai_selection_waits_for_approval_without_execution(self):
        local = Mock(side_effect=AssertionError('local should not run'))
        selection = ProviderSelection(ProviderID.OPENAI_CLOUD,
                                      SelectionReason.LOCAL_UNAVAILABLE_OPENAI_CONFIGURED)
        journey = self._controller(selection, local).start(self.REQUEST)
        self.assertEqual(journey.request, self.REQUEST)
        self.assertEqual(journey.state, FallbackState.AWAITING_CLOUD_APPROVAL)
        self.assertEqual(journey.current_provider, ProviderID.OPENAI_CLOUD)
        self.assertEqual(journey.attempted, ())
        local.assert_not_called()

    def test_duplicate_openai_result_cannot_be_recorded_twice(self):
        local = Mock(return_value={'status': 'failed', 'error_category': 'connection'})
        selection = ProviderSelection(ProviderID.LOCAL_OLLAMA, SelectionReason.LOCAL_AVAILABLE)
        controller = self._controller(selection, local)
        pending = controller.start(self.REQUEST)
        completed = controller.report_openai_result(pending, success=True)
        repeated = controller.report_openai_result(completed, success=True)
        self.assertEqual(completed.state, FallbackState.SUCCESS)
        self.assertEqual(completed.attempted.count(ProviderID.OPENAI_CLOUD), 1)
        self.assertEqual(repeated, completed)

    def test_openai_failure_exhausts_without_exposing_raw_error(self):
        local = Mock(return_value={'status': 'failed', 'error_category': 'timeout'})
        selection = ProviderSelection(ProviderID.LOCAL_OLLAMA, SelectionReason.LOCAL_AVAILABLE)
        controller = self._controller(selection, local)
        pending = controller.start(self.REQUEST)
        exhausted = controller.report_openai_result(
            pending, success=False, failure_category='Bearer raw-secret')
        self.assertEqual(exhausted.state, FallbackState.EXHAUSTED)
        self.assertEqual(exhausted.attempted,
                         (ProviderID.LOCAL_OLLAMA, ProviderID.OPENAI_CLOUD))
        self.assertEqual(exhausted.diagnostic, 'unknown')
        self.assertNotIn('Bearer', repr(exhausted))
        self.assertEqual(controller.report_openai_result(exhausted, success=True), exhausted)


if __name__ == '__main__':
    unittest.main()
