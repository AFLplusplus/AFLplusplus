"""Offline tests for independent reasoning/research lanes and exact-query consent."""
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core.fallback_state import FallbackState
from brain_core.provider_selection import ProviderSelection, SelectionReason
from brain_core.providers import ProviderID
from brain_core.research_coordination import ResearchAuthorizationLedger, ResearchCoordinator


class ResearchCoordinationTests(unittest.TestCase):
    def setUp(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp_dir.cleanup)
        self._ledger_path = Path(self._temp_dir.name) / 'research-claims.sqlite3'

    def _ledger(self):
        return ResearchAuthorizationLedger(self._ledger_path)

    def _coordinator(self, reasoning, research, ledger=None):
        return ResearchCoordinator(reasoning_runner=reasoning, search_runner=research,
                                   authorization_ledger=ledger or self._ledger())

    def test_reasoning_and_research_both_succeed_and_preserve_evidence(self):
        evidence = ({'title': 'Synthetic source', 'url': 'https://example.test/',
                     'snippet': 'Evidence snippet', 'source': {'provider': 'brave'}},)
        reasoning = Mock(return_value=FallbackState.SUCCESS)
        research = Mock(return_value={'status': 'ok', 'results': list(evidence), 'error': None})
        result = self._coordinator(reasoning, research).run(
            query='exact synthetic query', research_authorized=True,
            journey_id='journey-success', authorization_id='approval-success', reasoning_authorized=True,
            reasoning_selection=ProviderSelection(ProviderID.LOCAL_OLLAMA,
                                                  SelectionReason.LOCAL_AVAILABLE))
        self.assertEqual(result.reasoning_status, FallbackState.SUCCESS)
        self.assertEqual(result.research_status, 'ok')
        self.assertEqual(result.evidence, evidence)
        self.assertIsNone(result.reasoning_diagnostic)
        self.assertIsNone(result.research_diagnostic)

    def test_reasoning_failure_does_not_prevent_authorized_research(self):
        reasoning = Mock(side_effect=RuntimeError('private model failure detail'))
        research = Mock(return_value={'status': 'ok', 'results': [{'title': 'Source'}], 'error': None})
        result = self._coordinator(reasoning, research).run(
            query='synthetic query', research_authorized=True, journey_id='journey-reason-fail',
            authorization_id='approval-reason-fail', reasoning_authorized=True)
        self.assertEqual(result.reasoning_status, FallbackState.FAILED)
        self.assertEqual(result.reasoning_diagnostic, 'reasoning_failed')
        self.assertEqual(result.research_status, 'ok')
        self.assertEqual(result.evidence[0]['title'], 'Source')

    def test_research_failure_does_not_prevent_reasoning(self):
        reasoning = Mock(return_value=FallbackState.SUCCESS)
        research = Mock(return_value={'status': 'timeout', 'results': [], 'error': 'timeout'})
        result = self._coordinator(reasoning, research).run(
            query='synthetic query', research_authorized=True, journey_id='journey-search-fail',
            authorization_id='approval-search-fail', reasoning_authorized=True)
        self.assertEqual(result.reasoning_status, FallbackState.SUCCESS)
        self.assertEqual(result.research_status, 'timeout')
        self.assertEqual(result.research_diagnostic, 'timeout')

    def test_missing_research_authorization_does_not_search_or_imply_permission(self):
        reasoning = Mock(return_value=FallbackState.SUCCESS)
        research = Mock(side_effect=AssertionError('search called without research authorization'))
        result = self._coordinator(reasoning, research).run(
            query='synthetic query', reasoning_authorized=True)
        self.assertEqual(result.reasoning_status, FallbackState.SUCCESS)
        self.assertEqual(result.research_status, 'awaiting_authorization')
        research.assert_not_called()

    def test_repeated_authorization_across_coordinators_does_not_repeat_search(self):
        ledger = self._ledger()
        reasoning, research = Mock(return_value=FallbackState.SUCCESS), Mock(
            return_value={'status': 'ok', 'results': [{'title': 'Source'}], 'error': None})
        first = self._coordinator(reasoning, research, ledger).run(
            query='Exact query', research_authorized=True, journey_id='journey-shared',
            authorization_id='auth-one', reasoning_authorized=True)
        second = self._coordinator(reasoning, research, ledger).run(
            query='Exact query', research_authorized=True, journey_id='journey-shared',
            authorization_id='auth-one', reasoning_authorized=True)
        self.assertEqual(research.call_count, 1)
        self.assertEqual(first.research_status, 'ok')
        self.assertEqual(first.evidence, ({'title': 'Source'},))
        self.assertEqual(second.research_status, 'duplicate')
        self.assertEqual(second.evidence, ())

    def test_simultaneous_claims_allow_only_one_execution(self):
        ledger = self._ledger()
        barrier = threading.Barrier(8)
        claims = []
        def claim():
            barrier.wait()
            claims.append(ledger.claim(journey_id='journey-concurrent', authorization_id='auth-concurrent',
                                       request_fingerprint='fingerprint-exact-query'))
        threads = [threading.Thread(target=claim) for _ in range(8)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(claims.count(True), 1)
        self.assertEqual(claims.count(False), 7)

    def test_fresh_authorization_id_permits_new_search(self):
        ledger = self._ledger()
        reasoning = Mock(return_value=FallbackState.SUCCESS)
        research = Mock(return_value={'status': 'ok', 'results': [{'title': 'Source'}], 'error': None})
        coordinator = self._coordinator(reasoning, research, ledger)
        first = coordinator.run(query='same exact query', research_authorized=True,
                                journey_id='journey-fresh', authorization_id='auth-1')
        second = self._coordinator(reasoning, research, ledger).run(
            query='same exact query', research_authorized=True,
            journey_id='journey-fresh', authorization_id='auth-2')
        self.assertEqual(research.call_count, 2)
        self.assertEqual(first.research_status, 'ok')
        self.assertEqual(second.research_status, 'ok')

    def test_authorization_id_cannot_be_reused_for_different_exact_request(self):
        ledger = self._ledger()
        reasoning, research = Mock(return_value=FallbackState.SUCCESS), Mock(
            return_value={'status': 'ok', 'results': [], 'error': None})
        coordinator = self._coordinator(reasoning, research, ledger)
        first = coordinator.run(query='first exact query', research_authorized=True,
                                journey_id='journey-bound', authorization_id='auth-bound')
        second = coordinator.run(query='different exact query', research_authorized=True,
                                 journey_id='journey-bound', authorization_id='auth-bound')
        self.assertEqual(research.call_count, 2)
        self.assertEqual(first.research_status, 'ok')
        self.assertEqual(second.research_status, 'ok')

    def test_repeated_exact_query_with_same_authorization_does_not_duplicate(self):
        ledger = self._ledger()
        reasoning = Mock(return_value=FallbackState.SUCCESS)
        source = {'title': 'Preserved result', 'url': 'https://example.test/', 'snippet': 'Text'}
        research = Mock(return_value={'status': 'ok', 'results': [source], 'error': None})
        coordinator = self._coordinator(reasoning, research, ledger)
        first = coordinator.run(query='Exact   query', research_authorized=True,
                                journey_id='journey-repeat', authorization_id='auth-repeat')
        second = coordinator.run(query=' exact query ', research_authorized=True,
                                 journey_id='journey-repeat', authorization_id='auth-repeat')
        self.assertEqual(research.call_count, 1)
        self.assertEqual(first.evidence, (source,))
        self.assertEqual(second.research_status, 'duplicate')

    def test_claim_remains_consumed_after_ledger_reopen(self):
        ledger = self._ledger()
        claim = dict(journey_id='journey-restart', authorization_id='auth-restart',
                     request_fingerprint='exact-request-fingerprint')
        self.assertTrue(ledger.claim(**claim))

        reopened_ledger = ResearchAuthorizationLedger(self._ledger_path)
        self.assertFalse(reopened_ledger.claim(**claim))

    def test_reasoning_lane_runs_without_research_consent(self):
        reasoning = Mock(return_value=FallbackState.SUCCESS)
        research = Mock()
        result = self._coordinator(reasoning, research).run(
            query='synthetic query', reasoning_authorized=True)
        self.assertEqual(result.reasoning_status, FallbackState.SUCCESS)
        self.assertEqual(result.research_status, 'awaiting_authorization')
        research.assert_not_called()


if __name__ == '__main__':
    unittest.main()
