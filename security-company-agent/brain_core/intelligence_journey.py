"""Backend Local-to-OpenAI reasoning journey without embedded cloud consent."""
from dataclasses import dataclass
from typing import Any

from .fallback_state import FallbackState, transition_fallback
from .provider_selection import ProviderSelection, SelectionReason, select_provider
from .providers import ProviderID


@dataclass(frozen=True)
class IntelligenceJourney:
    """Immutable journey state; the original request is retained verbatim."""
    request: Any
    selection: ProviderSelection
    state: FallbackState
    attempted: tuple[ProviderID, ...]
    current_provider: ProviderID | None
    diagnostic: str | None = None


class IntelligenceJourneyController:
    """Run Local once, then stop at existing OpenAI approval when needed.

    This controller never constructs cloud consent or invokes OpenAI. Its caller
    must use the existing exact-payload single-use authorization flow.
    """
    def __init__(self, *, local_runner, selector=select_provider):
        if not callable(local_runner) or not callable(selector):
            raise TypeError('local_runner and selector must be callable')
        self._local_runner = local_runner
        self._selector = selector

    @staticmethod
    def _safe_category(value):
        allowed = {'resource_limit', 'invalid_or_unvalidated_output', 'timeout',
                   'connection', 'authentication', 'provider_error', 'internal_error', 'unknown'}
        return value if isinstance(value, str) and value in allowed else 'unknown'

    def start(self, request, *, local_readiness=None, openai_readiness=None):
        selection = self._selector(local_readiness=local_readiness,
                                   openai_readiness=openai_readiness)
        if not isinstance(selection, ProviderSelection):
            selection = ProviderSelection(None, SelectionReason.NO_CONFIGURED_PROVIDER)
        initial = transition_fallback(selection=selection)
        if selection.provider != ProviderID.LOCAL_OLLAMA:
            return IntelligenceJourney(request, selection, initial.state,
                                       initial.attempted, initial.next_provider,
                                       initial.failure_category)

        # Keep the original request and record Local regardless of the result.
        attempted = (ProviderID.LOCAL_OLLAMA,)
        try:
            result = self._local_runner(request)
            status = getattr(result, 'status', None)
            if status is None and isinstance(result, dict):
                status = result.get('status')
            succeeded = status in ('success', 'SUCCESS', True)
            category = None
            if not succeeded:
                category = self._safe_category(
                    getattr(result, 'error_category', None) or
                    (result.get('error_category') if isinstance(result, dict) else None))
        except Exception:
            succeeded, category = False, 'provider_error'

        if succeeded:
            transition = transition_fallback(
                selection=selection, state=FallbackState.SUCCESS,
                provider=ProviderID.LOCAL_OLLAMA, attempted=attempted)
            return IntelligenceJourney(request, selection, transition.state,
                                       transition.attempted, None, None)

        # SB-05 owns recording the failed Local attempt from the prior history.
        fallback_selection = self._selector(
            local_readiness={'status': 'UNAVAILABLE', 'reason': 'unknown'},
            openai_readiness=openai_readiness)
        transition = transition_fallback(
            selection=selection, outcome='FAILED', provider=ProviderID.LOCAL_OLLAMA,
            attempted=(), failure_category=category,
            fallback_selection=fallback_selection)
        return IntelligenceJourney(request, selection, transition.state,
                                   transition.attempted, transition.next_provider,
                                   transition.failure_category)

    def report_openai_result(self, journey, *, success, failure_category=None):
        """Record a result only after the existing OpenAI approval/execution path."""
        if not isinstance(journey, IntelligenceJourney):
            raise TypeError('journey must be an IntelligenceJourney')
        if journey.state != FallbackState.AWAITING_CLOUD_APPROVAL:
            return journey
        if ProviderID.OPENAI_CLOUD in journey.attempted:
            return self._record_exhausted(journey, journey.attempted, 'unknown')

        attempted = journey.attempted + (ProviderID.OPENAI_CLOUD,)
        if success:
            transition = transition_fallback(
                selection=journey.selection, state=FallbackState.SUCCESS,
                provider=ProviderID.OPENAI_CLOUD, attempted=attempted)
            return IntelligenceJourney(journey.request, journey.selection, transition.state,
                                       transition.attempted, None, None)
        return self._record_exhausted(
            journey, attempted, self._safe_category(failure_category))

    @staticmethod
    def _record_exhausted(journey, attempted, category):
        transition = transition_fallback(
            selection=journey.selection, outcome='FAILED',
            provider=ProviderID.OPENAI_CLOUD, attempted=attempted,
            failure_category=category)
        return IntelligenceJourney(journey.request, journey.selection, transition.state,
                                   transition.attempted, None, transition.failure_category)
