"""Pure state transitions for safe local-to-OpenAI fallback orchestration."""
from dataclasses import dataclass
from enum import Enum

from .provider_selection import ProviderSelection, SelectionReason, select_provider
from .providers import ProviderID


class FallbackState(str, Enum):
    SUCCESS = 'SUCCESS'
    FAILED = 'FAILED'
    AWAITING_CLOUD_APPROVAL = 'AWAITING_CLOUD_APPROVAL'
    EXHAUSTED = 'EXHAUSTED'


@dataclass(frozen=True)
class FallbackTransition:
    state: FallbackState
    selected_provider: ProviderID | None
    next_provider: ProviderID | None
    attempted: tuple[ProviderID, ...]
    failure_category: str | None
    requires_cloud_approval: bool


def _sanitize_failure_category(category):
    """Accept only safe, bounded category tokens; never preserve exception text."""
    if not isinstance(category, str):
        return 'unknown'
    normalized = category.strip().casefold()
    allowed = {'resource_limit', 'invalid_or_unvalidated_output', 'timeout',
               'connection', 'authentication', 'provider_error', 'internal_error',
               'unknown'}
    return normalized if normalized in allowed else 'unknown'


def transition_fallback(*, selection=None, state=None, provider=None, outcome=None,
                         attempted=(), failure_category=None, cloud_approved=False):
    """Compute one fallback state only; never call inference or consume consent.

    A cloud candidate is represented as AWAITING_CLOUD_APPROVAL until the caller
    reports that existing exact-payload consent has already been granted. The
    function itself has no provider clients and cannot execute a request.
    """
    if selection is None:
        selection = select_provider()
    if not isinstance(selection, ProviderSelection):
        selection = ProviderSelection(None, SelectionReason.NO_CONFIGURED_PROVIDER)

    tried = []
    for item in attempted:
        try:
            candidate = item if isinstance(item, ProviderID) else ProviderID(item)
        except (ValueError, TypeError):
            continue
        if candidate not in tried:
            tried.append(candidate)

    if state is not None:
        try:
            previous = state if isinstance(state, FallbackState) else FallbackState(state)
        except (ValueError, TypeError):
            previous = None
        if previous == FallbackState.SUCCESS:
            return FallbackTransition(FallbackState.SUCCESS, provider, None, tuple(tried), None, False)
        if previous == FallbackState.EXHAUSTED:
            return FallbackTransition(FallbackState.EXHAUSTED, None, None, tuple(tried),
                                      _sanitize_failure_category(failure_category), False)

    if outcome is None:
        if selection.provider is None:
            return FallbackTransition(FallbackState.EXHAUSTED, None, None, tuple(tried),
                                      'unknown', False)
        if selection.provider == ProviderID.OPENAI_CLOUD:
            if selection.provider in tried:
                return FallbackTransition(FallbackState.EXHAUSTED, None, None, tuple(tried),
                                          'unknown', False)
            if cloud_approved:
                tried.append(ProviderID.OPENAI_CLOUD)
                return FallbackTransition(FallbackState.FAILED, ProviderID.OPENAI_CLOUD, None,
                                          tuple(tried), None, False)
            return FallbackTransition(FallbackState.AWAITING_CLOUD_APPROVAL, None,
                                      ProviderID.OPENAI_CLOUD, tuple(tried), None, True)
        if selection.provider in tried:
            return FallbackTransition(FallbackState.EXHAUSTED, None, None, tuple(tried),
                                      'unknown', False)
        return FallbackTransition(FallbackState.FAILED, selection.provider, None,
                                  tuple(tried), None, False)

    normalized_outcome = str(outcome).upper()
    if normalized_outcome == 'SUCCESS':
        current = provider or selection.provider
        if current is not None:
            try:
                current = current if isinstance(current, ProviderID) else ProviderID(current)
            except (ValueError, TypeError):
                current = None
        return FallbackTransition(FallbackState.SUCCESS, current, None, tuple(tried), None, False)

    if normalized_outcome != 'FAILED':
        return FallbackTransition(FallbackState.EXHAUSTED, None, None, tuple(tried),
                                  _sanitize_failure_category(failure_category), False)

    try:
        current = provider if isinstance(provider, ProviderID) else ProviderID(provider)
    except (ValueError, TypeError):
        current = selection.provider

    if current is not None and current not in tried:
        tried.append(current)
    safe_category = _sanitize_failure_category(failure_category)

    if current == ProviderID.OPENAI_CLOUD or ProviderID.OPENAI_CLOUD in tried:
        return FallbackTransition(FallbackState.EXHAUSTED, None, None, tuple(tried),
                                  safe_category, False)

    if current == ProviderID.LOCAL_OLLAMA and selection.provider != ProviderID.LOCAL_OLLAMA:
        return FallbackTransition(FallbackState.EXHAUSTED, None, None, tuple(tried),
                                  safe_category, False)

    # Reuse SB-04 policy after recording Local as unavailable; only configured
    # OpenAI can become the next candidate.
    next_selection = select_provider(
        local_readiness={'status': 'UNAVAILABLE', 'reason': 'unknown'},
        openai_readiness={'status': 'AVAILABLE' if selection.provider == ProviderID.OPENAI_CLOUD
                          else 'UNAVAILABLE', 'reason': 'unknown'})
    if (next_selection.provider != ProviderID.OPENAI_CLOUD
            or ProviderID.OPENAI_CLOUD in tried):
        return FallbackTransition(FallbackState.EXHAUSTED, None, None, tuple(tried),
                                  safe_category, False)

    return FallbackTransition(FallbackState.AWAITING_CLOUD_APPROVAL, None,
                              ProviderID.OPENAI_CLOUD, tuple(tried), safe_category, True)
