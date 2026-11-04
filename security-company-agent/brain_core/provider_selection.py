"""Backend policy for selecting a configured inference provider without execution."""
from dataclasses import dataclass
from enum import Enum

from .providers import ProviderID


class SelectionReason(str, Enum):
    LOCAL_AVAILABLE = 'local_available'
    LOCAL_UNAVAILABLE_OPENAI_CONFIGURED = 'local_unavailable_openai_configured'
    NO_CONFIGURED_PROVIDER = 'no_configured_provider'


@dataclass(frozen=True)
class ProviderSelection:
    """A sanitized provider decision; it carries no credentials or execution grant."""
    provider: ProviderID | None
    reason: SelectionReason

    @property
    def selected_provider(self):
        return self.provider

    @property
    def status(self):
        return 'SELECTED' if self.provider is not None else 'NO_PROVIDER'


def select_provider(*, local_readiness=None, openai_readiness=None, alibaba_readiness=None):
    """Prefer a ready local provider, else configured OpenAI; Alibaba is deferred.

    Readiness arguments are injectable for offline tests. When omitted, the
    existing read-only readiness checks are used. Alibaba readiness is
    intentionally ignored until a later selection policy includes it.
    """
    if local_readiness is None:
        from .model_api import check_local_readiness
        local_readiness = check_local_readiness()
    if local_readiness.get('status') == 'AVAILABLE':
        return ProviderSelection(ProviderID.LOCAL_OLLAMA, SelectionReason.LOCAL_AVAILABLE)

    if openai_readiness is None:
        from .openai_provider import openai_readiness as check_openai_readiness
        openai_readiness = check_openai_readiness()
    if openai_readiness.get('status') == 'AVAILABLE':
        return ProviderSelection(ProviderID.OPENAI_CLOUD,
                                 SelectionReason.LOCAL_UNAVAILABLE_OPENAI_CONFIGURED)

    return ProviderSelection(None, SelectionReason.NO_CONFIGURED_PROVIDER)
