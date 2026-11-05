"""Immutable, provider-independent records for inference and external evidence.

Model output remains an assertion, not verified truth. Web evidence remains
untrusted unless independently validated by a separate process.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from .providers import InferenceResult, ProviderID
from .research_evidence import ResearchEvidence


class ValidationStatus(str, Enum):
    """Whether the source adapter established basic structural validity."""

    VALID = 'valid'
    INVALID = 'invalid'
    FAILED = 'failed'
    UNVERIFIED = 'unverified'


@dataclass(frozen=True)
class IntelligenceRecord:
    """A deterministic immutable source record; it does not assert truth."""

    source_type: str
    source_id: str | None
    content: Any
    validation_status: ValidationStatus
    citations: tuple[str, ...]
    uncertainty: str
    provenance: tuple[tuple[str, Any], ...]


def _freeze(value: Any) -> Any:
    """Recursively copy mutable containers into deterministic immutable values."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TypeError('Record mappings require string keys.')
        return tuple((key, _freeze(value[key])) for key in sorted(value))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    raise TypeError('Unsupported value in intelligence record.')


def _provenance(**fields: Any) -> tuple[tuple[str, Any], ...]:
    return tuple((key, _freeze(value)) for key, value in sorted(fields.items()) if value is not None)


def from_inference_result(result: InferenceResult) -> IntelligenceRecord:
    """Adapt an existing local/OpenAI/Qwen result without upgrading its trust."""
    if not isinstance(result, InferenceResult):
        raise TypeError('Expected an InferenceResult.')
    provider = result.provider.value if isinstance(result.provider, ProviderID) else str(result.provider)
    status = result.status if isinstance(result.status, str) else 'invalid'
    if status == 'failed':
        validation = ValidationStatus.FAILED
    elif status == 'success' and isinstance(result.structured, dict):
        validation = ValidationStatus.VALID
    elif status == 'success':
        validation = ValidationStatus.INVALID
    else:
        validation = ValidationStatus.INVALID
    content = result.structured if result.structured is not None else result.text
    uncertainty = (
        'Provider output is model-generated and is not independently verified; citations are not inferred.'
        if validation is not ValidationStatus.FAILED else
        'Inference failed; no model output is treated as trusted evidence.'
    )
    if result.status == 'success' and not isinstance(result.structured, dict):
        uncertainty = 'Provider reported success without structured output; content is invalid and untrusted.'
    return IntelligenceRecord(
        source_type='inference',
        source_id=result.request_id,
        content=_freeze(content),
        validation_status=validation,
        citations=(),
        uncertainty=uncertainty,
        provenance=_provenance(
            status=status, provider=provider, model=result.model, error_category=result.error_category,
            latency_seconds=result.latency_seconds, input_tokens=result.input_tokens,
            output_tokens=result.output_tokens, estimated_cost=result.estimated_cost,
            cost_is_estimate=result.cost_is_estimate,
            external_transmission=result.external_transmission),
    )


def from_web_evidence(evidence: ResearchEvidence) -> IntelligenceRecord:
    """Adapt validated SB-08 evidence while explicitly retaining its untrusted status."""
    if not isinstance(evidence, ResearchEvidence):
        raise TypeError('Expected a ResearchEvidence record.')
    citation = evidence.source_url
    return IntelligenceRecord(
        source_type='web_evidence',
        source_id=citation,
        content=_freeze({'claim': evidence.claim, 'snippet': evidence.snippet,
                         'title': evidence.title, 'source_url': evidence.source_url,
                         'retrieved_at': evidence.retrieved_at}),
        validation_status=ValidationStatus.UNVERIFIED,
        citations=(citation,) if citation else (),
        uncertainty=evidence.uncertainty,
        provenance=_provenance(
            source_url=evidence.source_url, title=evidence.title,
            retrieved_at=evidence.retrieved_at, confidence=evidence.confidence,
            content_trusted=evidence.content_trusted,
            validation='validated_search_record_unverified_content'),
    )
