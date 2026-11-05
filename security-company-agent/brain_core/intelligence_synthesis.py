"""Deterministically synthesize an SB-23 comparison without external calls."""
from __future__ import annotations

from dataclasses import dataclass

from .intelligence_comparison import ClaimReference, IntelligenceComparison
from .intelligence_records import ValidationStatus


@dataclass(frozen=True)
class SupportingSource:
    """A claim and its traceable source metadata, with trust label."""

    claim: str
    source_id: str | None
    source_type: str
    citations: tuple[str, ...]
    provenance: tuple[tuple[str, object], ...]
    evidence_label: str


@dataclass(frozen=True)
class IntelligenceSynthesis:
    """One grounded, qualified response assembled solely from a comparison."""

    answer: str
    status: str
    supporting_sources: tuple[SupportingSource, ...]
    unresolved_differences: tuple[ClaimReference, ...]
    uncertainty: tuple[str, ...]


def _label(reference: ClaimReference) -> str:
    if reference.source_type == 'web_evidence':
        return 'unverified_web_evidence'
    return 'validated_model_content_not_factually_verified'


def synthesize_intelligence(comparison: IntelligenceComparison) -> IntelligenceSynthesis:
    """Build a response using only validated model content and labeled web evidence.

    No provider, search, or model calls are made. Exact shared claims are reported
    as repeated source assertions, never as established facts. All non-identical
    claims stay unresolved, and model-only assertions are not synthesized as an
    answer because agreement between models is not independent verification.
    """
    if not isinstance(comparison, IntelligenceComparison):
        raise TypeError('Expected an IntelligenceComparison.')

    uncertainty = set(comparison.uncertainty)
    references: list[ClaimReference] = []
    for group in comparison.shared_claims:
        references.extend(group)
    references.extend(comparison.unsupported_claims)
    # Deduplicate references while preserving identity-bearing source metadata.
    unique: dict[tuple[object, ...], ClaimReference] = {}
    for reference in references:
        key = (reference.source_type, reference.source_id, reference.claim,
               reference.citations, reference.provenance, reference.uncertainty)
        unique[key] = reference
    ordered = sorted(unique.values(), key=lambda item: (
        item.source_type, item.source_id or '', item.claim, item.citations, repr(item.provenance)))

    source_records = {record.source_id: record for record in comparison.valid_sources}
    supporting: list[SupportingSource] = []
    for reference in ordered:
        record = source_records.get(reference.source_id)
        if record is not None and record.source_type != reference.source_type:
            record = None
        if reference.source_type == 'inference':
            if record is None or record.validation_status is not ValidationStatus.VALID:
                continue
        elif reference.source_type == 'web_evidence':
            if record is None or record.validation_status is not ValidationStatus.UNVERIFIED:
                continue
            uncertainty.add('Web evidence is unverified and is presented only as a source-reported snippet or claim.')
        else:
            continue
        supporting.append(SupportingSource(
            claim=reference.claim,
            source_id=reference.source_id,
            source_type=reference.source_type,
            citations=reference.citations,
            provenance=reference.provenance,
            evidence_label=_label(reference),
        ))

    unresolved = tuple(sorted(comparison.unresolved_claims, key=lambda item: (
        item.source_type, item.source_id or '', item.claim, item.citations, repr(item.provenance))))
    if comparison.contradictions:
        uncertainty.add('Conflicting claims are unresolved; no conclusion was selected.')
    if unresolved:
        uncertainty.add('Differences remain unresolved; no semantic reconciliation was attempted.')

    if not comparison.valid_sources:
        answer = 'Unresolved: no valid sources are available.'
        status = 'unresolved'
    elif not supporting:
        answer = 'Unresolved: available sources do not support a grounded consolidated answer.'
        status = 'unresolved'
    elif all(item.source_type == 'web_evidence' for item in supporting):
        rendered = '; '.join(f"unverified source reports: {item.claim}" for item in supporting)
        answer = f'Qualified summary only — {rendered}. This is not established as fact.'
        status = 'qualified'
    else:
        # Use only literal claim text, explicitly framed as assertions. Avoid
        # joining apparently related but non-identical claims into a conclusion.
        rendered = '; '.join(f"{item.claim} [model assertion, not verified]"
                             if item.source_type == 'inference'
                             else f"unverified web source reports: {item.claim}"
                             for item in supporting)
        answer = f'Qualified summary of available source claims: {rendered}.'
        status = 'qualified'

    return IntelligenceSynthesis(
        answer=answer,
        status=status,
        supporting_sources=tuple(supporting),
        unresolved_differences=unresolved,
        uncertainty=tuple(sorted(uncertainty)),
    )
