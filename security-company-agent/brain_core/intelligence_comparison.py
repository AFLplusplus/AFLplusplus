"""Deterministic comparison of explicit claims across intelligence records.

Only exact normalized text is matched. Other cross-source comparisons remain
unresolved; no model output or web snippet is upgraded to verified truth.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable
import re

from .intelligence_records import IntelligenceRecord, ValidationStatus


@dataclass(frozen=True)
class ClaimReference:
    source_id: str | None
    source_type: str
    claim: str
    citations: tuple[str, ...]
    provenance: tuple[tuple[str, object], ...]
    uncertainty: str


@dataclass(frozen=True)
class IntelligenceComparison:
    """Immutable deterministic summary; comparison categories are not truth judgments."""

    valid_sources: tuple[IntelligenceRecord, ...]
    shared_claims: tuple[tuple[ClaimReference, ...], ...]
    contradictions: tuple[tuple[ClaimReference, ...], ...]
    unsupported_claims: tuple[ClaimReference, ...]
    unresolved_claims: tuple[ClaimReference, ...]
    uncertainty: tuple[str, ...]


def _content_map(record: IntelligenceRecord) -> dict[str, object]:
    content = record.content
    if isinstance(content, tuple) and all(
            isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], str)
            for item in content):
        return dict(content)
    return {}


def _claim_text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = ' '.join(value.split())
    return value or None


def _normalized(claim: str) -> str:
    return re.sub(r'\s+', ' ', claim).casefold()


def _record_claims(record: IntelligenceRecord) -> tuple[str, ...]:
    fields = _content_map(record)
    if record.source_type == 'web_evidence':
        candidates = (fields.get('claim'), fields.get('snippet'))
    else:
        candidates = tuple(item for key in ('claims', 'facts', 'assertions')
                           for item in (fields.get(key) if isinstance(fields.get(key), tuple) else ())) + (
                               fields.get('claim'), fields.get('answer'))
    seen: set[str] = set()
    claims = []
    for value in candidates:
        claim = _claim_text(value)
        if claim is None:
            continue
        normalized = _normalized(claim)
        if normalized not in seen:
            seen.add(normalized)
            claims.append(claim)
    return tuple(claims)


def compare_intelligence(records: Iterable[IntelligenceRecord] | None) -> IntelligenceComparison:
    """Compare explicitly represented claims; mark non-exact comparisons unresolved.

    Inference records must have valid structured output. Web evidence remains an
    unverified source and can be displayed, but is not sufficient to establish
    model agreement. Failed and invalid records are excluded from claim comparison.
    """
    eligible: list[IntelligenceRecord] = []
    uncertainty: set[str] = set()
    for record in records or ():
        if not isinstance(record, IntelligenceRecord):
            continue
        if record.validation_status in (ValidationStatus.FAILED, ValidationStatus.INVALID):
            uncertainty.add(record.uncertainty or 'A failed or invalid source was excluded.')
            continue
        if record.source_type == 'inference' and record.validation_status is not ValidationStatus.VALID:
            uncertainty.add(record.uncertainty or 'Inference source was not structurally valid.')
            continue
        eligible.append(record)
        if record.uncertainty:
            uncertainty.add(record.uncertainty)

    eligible.sort(key=lambda item: (item.source_type, item.source_id or '', repr(item.content),
                                    repr(item.citations), repr(item.provenance)))
    model_records = [item for item in eligible if item.source_type == 'inference']
    web_records = [item for item in eligible if item.source_type == 'web_evidence']
    # Model-only agreement is not corroboration. Exclude those claims from
    # shared/support categories and retain them as unresolved model assertions.
    compare_records = list(eligible)
    if model_records and not web_records:
        compare_records = [item for item in eligible if item.source_type != 'inference']
        uncertainty.add('Model-only claims do not provide independent factual verification.')

    groups: dict[str, list[ClaimReference]] = {}
    all_claims: list[ClaimReference] = []
    for record in compare_records:
        claims = _record_claims(record)
        if not claims:
            uncertainty.add(f"Source {record.source_id or '<unknown>'} contains no extractable explicit claim.")
            continue
        for claim in claims:
            reference = ClaimReference(record.source_id, record.source_type, claim,
                                       tuple(record.citations), tuple(record.provenance), record.uncertainty)
            all_claims.append(reference)
            groups.setdefault(_normalized(claim), []).append(reference)

    shared: list[tuple[ClaimReference, ...]] = []
    unsupported: list[ClaimReference] = []
    for group in groups.values():
        unique_source_ids = {(item.source_type, item.source_id) for item in group}
        ordered = tuple(sorted(group, key=lambda item: (item.source_type, item.source_id or '', item.claim)))
        if len(unique_source_ids) > 1:
            shared.append(ordered)
        else:
            unsupported.extend(ordered)

    shared.sort(key=lambda group: (_normalized(group[0].claim), tuple(
        (item.source_type, item.source_id or '') for item in group)))
    unsupported.sort(key=lambda item: (_normalized(item.claim), item.source_type, item.source_id or ''))
    all_claims.sort(key=lambda item: (_normalized(item.claim), item.source_type, item.source_id or ''))
    if shared:
        uncertainty.add('Exact claim repetition is not independent factual verification or proof of truth.')
    if all_claims:
        uncertainty.add('Non-identical claims remain unresolved; semantic agreement or contradiction was not inferred.')

    return IntelligenceComparison(
        valid_sources=tuple(eligible),
        shared_claims=tuple(shared),
        contradictions=(),
        unsupported_claims=tuple(unsupported),
        unresolved_claims=tuple(all_claims),
        uncertainty=tuple(sorted(uncertainty)),
    )
