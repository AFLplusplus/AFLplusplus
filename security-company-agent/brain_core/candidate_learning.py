"""Generate immutable, pending-review lesson candidates from SB-24 output.

This module is a pure transformation: it does not persist or approve lessons.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from .intelligence_synthesis import IntelligenceSynthesis


@dataclass(frozen=True)
class CandidateLesson:
    """A review-only reusable principle with traceable source metadata."""

    proposed_principle: str
    source_references: tuple[tuple[str, str | None, tuple[str, ...], tuple[tuple[str, object], ...]], ...]
    uncertainty: tuple[str, ...]
    provenance: tuple[tuple[tuple[str, object], ...], ...]
    review_status: str = 'pending_review'


_PRINCIPLE_PATTERNS = (
    re.compile(r'\b(?:always|never|should|must|prefer|avoid|ask|use|check|verify|wait|confirm|do not|don.t)\b', re.IGNORECASE),
    re.compile(r'\b(?:principle|rule|guideline|lesson)\s*:', re.IGNORECASE),
)
_EMOTIONAL_CLAIM = re.compile(
    r'\b(?:feels?|felt|feeling|wants?|wanted|intends?|intended|believes?|believed|'
    r'fears?|feared|loves?|hates?|angry|sad|anxious|afraid|motivated|emotion)\b',
    re.IGNORECASE,
)
_UNRESOLVED_TERMS = ('unresolved', 'conflict', 'contradict', 'insufficient', 'uncertain', 'disagree')


def _clean_claim(value: str) -> str:
    return ' '.join(value.split()).strip(' .;')


def _clear_principle(claim: str) -> bool:
    cleaned = _clean_claim(claim)
    if not cleaned or len(cleaned) < 18 or len(cleaned) > 500:
        return False
    if _EMOTIONAL_CLAIM.search(cleaned):
        return False
    if not any(pattern.search(cleaned) for pattern in _PRINCIPLE_PATTERNS):
        return False
    return bool(re.search(r'\b(?:when|if|before|after|because|rather than|instead of|to avoid|to ensure)\b',
                          cleaned, re.IGNORECASE) or re.search(r'\bto\s+\w+', cleaned, re.IGNORECASE))


def generate_candidate(synthesis: IntelligenceSynthesis) -> CandidateLesson | None:
    """Create a candidate only for an explicit, matching reusable model principle.

    Eligibility requires a qualified SB-24 synthesis, one repeated exact principle
    in validated model content and explicitly present in web evidence, and no
    unresolved model claim. Web-only evidence and model-only agreement cannot
    create candidates. Returned candidates are never persisted or approved.
    """
    if not isinstance(synthesis, IntelligenceSynthesis):
        raise TypeError('Expected an IntelligenceSynthesis.')
    if synthesis.status != 'qualified' or not synthesis.supporting_sources:
        return None
    if any(re.search(r'\bconflict\b', uncertainty.casefold())
           or re.search(r'\bdisagree\b', uncertainty.casefold())
           for uncertainty in synthesis.uncertainty):
        return None

    model_sources = [source for source in synthesis.supporting_sources
                     if source.source_type == 'inference'
                     and source.evidence_label == 'validated_model_content_not_factually_verified']
    web_sources = [source for source in synthesis.supporting_sources
                   if source.source_type == 'web_evidence'
                   and source.evidence_label == 'unverified_web_evidence']
    model_claims = {_clean_claim(source.claim).casefold() for source in model_sources}
    if len(model_claims) > 1:
        return None
    if synthesis.unresolved_differences:
        unresolved_model_claims = {reference.claim.casefold()
                                   for reference in synthesis.unresolved_differences
                                   if reference.source_type == 'inference'}
        if len(unresolved_model_claims) > 1:
            return None

    if not model_sources or not web_sources:
        return None

    candidates = {_clean_claim(source.claim) for source in model_sources}
    if len(candidates) != 1:
        return None
    principle, = candidates
    if not _clear_principle(principle):
        return None
    matching_web = [source for source in web_sources
                    if _clean_claim(source.claim).casefold() == principle.casefold()]
    if not matching_web:
        return None

    selected = sorted(model_sources + matching_web,
                      key=lambda source: (source.source_type, source.source_id or '', source.claim))
    references = tuple((source.source_type, source.source_id, tuple(source.citations),
                        tuple(source.provenance)) for source in selected)
    provenance = tuple(tuple(source.provenance) for source in selected)
    uncertainty = tuple(sorted(set(synthesis.uncertainty) | {
        'Candidate is derived from source assertions and requires human review; it is not approved memory.',
        'Model content is not factual verification; web evidence, if present, remains unverified.'
    }))
    return CandidateLesson(
        proposed_principle=principle,
        source_references=references,
        uncertainty=uncertainty,
        provenance=provenance,
        review_status='pending_review',
    )
