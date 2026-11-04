"""Deterministic policy for deciding whether external research may help."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re


class KnowledgeGapClassification(str, Enum):
    NOT_NEEDED = 'NOT_NEEDED'
    OPTIONAL = 'OPTIONAL'
    RECOMMENDED = 'RECOMMENDED'


@dataclass(frozen=True)
class KnowledgeGapAssessment:
    classification: KnowledgeGapClassification
    reason: str


# Reasons are fixed, short, and never include user-supplied text.
_REASON = {
    KnowledgeGapClassification.NOT_NEEDED: 'Stable conversational request; external sources are unlikely to help.',
    KnowledgeGapClassification.OPTIONAL: 'Stable factual topic; sources could add useful detail.',
    KnowledgeGapClassification.RECOMMENDED: 'Fresh, requested, or uncertain facts may need external sources.',
}


_EXPLICIT_RESEARCH = re.compile(
    r"\b(?:research|look\s+up|search\s+(?:the\s+)?(?:web|internet|online)|"
    r"find\s+(?:sources|citations|references|evidence)|with\s+(?:sources|citations)|"
    r"cite\s+(?:your\s+)?sources|source\s+this|check\s+(?:online|the\s+web))\b", re.I)
_FRESHNESS = re.compile(
    r"\b(?:current(?:ly)?|currently|today|right\s+now|latest|recent(?:ly)?|"
    r"newest|up[- ]to[- ]date|as\s+of\s+(?:today|now|20\d{2})|this\s+(?:week|month|year))\b", re.I)
_LAW = re.compile(
    r"\b(?:law|laws|legal|legislation|statute|regulation|regulatory|court\s+case|"
    r"ruling|ordinance|compliance|policy)\b", re.I)
_UNCERTAINTY = re.compile(
    r"\b(?:not\s+sure|uncertain|unsure|might\s+be\s+wrong|verify|"
    r"fact[- ]check|is\s+(?:this|that)\s+(?:true|accurate|correct)|"
    r"what\s+(?:is|are)\s+the\s+(?:odds|statistics|rate|number)|"
    r"statistics|data|evidence|study|studies|source\s+of)\b", re.I)
_EMOTIONAL = re.compile(
    r"\b(?:i\s+feel|feeling|feels|hurt|grief|sad|anxious|anxiety|angry|"
    r"upset|lonely|relationship|break[- ]?up|heartbroken|overwhelmed|"
    r"comfort|support\s+me|listen\s+to\s+me)\b", re.I)
_GREETING = re.compile(
    r"^(?:hi|hello|hey|good\s+(?:morning|afternoon|evening)|thanks|thank\s+you|"
    r"how\s+are\s+you|who\s+are\s+you)[!.?,\s]*$", re.I)


def assess_knowledge_gap(question: str) -> KnowledgeGapAssessment:
    """Classify research value without network or model calls.

    The policy only inspects bounded text using deterministic phrase rules. An
    explicit request or inherently time-sensitive/legal topic is recommended;
    stable factual questions may benefit optionally; social/emotional requests
    do not trigger research unless the user explicitly asks for it.
    """
    if not isinstance(question, str):
        question = ''
    text = question[:4000].strip()
    if not text or _GREETING.fullmatch(text):
        classification = KnowledgeGapClassification.NOT_NEEDED
    elif _EXPLICIT_RESEARCH.search(text) or _FRESHNESS.search(text) or _LAW.search(text):
        classification = KnowledgeGapClassification.RECOMMENDED
    elif _EMOTIONAL.search(text):
        classification = KnowledgeGapClassification.NOT_NEEDED
    elif _UNCERTAINTY.search(text):
        classification = KnowledgeGapClassification.RECOMMENDED
    elif re.search(r"\b(?:what|when|where|who|which|how|define|explain|"
                   r"tell\s+me\s+about|compare|why)\b", text, re.I):
        classification = KnowledgeGapClassification.OPTIONAL
    else:
        classification = KnowledgeGapClassification.NOT_NEEDED
    return KnowledgeGapAssessment(classification, _REASON[classification])


def classify_knowledge_gap(question: str) -> KnowledgeGapAssessment:
    """Compatibility-friendly name for the knowledge-gap policy."""
    return assess_knowledge_gap(question)
