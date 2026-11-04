"""Session-scoped state for separately authorized Conversation web research."""
from __future__ import annotations

from dataclasses import dataclass, field
import uuid


MAX_QUERY_CHARS = 180


@dataclass
class PendingResearch:
    journey_id: str
    query: str
    authorization_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: str = 'awaiting_approval'
    evidence: tuple = ()
    diagnostic: str | None = None


class ConversationResearchStore:
    """Retain one research preview/result per conversation across UI reruns."""
    def __init__(self):
        self._items = {}

    def prepare(self, conversation_id, query, *, journey_id=None):
        current = self._items.get(conversation_id)
        normalized = ' '.join(query.split())[:MAX_QUERY_CHARS] if isinstance(query, str) else ''
        if not normalized:
            return None, False
        if current is not None and current.query.casefold() == normalized.casefold():
            return current, False
        item = PendingResearch(journey_id or str(uuid.uuid4()), normalized)
        self._items[conversation_id] = item
        return item, True

    def get(self, conversation_id):
        return self._items.get(conversation_id)

    def remove(self, conversation_id):
        return self._items.pop(conversation_id, None)
