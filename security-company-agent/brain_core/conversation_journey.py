"""In-memory idempotency state for a Streamlit conversation reasoning turn."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class PendingTurn:
    text: str
    profile: dict[str, Any]
    approved_lessons: tuple[dict[str, Any], ...]
    model_config: Any = None
    local_state: str = 'pending'
    local_result: Any = None
    local_error: Exception | None = None
    journey: Any = None
    cloud_service: Any = None
    cloud_request: Any = None
    cloud_state: str = 'not_prepared'
    cloud_result_written: bool = False
    result_recorded: bool = False


class ConversationJourneyStore:
    """Keep a single non-duplicating pending turn per conversation."""
    def __init__(self):
        self._turns: dict[str, PendingTurn] = {}

    def begin(self, conversation_id, *, text, profile, approved_lessons, model_config=None):
        current = self._turns.get(conversation_id)
        # The UI saves the user message before entering this service. Reuse its
        # active journey rather than accidentally treating a rerun as new work.
        if current is not None and current.text == text:
            return current, False
        if current is not None and current.cloud_state in ('awaiting_approval', 'completed'):
            return current, False
        turn = PendingTurn(text, dict(profile), tuple(dict(item) for item in approved_lessons), model_config)
        self._turns[conversation_id] = turn
        return turn, True

    def get(self, conversation_id):
        return self._turns.get(conversation_id)

    def remove(self, conversation_id):
        return self._turns.pop(conversation_id, None)

    def __len__(self):
        return len(self._turns)
