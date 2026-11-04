"""Provider-neutral structured reasoning contract and safe validation summary."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

CONTRACT_VERSION = 'sovereign-reasoning.v1'


@dataclass(frozen=True)
class ReasoningContract:
    """Normalized view of existing Understand → Evaluate → Decide stages.

    It deliberately carries lesson provenance as guidance and not as scenario evidence.
    Validation status reflects validator outcomes, not a claim of objective correctness.
    """
    version: str
    scenario_facts: tuple[str, ...]
    user_reported_emotions: tuple[dict[str, str], ...]
    uncertainties: tuple[str, ...]
    approved_lessons: tuple[dict[str, Any], ...]
    alternative_interpretations: tuple[str, ...]
    potential_actions: tuple[dict[str, str], ...]
    recommended_response: str
    consequences: tuple[str, ...]
    validation_status: dict[str, Any]
    failure_reasons: tuple[str, ...] = field(default_factory=tuple)


def from_validated_result(result: dict[str, Any]) -> ReasoningContract:
    stages = result.get('_stage_outputs') or {}
    understand = stages.get('understanding') or {}
    evaluate = stages.get('alternatives') or {}
    decide = stages.get('final_decision') or {}
    lessons = result.get('_provenance', {}).get('approved_lessons', ())
    actions = evaluate.get('alternatives', ())
    assumptions = tuple(understand.get('assumptions', ()))
    return ReasoningContract(
        version=CONTRACT_VERSION,
        scenario_facts=tuple(understand.get('facts', ())),
        user_reported_emotions=tuple(dict(item) for item in understand.get('emotions', ())),
        uncertainties=assumptions,
        approved_lessons=tuple(dict(item) for item in lessons if isinstance(item, dict)),
        potential_actions=tuple(dict(item) for item in actions if isinstance(item, dict)),
        recommended_response=str(decide.get('selected_action', '')),
        consequences=tuple(str(item.get('consequence', '')) for item in actions if isinstance(item, dict)),
        validation_status=dict(result.get('_validation', {})),
        alternative_interpretations=tuple(
            value for value in assumptions
            if any(marker in value.casefold() for marker in ('unknown', 'may ', 'could ', 'does not establish', 'not establish'))),
        failure_reasons=(),
    )


def failure_contract(*, reason: str, stage: str | None = None, category: str | None = None) -> dict[str, Any]:
    """Safe, compact failure envelope; excludes model output, prompt and scenario text."""
    def safe(value):
        return ''.join(char for char in str(value)[:120] if char.isalnum() or char in ' _-').strip()
    return {'version': CONTRACT_VERSION, 'validation_status': {'passed': False},
            'failure_reasons': tuple(item for item in (safe(category), safe(stage), safe(reason)) if item)}
