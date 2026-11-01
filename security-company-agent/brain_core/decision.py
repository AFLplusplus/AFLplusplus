"""Structured recommendation contract shared by replaceable model providers."""
from .appraisal import EMOTIONS, validate_emotions

def object_schema(properties):
    return {'type': 'object', 'properties': properties,
            'required': list(properties), 'additionalProperties': False}

TEXT = {'type': 'string', 'minLength': 1, 'maxLength': 3000}
UNIT = {'type': 'number', 'minimum': 0, 'maximum': 1}
STRINGS = {'type': 'array', 'items': TEXT, 'minItems': 1, 'maxItems': 5}
SCHEMA = object_schema({
    'narrative': TEXT, 'emotion': TEXT, 'confidence': UNIT,
    'chemical_indexes': object_schema({k: {'type': 'number', 'minimum': 0, 'maximum': 100}
                                      for k in ('dopamine', 'cortisol', 'serotonin')}),
    'temperament': object_schema({k: UNIT for k in ('caution', 'assertiveness')}),
    'emotions': object_schema({k: UNIT for k in EMOTIONS}),
    'decision': object_schema({'conflicting_emotions': STRINGS, 'evidence': TEXT,
                               'uncertainty': TEXT, 'options': STRINGS,
                               'recommended_action': TEXT, 'rationale': TEXT}),
    'operational_rule': object_schema({k: TEXT for k in ('trigger', 'rule', 'recommended_action')})
})

def validate_decision(data):
    validate_emotions(data.get('emotions'))
    decision = data.get('decision')
    if not isinstance(decision, dict):
        raise ValueError('Model must return a structured decision.')
    for key in ('conflicting_emotions', 'options'):
        values = decision.get(key)
        if not isinstance(values, list) or not 1 <= len(values) <= 5 or any(
                not isinstance(item, str) or not item.strip() or len(item) > 3000 for item in values):
            raise ValueError(f'Invalid decision {key}.')
    for key in ('evidence', 'uncertainty', 'recommended_action', 'rationale'):
        if not isinstance(decision.get(key), str) or not decision[key].strip() or len(decision[key]) > 3000:
            raise ValueError(f'Invalid decision {key}.')
    return data
