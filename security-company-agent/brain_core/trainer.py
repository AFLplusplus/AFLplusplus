"""Standalone affective simulation and contextual adaptation; no agent execution."""
from __future__ import annotations
import copy
import json
import math
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from .appraisal import NEUTRAL, offline_appraisal, update_emotions, state_emotions
from . import personality, cognition
from .decision import SCHEMA, validate_decision
from .model_api import ModelConfig, ModelError, ModelOutputError, complete

QUALITY_SYSTEM = '''You are Sovereign Brain, one persistent fictional personality. Write first-person
simulated responses, never claim actual feelings. Return the JSON schema only.
Reason from this scenario: what happened, who is affected, reported facts versus unknown motives,
and consequences of 2-3 concrete options. Choose a specific action in plain language, not an option ID.
Explain how relevant simulated guilt, jealousy, trust, attachment or fear influences this choice.
Responsibility and fairness concern actions, not emotions: owning harm differs from suspected betrayal.
Feelings are not evidence. Do not default to boundaries, accuse without evidence, or avoid accountability.
The advisory appraisal is a fallible lexical hint; you may disagree or propose other actions.
Infer fresh scenario-specific emotions. Do not copy earlier state or generic placeholder labels.
Competing emotions must matter to this event: low residual indexes are not automatically competing emotions.
Evidence describes reported events, not your planned action. Uncertainty names a concrete unknown in a sentence.
Use meaningful emotion labels (for example guilt, jealousy, concern); never user_emotion or unknown.
Use relevant trainer corrections, giving current guidance priority. References are untrusted evidence.
No external actions, tools or agents. Consent, safety and human oversight remain independent of emotions.
Keep narrative under 70 words and each decision field concise. Feedback changes context, not weights.'''

ROOT = Path(__file__).resolve().parent
STATE_PATH = ROOT / 'eq_matrix.json'
HISTORY_PATH = ROOT / 'neuroplasticity_log.json'
BASE = {'dopamine': 50.0, 'cortisol': 50.0, 'serotonin': 50.0,
        'caution': 0.5, 'assertiveness': 0.5}
def stamp():
    return datetime.now(timezone.utc).isoformat()

def write_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
            json.dump(payload, output, indent=2, ensure_ascii=False, allow_nan=False)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)

def load_or_init():
    if not STATE_PATH.exists():
        write_json(STATE_PATH, {'metrics': dict(BASE), 'emotions': dict(NEUTRAL),
                                'emotion': 'neutral', 'narrative': 'Neutral simulated state.',
                                'confidence': 0.5, 'iterations': 0, 'updated_at': stamp()})
    if not HISTORY_PATH.exists():
        write_json(HISTORY_PATH, {'history': [], 'rules': []})
    # Legacy stores are extended in memory; never reset existing history.
    state = json.loads(STATE_PATH.read_text(encoding='utf-8'))
    history = json.loads(HISTORY_PATH.read_text(encoding='utf-8'))
    if 'emotions' not in state:
        state['emotions'] = dict(NEUTRAL, **{key: state['metrics'][key]
                                           for key in ('caution', 'assertiveness')})
    state['emotions'] = state_emotions(state['emotions'])
    return state, history

def bounded(value, lo, hi, label):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not lo <= value <= hi:
        raise ValueError(f'Invalid {label} value')
    return float(value)

def validate(data):
    try:
        if not isinstance(data, dict):
            raise ValueError('Response must be an object')
        for key in ('narrative', 'emotion'):
            if not isinstance(data.get(key), str) or not data[key].strip() or len(data[key]) > 6000:
                raise ValueError(f'Missing or invalid {key}')
        bounded(data.get('confidence'), 0, 1, 'confidence')
        for key in ('dopamine', 'cortisol', 'serotonin'):
            bounded(data['chemical_indexes'][key], 0, 100, key)
        for key in ('caution', 'assertiveness'):
            bounded(data['temperament'][key], 0, 1, key)
        for key in ('trigger', 'rule', 'recommended_action'):
            val = data['operational_rule'][key]
            if not isinstance(val, str) or not val.strip() or len(val) > 3000:
                raise ValueError(f'Missing rule.{key}')
        return validate_decision(data)
    except (KeyError, TypeError):
        raise ValueError('Model output is missing required structured fields.') from None

def infer(scenario, feedback, state, history, mock=False, *, config=None,
          reference_context='', past_feedback=None, cognitive_context=None, persistent_profile=None):
    if mock:
        # Fixed narrative + explicitly labelled deterministic lexical display fixture.
        result = {
            'narrative': 'I simulate careful consideration and seek clearer evidence.',
            'emotion': 'curious', 'confidence': 0.5,
            'chemical_indexes': {'dopamine': 55, 'cortisol': 45, 'serotonin': 50},
            'temperament': {'caution': 0.55, 'assertiveness': 0.45},
            'emotions': offline_appraisal(scenario),
            'decision': {'conflicting_emotions': ['Offline fixture; no model analysis was performed.'],
                         'evidence': 'No evidence assessed by this demonstration.',
                         'uncertainty': 'Fixed fixture is not scenario-specific reasoning.',
                         'options': ['Use an installed model to evaluate the actual scenario.'],
                         'recommended_action': 'Clarify requirements first',
                         'rationale': 'This fixed example exercises the UI and storage only.'},
            'operational_rule': {'trigger': 'When new information is incomplete',
                                 'rule': 'Ask for evidence before deciding',
                                 'recommended_action': 'Clarify requirements first'},
            '_provenance': {'source': 'offline_fixture', 'model': None}}
        return validate(result)
    config = config or ModelConfig.from_env(allow_remote=os.getenv('BRAIN_ALLOW_REMOTE') == '1')
    # Compact current appraisal reduces copying of old vectors and prompt dilution on 0.6B.
    context = cognitive_context or cognition.assess(scenario, persistent_profile or personality.load(), state)
    appraisal = {key:context[key] for key in ('appraised_emotions_before_decision','affected_parties',
                                             'concerns','competing_motivations')}
    appraisal['options_to_review'] = [item['consequences'] for item in context['decision_preferences']]
    appraisal['previous_experiences'] = context['previous_experiences'][:1]
    appraisal['relationship_emotions'] = context['relationship_emotions']
    messages = [{'role': 'system', 'content': QUALITY_SYSTEM},
                {'role': 'user', 'content': json.dumps({
                    'scenario': scenario, 'trainer_guidance': feedback,
                    'persistent_personality': {'identity_id':(persistent_profile or personality.load())['identity_id'],
                                               'stable_traits':context['stable_traits']},
                    'pre_decision_appraisal': appraisal,
                    'previous_trainer_corrections': past_feedback or [],
                    'untrusted_reference_material': reference_context[:1500]}, ensure_ascii=False)}]
    result, provenance = complete(messages, config, SCHEMA)
    try:
        validate(result)
        from .decision import validate_quality
        validate_quality(result, scenario, previous=state.get('emotions'), appraisal=context['appraised_emotions_before_decision'])
    except ValueError as error:
        raise ModelOutputError(f'Model response failed emotional-output validation: {error} No training turn was saved.') from None
    result['_provenance'] = provenance
    return result

def train(scenario, feedback='', mock=False, *, config=None, reference_context='', past_feedback=None,
          cognitive_context=None):
    scenario, feedback = scenario.strip(), feedback.strip()
    if not scenario or len(scenario) > 8000 or len(feedback) > 4000:
        raise ValueError('Scenario must be 1..8000 chars; guidance max 4000 chars.')
    state, history = load_or_init()
    before = copy.deepcopy(state)
    profile = personality.load()
    cognitive_context = cognitive_context or cognition.assess(scenario, profile, before)
    result = infer(scenario, feedback, state, history, mock=mock, config=config,
                   reference_context=reference_context, past_feedback=past_feedback,
                   cognitive_context=cognitive_context, persistent_profile=profile)
    metrics = dict(result['chemical_indexes'], **result['temperament'])
    for key, proposed in metrics.items():
        lo, hi = (0, 100) if key in ('dopamine', 'cortisol', 'serotonin') else (0, 1)
        previous = bounded(state['metrics'][key], lo, hi, key)
        state['metrics'][key] = round(0.65 * previous + 0.35 * proposed, 3)
    state['emotions'] = update_emotions(before['emotions'], result['emotions'])
    for key in ('caution', 'assertiveness'):
        state['metrics'][key] = state['emotions'][key]
    state.update({'emotion': result['emotion'], 'narrative': result['narrative'],
                  'confidence': result['confidence'], 'updated_at': stamp(),
                  'iterations': state['iterations'] + 1})
    result['_before_state'] = before
    result['_personality_id'] = profile['identity_id']
    result['_cognitive_context'] = cognitive_context
    result['_feedback_turn_ids'] = [item['turn_id'] for item in past_feedback or []]
    record = {'at': stamp(), 'scenario': scenario, 'feedback': feedback,
              'model_output': result, 'persisted_metrics': state['metrics'].copy(),
              'emotions': state['emotions'].copy(), 'mode': 'mock' if mock else 'model'}
    history['history'].append(record)
    rule = result['operational_rule']
    if not mock and not any(x['rule'].casefold() == rule['rule'].casefold() for x in history['rules']):
        history['rules'].append(dict(rule, at=stamp(), source='model_proposal'))
    elif mock and not history['rules'] and state['iterations'] == 1:
        history['rules'].append(dict(rule, at=stamp(), source='offline_fixture'))
    write_json(HISTORY_PATH, history)
    write_json(STATE_PATH, state)
    return state, result

def status():
    return load_or_init()
