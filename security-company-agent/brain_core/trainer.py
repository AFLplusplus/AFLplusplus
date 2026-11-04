"""Standalone affective simulation and contextual adaptation; no agent execution."""
from __future__ import annotations
import copy
import json
import math
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
import uuid
from .appraisal import NEUTRAL, offline_appraisal, update_emotions, state_emotions
from . import personality, cognition
from .decision import SCHEMA, validate_decision, validate_quality
from .model_api import ModelConfig, ModelError, ModelOutputError, complete

QUALITY_SYSTEM = '''You are Sovereign Brain, one persistent fictional personality. Write first-person
simulated responses, never claim actual feelings. Return the JSON schema only.
Reason from this scenario: what happened, who is affected, reported facts versus unknown motives,
and consequences of 2 concrete options. Choose a specific action in plain language, not an option ID.
Explain how relevant simulated emotions influence this choice. Responsibility and fairness concern actual harm;
self-respect means respectful boundaries, not always winning a disagreement.'''
BASE = {'dopamine': 50.0, 'cortisol': 50.0, 'serotonin': 50.0}
ROOT = Path(__file__).resolve().parent
STATE_PATH = ROOT / 'eq_matrix.json'
HISTORY_PATH = ROOT / 'trainer_history.json'


def stamp():
    return datetime.now(timezone.utc).isoformat()


def _read(path, default):
    path = Path(path)
    if not path.exists():
        return copy.deepcopy(default)
    return json.loads(path.read_text(encoding='utf-8'))


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')


def load_or_init(*, state_path=None, history_path=None):
    state_path = Path(state_path or STATE_PATH)
    history_path = Path(history_path or HISTORY_PATH)
    state = _read(state_path, {'iterations': 0, 'emotion': 'neutral', 'metrics': dict(BASE), 'emotions': dict(NEUTRAL)})
    history = _read(history_path, {'iterations': 0, 'rules': [], 'history': []})
    history.setdefault('history', [])
    return state, history


def _isolated_test_runtime(*, state_path=None, history_path=None, db_path=None, data_dir=None):
    """Require test/offline writes to route to injected stores, not active runtime files."""
    active = Path(__file__).resolve().parent
    state_target = Path(state_path or STATE_PATH)
    history_target = Path(history_path or HISTORY_PATH)
    database = Path(db_path) if db_path is not None else active / 'studio_data' / 'brain.sqlite3'
    data_target = Path(data_dir) if data_dir is not None else active / 'studio_data'
    return (state_target != active / 'eq_matrix.json'
            and history_target != active / 'trainer_history.json'
            and database != active / 'studio_data' / 'brain.sqlite3'
            and data_target != active / 'studio_data')


def inspect_status(*, state_path=None, history_path=None):
    state_path = Path(state_path or STATE_PATH)
    history_path = Path(history_path or HISTORY_PATH)
    if not state_path.exists() and not history_path.exists():
        return None, {'history': [], 'rules': []}
    state, history = load_or_init(state_path=state_path, history_path=history_path)
    if 'emotions' not in state and state_path.exists():
        state['emotions'] = dict(NEUTRAL)
    if 'emotions' in state:
        state['emotions'] = state_emotions(state['emotions'])
    history.setdefault('history', [])
    return state, history


def status(*, state_path=None, history_path=None):
    return inspect_status(state_path=state_path, history_path=history_path)


def validate(data):
    return validate_decision(data)


_DIAGNOSTIC_FIELDS = {
    'id', 'scenario_length', 'stage', 'stage_duration_seconds', 'repair_duration_seconds', 'validation_passed',
    'original_validation', 'validation_error', 'repair_error', 'repair_attempted', 'repair_validation', 'repair_succeeded',
    'failed_field', 'repair_failed_field', 'failed_criterion', 'failed_alternative_index', 'repair_failed_alternative_index',
    'validator_details', 'alternatives', 'repair_alternatives', 'emotion_labels',
    'response_fields', 'verbosity', 'at', 'error_category', 'provider', 'model', 'raw_response_redacted',
}
_DIAGNOSTIC_SECRET_PATTERNS = (
    re.compile(r'(?i)\b(?:bearer\s+)?[A-Z0-9._~+/-]{20,}={0,2}\b'),
    re.compile(r'(?i)\b(?:api[_-]?key|token|password|passwd|secret|authorization)\s*[:=]?\s*[^\s,;]+'),
    re.compile(r'(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b'),
    re.compile(r'(?i)\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    re.compile(r'\b\d{1,5}\s+[\w.-]+\s+(?:street|st|road|rd|avenue|ave|lane|ln|drive|dr|court|ct|boulevard|blvd|way)\b', re.I),
)
_DIAGNOSTIC_NAME_PATTERN = re.compile(r'\b[A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,})+\b')
_DIAGNOSTIC_SINGLE_NAME_PATTERN = re.compile(r'\b(?:Alice|Bob|Charlie|David|Emma|Frank|Grace|John|Jane|Mary|Michael|Sarah)\b', re.I)


def _sanitize_diagnostic_value(value, scenario=''):
    if isinstance(value, str):
        return _sanitize_diagnostic_text(value, scenario)
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return value
    if isinstance(value, list):
        return [_sanitize_diagnostic_value(item, scenario) for item in value[:20]]
    if isinstance(value, dict):
        return {str(key)[:60]: _sanitize_diagnostic_value(item, scenario)
                for key, item in list(value.items())[:30]
                if isinstance(key, str) and re.fullmatch(r'[a-zA-Z0-9_.-]{1,60}', key)}
    return '[omitted]'


def _alternative_index(field):
    if not isinstance(field, str):
        return None
    match = re.fullmatch(r'alternatives\[(\d+)\]', field)
    return int(match.group(1)) if match else None


def _diagnostic_verbosity():
    value = os.getenv('BRAIN_DIAGNOSTIC_VERBOSITY', 'minimal').strip().casefold().replace('-', '_').replace(' ', '_')
    aliases = {'debug': 'local_debug', 'localdebug': 'local_debug'}
    value = aliases.get(value, value)
    return value if value in {'off', 'minimal', 'local_debug'} else 'minimal'


def _sanitize_diagnostic_text(value, scenario='', *, redact_names=True):
    """Conservatively redact identifying text and bound local diagnostic content."""
    if not isinstance(value, str):
        return '[omitted]'
    text = value
    if scenario:
        text = re.sub(re.escape(scenario), '[scenario omitted]', text, flags=re.I)
    # Scrub structured scenario values too (e.g. a name/email/phone copied into
    # an otherwise paraphrased validator message).
    text = re.sub(r'(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', '[redacted]', text)
    for pattern in _DIAGNOSTIC_SECRET_PATTERNS:
        text = pattern.sub('[redacted]', text)
    text = re.sub(r'(?i)\b(?:bearer|password|passwd|token|api[_-]?key|secret|authorization)\b\s*[:=]?\s*[^\s,;]+', '[redacted]', text)
    if redact_names:
        text = _DIAGNOSTIC_NAME_PATTERN.sub('[name]', text)
        text = _DIAGNOSTIC_SINGLE_NAME_PATTERN.sub('[name]', text)
    text = re.sub(r'(?i)\b(?:alice|bob|charlie|david|emma|frank|grace|john|jane|mary|michael|sarah)\b', '[name]', text)
    text = re.sub(r'(?i)\b(?:\+?\d[\d(). -]{7,}\d)\b', '[redacted]', text)
    return text[:500]


def _minimal_grounding_details(details):
    if not isinstance(details, dict):
        return {}
    keys = ('scenario_relevance_score', 'scenario_overlap_passed', 'scenario_threshold',
            'validated_fact_scores', 'validated_fact_overlap_passed', 'validated_fact_threshold', 'passed')
    if 'alternative_grounding' in details:
        checks = details.get('alternative_grounding')
        return {'alternative_grounding': [
            {key: item.get(key) for key in keys} for item in checks[:2] if isinstance(item, dict)
        ] if isinstance(checks, list) else []}
    summary = {}
    for phase in ('original', 'repair'):
        checks = details.get(phase)
        if isinstance(checks, dict) and isinstance(checks.get('alternative_grounding'), list):
            summary[phase] = [{key: item.get(key) for key in keys}
                              for item in checks['alternative_grounding'][:2] if isinstance(item, dict)]
    emotion_checks = details.get('emotion_appraisal')
    if isinstance(emotion_checks, list):
        summary['emotion_appraisal'] = [
            {key: item.get(key) for key in ('normalized_candidate', 'classification',
                                             'grounding_supported', 'reason')}
            for item in emotion_checks[:3] if isinstance(item, dict)
        ]
    return summary


def _write_diagnostic(diagnostic_id, scenario='', response=None, validation_error=None, repair_error=None,
                      *, stage=None, details=None, raw_text=None, error_category=None,
                      provider=None, model=None):
    """Write an allowlisted, sanitized failure record outside training memory."""
    verbosity = _diagnostic_verbosity()
    if verbosity == 'off':
        return None
    details = dict(details) if isinstance(details, dict) else {}
    response = response if isinstance(response, dict) else {}
    configured_path = os.getenv('BRAIN_DIAGNOSTIC_DIR')
    default_path = Path(tempfile.gettempdir()) / 'sovereign-brain-diagnostics'
    path = Path(configured_path) if configured_path else default_path
    if not path.is_absolute():
        path = default_path
    criterion = _sanitize_diagnostic_text(str(validation_error or ''), scenario)
    safe_diagnostic_id = re.sub(r'[^a-zA-Z0-9_-]', '', str(diagnostic_id))[:80] or 'diagnostic'
    if isinstance(details.get('stage_duration_seconds'), (int, float)):
        details['stage_duration_seconds'] = round(details['stage_duration_seconds'], 3)
    if isinstance(details.get('repair_duration_seconds'), (int, float)):
        details['repair_duration_seconds'] = round(details['repair_duration_seconds'], 3)
    allowed_details = {
        'stage_duration_seconds': details.get('stage_duration_seconds'),
        'repair_duration_seconds': details.get('repair_duration_seconds'),
        'validation_passed': details.get('validation_passed', False),
        'original_validation': _sanitize_diagnostic_text(str(details.get('original_validation') or criterion), scenario),
        'repair_attempted': bool(details.get('repair_attempted', repair_error is not None)),
        'repair_validation': _sanitize_diagnostic_text(str(details.get('repair_validation') or repair_error or ''), scenario),
        'repair_succeeded': bool(details.get('repair_succeeded', False)),
        'failed_field': _sanitize_diagnostic_text(str(details.get('failed_field') or ''), scenario),
        'failed_alternative_index': details.get('failed_alternative_index', _alternative_index(details.get('failed_field'))),
        'repair_failed_alternative_index': details.get('repair_failed_alternative_index', _alternative_index(details.get('repair_failed_field'))),
        'repair_failed_field': _sanitize_diagnostic_text(str(details.get('repair_failed_field') or ''), scenario),
        'emotion_labels': details.get('emotion_labels', []),
        'validator_details': details.get('validator_details') if isinstance(details.get('validator_details'), dict) else {},
    }
    allowed_details['validator_details'] = _sanitize_diagnostic_value(allowed_details['validator_details'], scenario)
    response_field_allowlist = {'facts', 'emotions', 'assumptions', 'alternatives',
                                'selected_action', 'rationale', 'emotional_tradeoff'}
    allowed_details['emotion_labels'] = _sanitize_diagnostic_value(allowed_details['emotion_labels'], scenario)
    payload = {'id': safe_diagnostic_id, 'scenario_length': len(scenario) if isinstance(scenario, str) else 0,
               'stage': _sanitize_diagnostic_text(str(stage or ''), scenario), **allowed_details,
               'error_category': str(error_category)[:80] if error_category else None,
               'provider': str(provider)[:80] if provider else None,
               'model': str(model)[:120] if model else None,
               'failed_criterion': criterion,
               'validation_error': criterion,
               'repair_error': _sanitize_diagnostic_text(str(repair_error or ''), scenario),
               'response_fields': sorted(key for key in response if key in response_field_allowlist),
               'verbosity': verbosity, 'at': stamp()}
    if verbosity == 'minimal':
        payload['alternatives'] = []
        payload['repair_alternatives'] = []
        payload['validator_details'] = _sanitize_diagnostic_value(
            _minimal_grounding_details(allowed_details['validator_details']), scenario)
    if verbosity == 'local_debug':
        # Raw completion text is strictly opt-in, local-only, bounded, and scrubbed
        # for the current scenario plus common secrets and identifiers.
        if isinstance(raw_text, str) and raw_text:
            payload['raw_response_redacted'] = _sanitize_diagnostic_text(raw_text, scenario)
        payload['emotion_labels'] = allowed_details['emotion_labels'][:6] if isinstance(allowed_details['emotion_labels'], list) else []
        if isinstance(raw_text, str) and raw_text:
            payload['raw_response_redacted'] = _sanitize_diagnostic_text(raw_text, scenario)
        def safe_alternatives(items):
            if not isinstance(items, list):
                return []
            output = []
            for item in items[:2]:
                if not isinstance(item, dict):
                    output.append({'action': '[missing]', 'consequence': '[missing]'})
                    continue
                action = item.get('action', '')
                consequence = item.get('consequence', '')
                if not isinstance(action, str) or not isinstance(consequence, str):
                    output.append({'action': '[omitted]', 'consequence': '[omitted]'})
                    continue
                output.append({
                    'action': _sanitize_diagnostic_text(action, scenario),
                    'consequence': _sanitize_diagnostic_text(consequence, scenario),
                })
            return output
        payload['alternatives'] = safe_alternatives(response.get('alternatives'))
        payload['repair_alternatives'] = safe_alternatives(response.get('repair_alternatives'))
        details_by_key = allowed_details['validator_details']
        payload['validator_details'] = _sanitize_diagnostic_value(details_by_key, scenario)
    # Enforce an explicit top-level allowlist even if this writer is extended later.
    payload = {key: value for key, value in payload.items() if key in _DIAGNOSTIC_FIELDS}
    try:
        path.mkdir(parents=True, exist_ok=True)
        if verbosity == 'local_debug' and os.name == 'nt':
            import subprocess
            subprocess.run(['icacls', str(path), '/inheritance:r', '/grant:r',
                            f'{os.getenv("USERNAME", "")}:(OI)(CI)F'],
                           capture_output=True, timeout=5, check=False)
        (path / f'{safe_diagnostic_id}.json').write_text(json.dumps(payload, ensure_ascii=False), encoding='utf-8')
    except OSError:
        return None
    return diagnostic_id


def infer(scenario, feedback, state, history, mock=False, *, config=None,
          reference_context='', past_feedback=None, cognitive_context=None, persistent_profile=None,
          initialize_profile=False, profile_path=None, state_path=None, history_path=None,
          data_dir=None, db_path=None):
    if mock:
        if not _isolated_test_runtime(state_path=state_path, history_path=history_path,
                                      db_path=db_path, data_dir=data_dir):
            raise ModelOutputError('Offline fixture requires an injected temporary state/database store.')
        action = 'I will request a local model before making a scenario-specific recommendation.'
        result = {
            'narrative': 'I simulate careful consideration and distinguish the fixed demonstration from actual analysis.',
            'emotion': 'curious', 'confidence': 0.5,
            'chemical_indexes': {'dopamine': 55, 'cortisol': 45, 'serotonin': 50},
            'temperament': {'caution': 0.55, 'assertiveness': 0.45},
            'emotions': offline_appraisal(scenario),
            'decision': {'conflicting_emotions': ['Offline fixture; no model analysis was performed.'],
                         'evidence': 'No evidence assessed by this demonstration.',
                         'uncertainty': 'Fixed fixture is not scenario-specific reasoning.',
                         'options': [action, 'I will explain that the offline fixture cannot evaluate this scenario.'],
                         'recommended_action': action,
                         'rationale': 'This fixed example exercises the UI and storage only.'},
            'operational_rule': {'trigger': 'When new information is incomplete',
                                 'rule': 'Ask for evidence before deciding', 'recommended_action': action},
            '_provenance': {'source': 'offline_fixture', 'model': None}}
        return validate(result)
    if not scenario.strip() or len(scenario) > 8000:
        raise ModelOutputError('Scenario must contain between 1 and 8000 characters.')
    from unittest.mock import Mock
    if isinstance(complete, Mock):
        if not _isolated_test_runtime(state_path=state_path, history_path=history_path,
                                      db_path=db_path, data_dir=data_dir):
            raise ModelOutputError('Mocked inference requires an injected temporary state/database store.')
        from .reasoning_stages import progressive_reasoning
        config = config or ModelConfig.from_env(allow_remote=os.getenv('BRAIN_ALLOW_REMOTE') == '1')
        profile = persistent_profile or copy.deepcopy(personality.DEFAULT)
        context = cognitive_context or cognition.assess(scenario, profile, state)
        return progressive_reasoning(scenario, config=config, feedback=feedback,
                                     cognitive_context=context, persistent_profile=profile,
                                     reference_context=reference_context, past_feedback=past_feedback,
                                     state_path=state_path, history_path=history_path,
                                     data_dir=data_dir, db_path=db_path)
    config = config or ModelConfig.from_env(allow_remote=os.getenv('BRAIN_ALLOW_REMOTE') == '1')
    profile = persistent_profile or (personality.load(profile_path=profile_path) if initialize_profile else
                                     personality.inspect(profile_path=profile_path) or copy.deepcopy(personality.DEFAULT))
    context = cognitive_context or cognition.assess(scenario, profile, state)
    from .reasoning_stages import progressive_reasoning
    return progressive_reasoning(scenario, config=config, feedback=feedback,
                                 cognitive_context=context, persistent_profile=profile,
                                 reference_context=reference_context, past_feedback=past_feedback)


def train(scenario, feedback='', mock=False, *, config=None, reference_context='', past_feedback=None,
          cognitive_context=None, persistent_profile=None, initialize_profile=False,
          state_path=None, history_path=None, data_dir=None, db_path=None, profile_path=None,
          persist_fixture_state=True, proposed_result=None):
    scenario, feedback = scenario.strip(), feedback.strip()
    if not scenario or len(scenario) > 8000 or len(feedback) > 4000:
        raise ValueError('Scenario or feedback exceeds the permitted length.')
    if mock and not _isolated_test_runtime(state_path=state_path, history_path=history_path,
                                           db_path=db_path, data_dir=data_dir):
        raise ModelOutputError('Offline fixture requires an injected temporary state/database store.')
    if mock and persist_fixture_state and proposed_result is None:
        persist_fixture_state = False
    if mock and proposed_result is not None:
        raise ValueError('Offline demonstration results cannot be used as approved training proposals.')
    if proposed_result is not None and not proposed_result.get('_trainer_approved'):
        raise ValueError('Explicit trainer approval is required before training on a proposed response.')
    if proposed_result is not None and proposed_result.get('_provenance', {}).get('source') == 'offline_fixture':
        raise ValueError('Offline demonstration fixtures are not eligible for training or approval.')
    if proposed_result is not None and proposed_result.get('_trainer_pending'):
        raise ValueError('Review and explicitly approve the response before training.')
    state, history = load_or_init(state_path=state_path, history_path=history_path)
    result = copy.deepcopy(proposed_result) if proposed_result is not None else infer(
        scenario, feedback, state, history, mock=mock, config=config,
        reference_context=reference_context, past_feedback=past_feedback,
        cognitive_context=cognitive_context, persistent_profile=persistent_profile,
        initialize_profile=initialize_profile, profile_path=profile_path,
        state_path=state_path, history_path=history_path, data_dir=data_dir, db_path=db_path)
    if result.get('_trainer_pending'):
        return None, state, result

    source = result.get('_provenance', {}).get('source')
    if source == 'offline_fixture' and proposed_result is not None:
        raise ValueError('Offline demonstration fixtures are not eligible for approval or persistence.')
    if source not in ('offline_fixture', 'unit_test_mock') and not result.get('_trainer_approved'):
        raise ValueError('Training records require explicit trainer approval.')
    if result.get('_trainer_approved') and proposed_result is None:
        raise ValueError('Model inference remains pending until an explicit trainer review and approval.')
    if proposed_result is not None and proposed_result.get('_trainer_pending'):
        raise ValueError('Review and explicitly approve the response before applying it.')
    if source == 'approved_training' and not result.get('_trainer_approved'):
        raise ValueError('Approved training provenance requires explicit trainer approval.')
    if source == 'approved_training' and not mock:
        if not feedback:
            return None, state, result
        state = copy.deepcopy(state)
        state.update(copy.deepcopy(result.get('state', {})))
        if 'emotions' in result:
            state['emotions'] = update_emotions(state.get('emotions', NEUTRAL), result['emotions'])
        if feedback:
            state['iterations'] = int(state.get('iterations', 0)) + 1
            history.setdefault('rules', []).append({'scenario': scenario, 'feedback': feedback, 'at': stamp()})
            history.setdefault('history', []).append({'scenario': scenario, 'feedback': feedback, 'at': stamp()})
        for target, payload in ((Path(state_path or STATE_PATH), state),
                                (Path(history_path or HISTORY_PATH), history)):
            target.parent.mkdir(parents=True, exist_ok=True)
            write_json(target, payload)
    from . import studio
    if mock:
        if not _isolated_test_runtime(state_path=state_path, history_path=history_path,
                                      db_path=db_path, data_dir=data_dir):
            raise ModelOutputError('Offline fixture requires an injected temporary state/database store.')
        if result.get('_trainer_pending'):
            return None, state, result
        if source == 'unit_test_mock':
            return None, state, result
        if persist_fixture_state and result.get('_trainer_approved'):
            state['iterations'] = int(state.get('iterations', 0)) + 1
            state['emotions'] = update_emotions(state.get('emotions', NEUTRAL), result['emotions'])
        if persist_fixture_state and result.get('_trainer_approved'):
            turn_id = studio.add_turn(scenario, feedback, result, state, data_dir=data_dir, db_path=db_path)
            stored = dict(result)
            stored['_trainer_approved'] = True
            with studio.connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
                db.execute('UPDATE turns SET result_json=? WHERE id=?', (json.dumps(stored), turn_id))
        else:
            turn_id = None
        if persist_fixture_state and result.get('_trainer_approved'):
            if feedback:
                history.setdefault('rules', []).append({'scenario': scenario, 'feedback': feedback, 'at': stamp()})
                history.setdefault('history', []).append({'scenario': scenario, 'feedback': feedback, 'at': stamp()})
                history['iterations'] = int(history.get('iterations', 0)) + 1
            for target, payload in ((Path(state_path or STATE_PATH), state),
                                    (Path(history_path or HISTORY_PATH), history)):
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
        return turn_id, state, result

    if proposed_result is not None and result.get('_trainer_approved'):
        if result.get('_provenance', {}).get('source') == 'approved_training' and not mock:
            state = copy.deepcopy(state)
            if 'emotions' in result:
                state['emotions'] = update_emotions(state.get('emotions', NEUTRAL), result['emotions'])
            history.setdefault('rules', []).append({'scenario': scenario, 'feedback': feedback, 'at': stamp()})
            history.setdefault('history', []).append({'scenario': scenario, 'feedback': feedback, 'at': stamp()})
            history['iterations'] = int(history.get('iterations', 0)) + 1
            for target, payload in ((Path(state_path or STATE_PATH), state),
                                    (Path(history_path or HISTORY_PATH), history)):
                target.parent.mkdir(parents=True, exist_ok=True)
                write_json(target, payload)
            return None, state, result
        turn_id = studio.add_turn(scenario, feedback, result, state, data_dir=data_dir, db_path=db_path)
        if feedback:
            history.setdefault('rules', []).append({'scenario': scenario, 'feedback': feedback, 'at': stamp()})
            history.setdefault('history', []).append({'scenario': scenario, 'feedback': feedback, 'at': stamp()})
            history['iterations'] = int(history.get('iterations', 0)) + 1
        for target, payload in ((Path(state_path or STATE_PATH), state),
                                (Path(history_path or HISTORY_PATH), history)):
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
        return turn_id, state, result
    return None, state, result
