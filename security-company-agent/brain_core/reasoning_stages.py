"""Validated progressive reasoning stages used for local model inference."""
from __future__ import annotations

import json
import re
import time
import uuid

from . import cognition, personality, trainer as _trainer
from .appraisal import offline_appraisal
from .decision import (
    ALTERNATIVES_SCHEMA,
    EMOTION_UNDERSTANDING_SCHEMA,
    FINAL_DECISION_SCHEMA,
    evaluate_alternative_grounding,
    validate_alternatives,
    validate_emotional_understanding,
    validate_final_decision,
    validate_quality,
)
from .model_api import ModelError, ModelOutputError, complete


def _validate_assembled(data, scenario):
    """Validate assembled shape, action contracts and consistency with approved stages."""
    from .decision import validate_decision, validate_quality
    validate_decision(data)
    validate_quality(data, scenario)
    from .decision import validate_conflicting_emotions
    validate_conflicting_emotions(data['decision']['conflicting_emotions'])
    stage_outputs = data['_stage_outputs']
    if data['narrative'].split(' because ', 1)[0] != 'I would choose ' + stage_outputs['final_decision']['selected_action'].rstrip('.'):
        raise ValueError('Assembled narrative does not preserve the selected stage action.')


def _failed_alternative_field(criterion, raw, facts, scenario):
    if not isinstance(raw, dict) or not isinstance(raw.get('alternatives'), list):
        return 'alternatives'
    criterion = str(criterion).casefold()
    alternatives = raw['alternatives'][:2]
    if 'action is not grounded' in criterion:
        for index, item in enumerate(alternatives):
            if isinstance(item, dict) and evaluate_alternative_grounding(
                    item.get('action', ''), item.get('consequence', ''), facts, scenario
            )['scenario_relevance_score'] == 0:
                return f'alternatives[{index + 1}]'
    if 'action and consequence are not grounded' in criterion:
        for index, item in enumerate(alternatives):
            if isinstance(item, dict) and not evaluate_alternative_grounding(
                    item.get('action', ''), item.get('consequence', ''), facts, scenario
            )['validated_fact_overlap_passed']:
                return f'alternatives[{index + 1}]'
    return 'alternatives'


def _stage_details(stage, raw, facts, scenario, criterion, *, duration, passed,
                   repair_attempted=False, repair_validation='', repair_succeeded=False,
                   repair_duration=None):
    details = {'stage_duration_seconds': round(duration, 3),
               'repair_duration_seconds': round(repair_duration, 3) if repair_duration is not None else None,
               'validation_passed': passed,
               'original_validation': 'passed' if passed else criterion,
               'repair_attempted': repair_attempted, 'repair_validation': repair_validation,
               'repair_succeeded': repair_succeeded,
               'failed_field': 'alternatives' if stage == 'decision alternatives' else '',
               'validator_details': {}}
    if stage == 'decision alternatives':
        details['failed_field'] = _failed_alternative_field(criterion, raw, facts, scenario)
        match = re.search(r'alternatives\[(\d+)\]', details['failed_field'])
        details['failed_alternative_index'] = int(match.group(1)) if match else None
    if stage == 'decision alternatives' and isinstance(raw, dict):
        alternatives = raw.get('alternatives')
        if isinstance(alternatives, list):
            details['validator_details'] = {
                'alternative_grounding': [
                    evaluate_alternative_grounding(item.get('action', '') if isinstance(item, dict) else '',
                                                   item.get('consequence', '') if isinstance(item, dict) else '',
                                                   facts, scenario)
                    for item in alternatives[:2]
                ]
            }
            failed = _failed_alternative_field(criterion, raw, facts, scenario)
            if failed != 'alternatives':
                details['failed_field'] = failed
    return details


def _diagnostic(stage, criterion, scenario, raw, repair_error=None, *, details=None):
    diagnostic_id = str(uuid.uuid4())
    try:
        return _trainer._write_diagnostic(
            diagnostic_id, scenario, raw, criterion, str(repair_error or ''), stage=stage, details=details)
    except Exception:
        return None


def run_stage(stage, messages, schema, validator, config, scenario, *, facts=()):
    """Call a single stage; allow exactly one criterion-scoped repair."""
    started = time.perf_counter()
    try:
        raw, meta = complete(messages, config, schema)
    except ModelError as error:
        duration = time.perf_counter() - started
        ref = _diagnostic(stage, 'stage request failed', scenario, {}, error,
                          details={'stage_duration_seconds': duration, 'validation_passed': False,
                                   'original_validation': 'not run: request failed',
                                   'repair_attempted': False, 'repair_succeeded': False})
        failure = ModelOutputError(
            f'{stage.title()} could not be completed. No training data or emotional state was changed.',
            diagnostic_id=ref)
        failure.stage, failure.criterion = stage, 'stage request failed'
        raise failure from None
    original = raw
    try:
        validated = validator(raw)
        return validated, meta, False
    except (ValueError, TypeError, KeyError) as initial_error:
        criterion = str(initial_error)[:300].replace(scenario, '[scenario]')
        original_validation = criterion
        repair = [
            {'role': 'system', 'content':
             f'Correct only the failed criterion for the {stage} stage. Return the complete stage object. '
             'Preserve all valid fields, do not invent facts, and do not relax grounding.'},
            {'role': 'user', 'content': json.dumps({
                'failed_criterion': criterion,
                'scenario': scenario,
                'original_stage_output': raw,
                'instruction': 'Repair only what is necessary for the failed criterion.'
            }, ensure_ascii=False)}]
        repair_started = time.perf_counter()
        try:
            repaired, repair_meta = complete(repair, config, schema)
            repair_validated = validator(repaired)
            return repair_validated, repair_meta, True
        except (ValueError, TypeError, KeyError, ModelError) as repair_error:
            duration = time.perf_counter() - started
            repair_raw = repaired if 'repaired' in locals() and isinstance(repaired, dict) else {}
            details = _stage_details(stage, original, facts, scenario, criterion, duration=duration,
                                     passed=False, repair_attempted=True,
                                     repair_validation=str(repair_error), repair_succeeded=False,
                                     repair_duration=time.perf_counter() - repair_started)
            details['original_validation'] = original_validation
            details['repair_validation'] = str(repair_error)
            details['validation_passed'] = False
            details['repair_succeeded'] = False
            raw_diagnostic = dict(original) if isinstance(original, dict) else {}
            raw_diagnostic['alternatives'] = original.get('alternatives', []) if isinstance(original, dict) else []
            raw_diagnostic['repair_alternatives'] = repair_raw.get('alternatives', [])
            # Keep schema evaluation detail, but Stage 2 grounding measurements should
            # identify alternative 1 and alternative 2 independently.
            details['failed_field'] = _failed_alternative_field(criterion, original, facts, scenario)
            details['repair_failed_field'] = _failed_alternative_field(str(repair_error), repair_raw, facts, scenario)
            failed_match = re.search(r'alternatives\[(\d+)\]', details['failed_field'])
            details['failed_alternative_index'] = int(failed_match.group(1)) if failed_match else None
            repair_details = _stage_details(stage, repair_raw, facts, scenario, str(repair_error),
                                            duration=duration, passed=False,
                                            repair_attempted=True, repair_validation=str(repair_error),
                                            repair_succeeded=False,
                                            repair_duration=time.perf_counter() - repair_started)
            original_checks = details['validator_details']
            repair_checks = repair_details['validator_details']
            details['validator_details'] = {'original': original_checks, 'repair': repair_checks}
            repair_match = re.search(r'alternatives\[(\d+)\]', repair_details.get('failed_field', ''))
            details['repair_failed_alternative_index'] = int(repair_match.group(1)) if repair_match else None
            ref = _diagnostic(stage, criterion, scenario, raw_diagnostic, repair_error, details=details)
            failure = ModelOutputError(
                f'{stage.title()} did not meet the reasoning quality checks. No training data or emotional state was changed.',
                diagnostic_id=ref)
            failure.stage, failure.criterion = stage, criterion
            raise failure from None


def _action_key(text):
    from .decision import _normalize_action
    return _normalize_action(text)


def assemble_result(understanding, alternatives, final, scenario, profile, cognitive_context, provenance,
                    repair_attempts):
    """Deterministically map validated stages to the established output schema."""
    chosen = next(item for item in alternatives['alternatives']
                  if _action_key(final['selected_action']) == _action_key(item['action']))
    emotions = cognitive_context.get('appraised_emotions_before_decision') or offline_appraisal(scenario)
    primary_labels = [item['label'] for item in understanding['emotions']]
    recognized = re.compile(
        r'\b(guilt|guilty|remorse|jealousy|jealous|fear|afraid|anger|angry|sad|sadness|hope|trust|empathy|'
        r'concern|concerned|curious|curiosity|anxiety|anxious|attachment|conflicted|neutral|calm|regret|'
        r'frustration|hurt|shame|relief|joy|happy|grief|disappointment|insecurity|insecure|cautious)\b')
    conflicts = list(dict.fromkeys(
        item for emotion in understanding['emotions']
        for item in recognized.findall(emotion['label'].casefold())))[:5]
    if len(conflicts) < 2:
        conflicts.extend(item for label in primary_labels if (item := label.casefold()) not in conflicts)
        conflicts = conflicts[:5]
    result = {
        'narrative': f"I would choose {chosen['action'].rstrip('.')} because {final['rationale'].rstrip('.')}.",
        'emotion': ' and '.join(primary_labels),
        'confidence': 0.55,
        'chemical_indexes': {'dopamine': 50.0, 'cortisol': 50.0, 'serotonin': 50.0},
        'temperament': {'caution': 0.5, 'assertiveness': 0.5},
        'emotions': dict(emotions),
        'decision': {
            'conflicting_emotions': conflicts,
            'evidence': ' '.join(understanding['facts']),
            'uncertainty': ' '.join(understanding['assumptions']),
            'options': [item['action'] for item in alternatives['alternatives']],
            'recommended_action': chosen['action'],
            'rationale': final['rationale'] + ' ' + final['emotional_tradeoff'],
        },
        'operational_rule': {
            'trigger': 'When an emotionally consequential request is made under uncertainty',
            'rule': 'Separate stated facts from assumptions before responding',
            'recommended_action': chosen['action'],
        },
        '_stage_outputs': {'understanding': understanding, 'alternatives': alternatives, 'final_decision': final},
        '_stage_repair_attempts': repair_attempts,
        '_provenance': provenance,
        '_trainer_pending': True,
    }
    _validate_assembled(result, scenario)
    return result


def progressive_reasoning(scenario, *, config, feedback='', cognitive_context=None,
                          persistent_profile=None, reference_context='', past_feedback=None):
    profile = persistent_profile or (personality.inspect() or dict(personality.DEFAULT))
    context = cognitive_context or cognition.assess(scenario, profile, {'emotions': {}})
    hints = {
        'appraisal': context.get('appraised_emotions_before_decision', {}),
        'affected_parties': context.get('affected_parties', []),
        'concerns': context.get('concerns', []),
    }
    stage1_messages = [
        {'role': 'system', 'content':
         'Extract at most three observable facts explicitly stated in the scenario. Identify two or three plausible '
         'emotions and explain each trigger. Separate assumptions from facts. Do not infer hidden intentions. Keep concise.'},
        {'role': 'user', 'content': json.dumps({
            'scenario': scenario, 'appraisal_hint': hints,
            'trainer_guidance': feedback[:500], 'approved_corrections': (past_feedback or [])[:1],
            'approved_reference_excerpt': reference_context[:400],
            'previous_trainer_corrections': (past_feedback or [])[:1],
            'persistent_personality': profile,
            'pre_decision_appraisal': context,
            'output_budget_hint': 'Keep each field to one short sentence; return JSON only.'
        }, ensure_ascii=False)}]
    understanding, meta1, repaired1 = run_stage(
        'emotional understanding', stage1_messages, EMOTION_UNDERSTANDING_SCHEMA,
        lambda value: validate_emotional_understanding(value, scenario), config, scenario)

    stage2_messages = [
        {'role': 'system', 'content':
         'Using only the validated facts and appraisal, provide exactly two concrete, context-specific actions and '
         'one plausible consequence for each. Actions must differ in what is done and likely consequence. '
         'Refer to a validated fact. Do not recommend one yet.'},
        {'role': 'user', 'content': json.dumps({
            'scenario': scenario, 'validated_understanding': understanding,
            'emotional_appraisal': context.get('relationship_emotions', {}),
            'previous_trainer_corrections': (past_feedback or [])[:1],
            'persistent_personality': profile,
            'pre_decision_appraisal': context,
            'output_budget_hint': 'Keep actions and consequences concise; return JSON only.'
        }, ensure_ascii=False)}]
    alternatives, meta2, repaired2 = run_stage(
        'decision alternatives', stage2_messages, ALTERNATIVES_SCHEMA,
        lambda value: validate_alternatives(value, understanding['facts'], scenario, understanding['emotions']),
        config, scenario, facts=understanding['facts'])

    stage3_messages = [
        {'role': 'system', 'content':
         'Select exactly one validated alternative; do not invent a new action. Give a concise rationale grounded in '
         'the original scenario and explain the principal emotional trade-off. Do not assume unspoken intentions.'},
        {'role': 'user', 'content': json.dumps({
            'scenario': scenario, 'validated_facts': understanding['facts'],
            'validated_emotions': understanding['emotions'], 'validated_alternatives': alternatives,
            'previous_trainer_corrections': (past_feedback or [])[:1],
            'persistent_personality': profile,
            'pre_decision_appraisal': context,
            'output_budget_hint': 'Keep rationale and emotional trade-off to one concise sentence each; return JSON only.'
        }, ensure_ascii=False)}]
    final, meta3, repaired3 = run_stage(
        'final decision', stage3_messages, FINAL_DECISION_SCHEMA,
        lambda value: validate_final_decision(value, alternatives, scenario, understanding['facts']), config, scenario)

    provenance = {'source': meta3.get('source', 'local_model'), 'model': config.model,
                  'seconds': sum(float(item.get('seconds', 0)) for item in (meta1, meta2, meta3))}
    return assemble_result(understanding, alternatives, final, scenario, profile, context, provenance,
                           {'understanding': repaired1, 'alternatives': repaired2, 'final_decision': repaired3})
