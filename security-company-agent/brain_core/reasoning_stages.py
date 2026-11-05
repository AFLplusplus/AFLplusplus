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
    """Validate internal structured result independently of trainer policy."""
    from .decision import validate_decision, validate_quality
    validate_decision(data)
    validate_quality(data, scenario)
    from .decision import validate_conflicting_emotions
    validate_conflicting_emotions(data['decision']['conflicting_emotions'])
    stage_outputs = data['_stage_outputs']
    if data['narrative'].split(' because ', 1)[0] != 'I would choose ' + stage_outputs['final_decision']['selected_action'].rstrip('.'):
        raise ValueError('Assembled narrative does not preserve the selected stage action.')
    return True


def conversational_response(data):
    """Render a validated internal analysis as natural user-facing conversation."""
    from .reasoning_contract import from_validated_result

    contract = from_validated_result(data)
    if not contract.scenario_facts or not contract.user_reported_emotions or not contract.uncertainties:
        raise ValueError('Validated response is missing required contract fields.')

    def sentence(value):
        text = str(value).strip().rstrip('.!? ')
        return text if text else ''

    def action_phrase(value):
        text = sentence(value)
        for prefix in ('I will ', 'I would ', 'I can '):
            if text.casefold().startswith(prefix.casefold()):
                return text[len(prefix):]
        return text[0].lower() + text[1:] if text else ''

    parts = [f"From what you described, {sentence(contract.scenario_facts[0])}."]
    emotion = contract.user_reported_emotions[0]
    label = str(emotion.get('label', '')).strip()
    trigger = sentence(emotion.get('trigger', ''))
    if not label or not trigger:
        raise ValueError('Validated response is missing a grounded emotion.')
    trigger = re.sub(r'^(I feel|I am|I\'m|I want|I do not want)\s+', '', trigger, flags=re.IGNORECASE)
    parts.append(f"You described feeling {label} about {trigger[0].lower() + trigger[1:] if trigger else trigger}.")

    uncertainty = sentence(contract.uncertainties[0])
    if not uncertainty:
        raise ValueError('Validated response is missing uncertainty context.')
    if uncertainty.casefold().startswith('the reason'):
        parts.append(f"What remains uncertain is {uncertainty[0].lower() + uncertainty[1:]}.")
    else:
        parts.append(f"What remains uncertain is that {uncertainty}.")
    if contract.alternative_interpretations:
        alternative = sentence(contract.alternative_interpretations[0])
        if alternative and alternative.casefold() != uncertainty.casefold():
            parts.append(f"Other possibilities to keep in mind: {alternative}.")

    chosen = action_phrase(contract.recommended_response)
    if not chosen:
        raise ValueError('Validated response is missing a recommendation.')
    parts.append(f"One proportionate next step is to {chosen}.")
    rationale = sentence(contract.potential_actions[0].get('consequence', '')) if contract.potential_actions else ''
    final = sentence((data.get('_stage_outputs') or {}).get('final_decision', {}).get('rationale', ''))
    if final:
        parts.append(final[0].upper() + final[1:] + '.')
    elif rationale:
        parts.append(f"This may {rationale}.")
    if contract.approved_lessons:
        lesson = contract.approved_lessons[0]
        principle = str(lesson.get('corrective_principle', '')).strip()
        lesson_id = str(lesson.get('lesson_id', '')).strip()
        source = str(lesson.get('source_type', '')).strip()
        if principle and lesson_id and source:
            parts.append(f"A relevant approved lesson (lesson {lesson_id}, source: {source}) offers this guidance, not evidence about anyone's motives: {sentence(principle)}.")
    return ' '.join(parts)


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


def _failed_stage_one_field(criterion, raw):
    text = str(criterion).casefold()
    if 'emotion' in text or 'appraisal' in text:
        return 'emotions'
    if 'assumption' in text:
        return 'assumptions'
    if 'fact' in text:
        return 'facts'
    if not isinstance(raw, dict):
        return 'response'
    return 'structure'


EMOTION_DIAGNOSTIC_LABELS = frozenset({
    'attachment', 'anger', 'sadness', 'fear', 'hope', 'trust', 'empathy',
    'frustration', 'caution', 'assertiveness', 'emotional_regulation', 'guilt', 'jealousy',
})


def _stage_one_emotion_diagnostics(raw, scenario):
    """Return compact label-level checks only; never persist triggers or prompts."""
    if not isinstance(raw, dict) or not isinstance(raw.get('emotions'), list):
        return []
    from .decision import _emotion_grounding_support, _normalize_emotion_label
    entries = []
    for item in raw['emotions'][:3]:
        if not isinstance(item, dict):
            continue
        label = item.get('label', '')
        canonical, status = _normalize_emotion_label(label)
        # Persist only labels from a closed diagnostic vocabulary. Arbitrary
        # generated text can contain names or private scenario details even after
        # best-effort redaction, so unknown raw labels are never written.
        safe_label = canonical or (label.casefold() if isinstance(label, str) and
                                   label.casefold() in EMOTION_DIAGNOSTIC_LABELS else '[unrecognized]')
        entries.append({
            'label': safe_label,
            'normalized_candidate': canonical,
            'classification': 'known' if canonical is not None else status,
            'grounding_supported': _emotion_grounding_support(canonical, scenario) if canonical else False,
            'reason': 'supported' if canonical and _emotion_grounding_support(canonical, scenario)
                      else ('unsupported_grounding' if canonical else status),
        })
    return entries


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


def _diagnostic(stage, criterion, scenario, raw, repair_error=None, *, details=None,
                raw_text=None, error_category=None, config=None):
    diagnostic_id = str(uuid.uuid4())
    try:
        return _trainer._write_diagnostic(
            diagnostic_id, scenario, raw, criterion, str(repair_error or ''), stage=stage, details=details,
            raw_text=raw_text, error_category=error_category,
            provider='local_ollama' if getattr(config, 'local', True) else 'remote_gateway',
            model=getattr(config, 'model', None))
    except Exception:
        return None


def run_stage(stage, messages, schema, validator, config, scenario, *, facts=()):
    """Call a single stage; allow exactly one criterion-scoped repair."""
    started = time.perf_counter()
    try:
        raw, meta = complete(messages, config, schema)
    except ModelError as error:
        duration = time.perf_counter() - started
        from .providers import category_for_error
        error_category = category_for_error(error)
        ref = _diagnostic(stage, 'stage request failed', scenario, {}, error,
                          details={'stage_duration_seconds': duration, 'validation_passed': False,
                                   'original_validation': 'not run: request failed',
                                   'repair_attempted': False, 'repair_succeeded': False},
                          error_category=error_category, config=config)
        failure = ModelOutputError(
            f'{stage.title()} could not be completed. No training data or emotional state was changed.',
            diagnostic_id=ref)
        failure.stage = stage
        failure.criterion = error_category
        raise failure from None
    original = raw
    raw_text = meta.get('raw_text') if isinstance(meta, dict) else None
    try:
        validated = validator(raw)
        return validated, meta, False
    except (ValueError, TypeError, KeyError) as initial_error:
        criterion = str(initial_error)[:300].replace(scenario, '[scenario]')
        original_validation = criterion
        # Keep repair context bounded: include the validated source and only the
        # offending field's original value, rather than echoing the full stage object.
        failed_key = 'assumptions' if 'assumption' in criterion.casefold() else (
            'facts' if 'fact' in criterion.casefold() else 'emotions' if 'emotion' in criterion.casefold() else None)
        repair_payload = {'failed_criterion': criterion, 'scenario': scenario,
                          'instruction': 'Return the complete stage object; correct only the failed field, keep every field concise, and do not invent facts.'}
        if failed_key and isinstance(raw, dict):
            repair_payload['failed_field'] = failed_key
            repair_payload['original_failed_value'] = raw.get(failed_key)
            repair_payload['validated_fields'] = {key: raw[key] for key in ('facts', 'emotions', 'assumptions')
                                                  if key != failed_key and key in raw}
        else:
            repair_payload['original_stage_output'] = raw
        repair = [
            {'role': 'system', 'content':
             f'Repair the {stage} JSON only. Preserve valid fields. Keep it concise; do not invent facts or weaken grounding.'},
            {'role': 'user', 'content': json.dumps(repair_payload, ensure_ascii=False)}]
        repair_started = time.perf_counter()
        try:
            repaired, repair_meta = complete(repair, config, schema)
            if not raw_text and isinstance(repair_meta, dict):
                raw_text = repair_meta.get('raw_text')
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
            if stage == 'emotional understanding':
                details['failed_field'] = _failed_stage_one_field(criterion, original)
                details['emotion_labels'] = _stage_one_emotion_diagnostics(original, scenario)
                details['validator_details'] = {'emotion_appraisal': details['emotion_labels']}
            details['repair_succeeded'] = False
            raw_diagnostic = dict(original) if isinstance(original, dict) else {}
            if stage == 'decision alternatives':
                raw_diagnostic['alternatives'] = original.get('alternatives', []) if isinstance(original, dict) else []
                raw_diagnostic['repair_alternatives'] = repair_raw.get('alternatives', [])
                # Stage 2 grounding measurements identify each alternative independently.
                details['failed_field'] = _failed_alternative_field(criterion, original, facts, scenario)
                details['repair_failed_field'] = _failed_alternative_field(str(repair_error), repair_raw, facts, scenario)
                failed_match = re.search(r'alternatives\[(\d+)\]', details['failed_field'])
                details['failed_alternative_index'] = int(failed_match.group(1)) if failed_match else None
                repair_details = _stage_details(stage, repair_raw, facts, scenario, str(repair_error),
                                                duration=duration, passed=False,
                                                repair_attempted=True, repair_validation=str(repair_error),
                                                repair_succeeded=False,
                                                repair_duration=time.perf_counter() - repair_started)
                details['validator_details'] = {'original': details['validator_details'],
                                                'repair': repair_details['validator_details']}
                repair_match = re.search(r'alternatives\[(\d+)\]', repair_details.get('failed_field', ''))
                details['repair_failed_alternative_index'] = int(repair_match.group(1)) if repair_match else None
            if stage == 'emotional understanding':
                raw_diagnostic['emotion_labels'] = details.get('emotion_labels', [])
            ref = _diagnostic(stage, criterion, scenario, raw_diagnostic, repair_error, details=details,
                              raw_text=raw_text,
                              error_category='cognitive_validation' if 'schema' not in str(repair_error).casefold()
                              else 'schema_validation', config=config)
            failure = ModelOutputError(
                f'{stage.title()} did not meet the reasoning quality checks. No training data or emotional state was changed.',
                diagnostic_id=ref)
            failure.stage = stage
            failure.criterion = criterion
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
    from .decision import _normalize_emotion_label
    # Defensively canonicalize at assembly too, so callers cannot bypass the
    # Stage 1 validator and inject arbitrary or compound labels downstream.
    primary_labels = []
    for item in understanding['emotions']:
        canonical, _ = _normalize_emotion_label(item.get('label'))
        if canonical is None:
            raise ValueError('Cannot assemble a result with an unrecognized emotional appraisal.')
        item['label'] = canonical
        primary_labels.append(canonical)
    conflicts = list(dict.fromkeys(primary_labels))[:5]
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
    # Stage 1's explicit contract is limited to scenario facts, emotions, and unknowns;
    # appraisal/context is incorporated downstream and is not needed in its prompt.
    stage1_messages = [
        {'role': 'system', 'content':
         'Return concise JSON only: 1-3 explicit scenario facts; 2-3 plausible emotions with brief scenario-grounded triggers; '
         '1-2 uncertainties tied to stated details. Keep each value short. Separate reported facts from inference; '
         'Use concise emotion words; do not assert another person’s emotion unless scenario-supported. '
         'Separate reported facts from inference; do not invent facts or infer hidden intentions.'},
        {'role': 'user', 'content': json.dumps({
            'scenario': scenario,
            'output_budget_hint': 'Minimal phrases; complete every required field.'
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
            'approved_human_supervised_lessons': context.get('supervised_lessons', [])[:3],
            'approved_lessons_enabled': context.get('supervised_lessons_enabled', False),
            'external_evidence': context.get('research_evidence'),
            'external_evidence_guidance': context.get('research_evidence_guidance'),
            'memory_provenance_guidance': (
                'Retrieved approved lessons are prior trainer-authored context only. '
                'Preserve each lesson ID and source; do not treat a lesson as verified evidence about this situation.'
            ),
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
            'approved_human_supervised_lessons': context.get('supervised_lessons', [])[:3],
            'approved_lessons_enabled': context.get('supervised_lessons_enabled', False),
            'external_evidence': context.get('research_evidence'),
            'external_evidence_guidance': context.get('research_evidence_guidance'),
            'memory_provenance_guidance': (
                'Retrieved approved lessons are prior trainer-authored context only. '
                'Preserve each lesson ID and source; do not treat a lesson as verified evidence about this situation.'
            ),
            'persistent_personality': profile,
            'pre_decision_appraisal': context,
            'output_budget_hint': 'Keep rationale and emotional trade-off to one concise sentence each; return JSON only.'
        }, ensure_ascii=False)}]
    final, meta3, repaired3 = run_stage(
        'final decision', stage3_messages, FINAL_DECISION_SCHEMA,
        lambda value: validate_final_decision(value, alternatives, scenario, understanding['facts']), config, scenario)

    provenance = {'source': meta3.get('source', 'local_model'), 'model': config.model,
                  'seconds': sum(float(item.get('seconds', 0)) for item in (meta1, meta2, meta3))}
    result = assemble_result(understanding, alternatives, final, scenario, profile, context, provenance,
                             {'understanding': repaired1, 'alternatives': repaired2, 'final_decision': repaired3})
    result['_intelligence_claims'] = [result['operational_rule']['rule']]
    result['conversational_response'] = conversational_response(result)
    result['_validation'] = {'schema_version': 'sovereign-reasoning.v1',
                             'schema_passed': True, 'cognitive_checks_passed': True,
                             'stages': ['understanding', 'alternatives', 'final_decision']}
    result['_provenance']['approved_lessons'] = [
        {'lesson_id': item.get('lesson_id'), 'source_type': item.get('source_type')}
        for item in (context.get('supervised_lessons') or [])[:3]
        if isinstance(item, dict) and item.get('approval_status', 'approved') == 'approved']
    return result
