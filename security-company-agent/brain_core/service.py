"""Streamlit-independent training service: references, feedback, state and storage."""
import json
from . import trainer, studio, personality, memory, cognition
from .appraisal import NEUTRAL

def analyze(scenario, guidance='', *, mock=False, config=None, use_references=False,
            use_feedback=True, relationship_label='', state_path=None, history_path=None,
            data_dir=None, db_path=None, profile_path=None, initialize_profile=False,
            persist_fixture_state=False, approved_result=None):
    if approved_result is not None and not approved_result.get('_trainer_approved'):
        raise ValueError('Explicit trainer approval is required before applying a pending response.')
    if approved_result is not None and approved_result.get('_provenance', {}).get('source') == 'offline_fixture':
        raise ValueError('Offline demonstration fixtures cannot be approved or applied as training.')
    if approved_result is not None and approved_result.get('_trainer_pending'):
        raise ValueError('Review and explicitly approve the response before applying it.')
    references = studio.relevant_context(scenario, max_chars=2500, initialize=False, data_dir=data_dir, db_path=db_path) if use_references else ''
    corrections = studio.feedback_context(scenario, initialize=False, data_dir=data_dir, db_path=db_path) if use_feedback else []
    profile = (personality.load(profile_path=profile_path, initialize=True) if initialize_profile else
               personality.inspect(profile_path=profile_path))
    if profile is None:
        profile = dict(personality.DEFAULT)
    previous, _ = trainer.inspect_status(state_path=state_path, history_path=history_path) if mock else ({'emotions': dict(NEUTRAL)}, {})
    if previous is None:
        previous = {'emotions': dict(NEUTRAL)}
    context = cognition.assess(scenario, profile, previous,
                               relationship_state=memory.relationship(relationship_label, data_dir=data_dir, db_path=db_path),
                               experiences=memory.experiences(scenario, data_dir=data_dir, db_path=db_path) if use_feedback else [])
    context['supervised_lessons'] = (memory.supervised_lessons(scenario, data_dir=data_dir, db_path=db_path)
                                     if use_feedback else [])
    context['supervised_lessons_enabled'] = bool(use_feedback)
    trainer_result = trainer.train(scenario, guidance, mock=mock, config=config,
                                  reference_context=references, past_feedback=corrections,
                                  cognitive_context=context, persistent_profile=profile,
                                  proposed_result=approved_result,
                                  initialize_profile=initialize_profile,
                                  state_path=state_path, history_path=history_path,
                                  data_dir=data_dir, db_path=db_path, profile_path=profile_path,
                                  persist_fixture_state=persist_fixture_state)
    if len(trainer_result) == 2:
        state, result = trainer_result
        trainer_turn = None
    else:
        trainer_turn, state, result = trainer_result
    if approved_result is not None and result.get('_trainer_approved') and result.get('_provenance', {}).get('source') == 'approved_training':
        state, _ = trainer.inspect_status(state_path=state_path, history_path=history_path)
    should_save = (mock and persist_fixture_state and result.get('_provenance', {}).get('source') == 'offline_fixture'
                   and not result.get('_trainer_pending') and result.get('_trainer_approved')) or (
        approved_result is not None and result.get('_trainer_approved')
        and not result.get('_trainer_pending'))
    turn_id = trainer_turn
    if should_save and turn_id is None:
        turn_id = studio.add_turn(scenario, guidance, result, state,
                                  data_dir=data_dir, db_path=db_path)
    elif (mock and persist_fixture_state
          and result.get('_provenance', {}).get('source') == 'offline_fixture'):
        turn_id = studio.add_turn(scenario, guidance, result, state,
                                  data_dir=data_dir, db_path=db_path)
    elif should_save and trainer_turn is not None:
        turn_id = trainer_turn
    if (mock and persist_fixture_state
            and result.get('_provenance', {}).get('source') == 'offline_fixture'
            and turn_id is not None):
        with studio.connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
            db.execute('UPDATE turns SET result_json=? WHERE id=?', (json.dumps(result), turn_id))
    if should_save and approved_result is not None and not mock:
        with studio.connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
            db.execute('UPDATE turns SET result_json=? WHERE id=?', (json.dumps(result), turn_id))
    if (not mock and approved_result is not None and result.get('_trainer_approved')
            and not result.get('_trainer_pending')):
        result = dict(result)
        result['_trainer_approved'] = True
        result.pop('_trainer_pending', None)
        saved_state, _ = trainer.inspect_status(state_path=state_path, history_path=history_path)
        if saved_state is not None:
            memory.save_relationship(relationship_label, saved_state.get('emotions', dict(NEUTRAL)),
                                     data_dir=data_dir, db_path=db_path, initialize=True)
    return turn_id, state, result, corrections

def give_feedback(turn_id, rating, correction, *, data_dir=None, db_path=None):
    if turn_id is None:
        raise ValueError('A model response must be explicitly saved before feedback.')
    try:
        with studio.connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
            row = db.execute('SELECT result_json FROM turns WHERE id=?', (turn_id,)).fetchone()
    except FileNotFoundError:
        row = None
    if not row:
        raise ValueError('The training record does not exist; feedback was not saved.')
    stored_result = json.loads(row[0])
    if stored_result.get('_trainer_pending'):
        raise ValueError('Review and explicitly approve the response before saving feedback.')
    if not stored_result.get('_trainer_approved'):
        stored_result['_trainer_approved'] = True
        with studio.connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
            db.execute('UPDATE turns SET result_json=? WHERE id=?',
                       (json.dumps(stored_result), turn_id))
    if not isinstance(correction, str) or len(correction) > 4000:
        raise ValueError('Trainer correction must be at most 4000 characters.')
    if rating not in ('good', 'partial', 'poor'):
        raise ValueError('Unknown training feedback rating.')
    studio.rate_turn(turn_id, rating, correction, data_dir=data_dir, db_path=db_path)
