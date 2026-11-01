"""Streamlit-independent training service: references, feedback, state and storage."""
from . import trainer, studio

def analyze(scenario, guidance='', *, mock=False, config=None, use_references=False,
            use_feedback=True):
    references = studio.relevant_context(scenario, max_chars=2500) if use_references else ''
    corrections = studio.feedback_context(scenario) if use_feedback else []
    state, result = trainer.train(scenario, guidance, mock=mock, config=config,
                                  reference_context=references, past_feedback=corrections)
    turn_id = studio.add_turn(scenario, guidance, result, state)
    return turn_id, state, result, corrections

def give_feedback(turn_id, rating, correction):
    if not isinstance(correction, str) or len(correction) > 4000:
        raise ValueError('Trainer correction must be at most 4000 characters.')
    studio.rate_turn(turn_id, rating, correction)
