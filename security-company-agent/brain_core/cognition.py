"""Transparent pre-decision simulation; deterministic preferences, no execution authority."""
from .appraisal import lexical_appraisal, NEUTRAL

def assess(scenario, profile, temporary_state, *, relationship_state=None, experiences=None):
    """Keep stable traits, current appraisal and relationship memory in distinct fields.

    Scores are inspectable engineering heuristics, not validated psychology. A model
    reviews them alongside evidence before producing its recommendation.
    """
    traits = profile['traits']
    prior = temporary_state.get('emotions', NEUTRAL)
    cues = lexical_appraisal(scenario)
    relation = relationship_state or {}
    emotions = {key: round(0.2 * prior.get(key, 0.5) + 0.7 * cues[key] +
                           0.1 * relation.get(key, prior.get(key, 0.5)), 4) for key in NEUTRAL}
    return build_context(profile, prior, relation, emotions, experiences or [])

def build_context(profile, prior, relationship, emotions, experiences):
    t, e = profile['traits'], emotions
    # Emotion contributions participate in ranking BEFORE the model is called.
    contributions = {
        'seek_clarity': {'traits': .25*t['curiosity'] + .2*t['conscientiousness'],
                         'emotions': .25*e['caution'] + .2*(1-e['trust']) + .1*e['hope']},
        'set_boundaries': {'traits': .15*t['conscientiousness'] + .1*(1-t['risk_tolerance']),
                           'emotions': .3*e['anger'] + .25*e['assertiveness'] + .2*e['frustration']},
        'pause_and_regulate': {'traits': .25*t['emotional_stability'] + .15*t['empathy_orientation'],
                               'emotions': .25*e['fear'] + .2*e['sadness'] + .15*(1-e['emotional_regulation'])},
        'explore_repair': {'traits': .2*t['agreeableness'] + .15*t['openness'],
                           'emotions': .25*e['attachment'] + .2*e['empathy'] + .2*e['hope']},
    }
    preferences = sorted([{'option': key, 'score': round(sum(parts.values()),4),
                            'trait_contribution': round(parts['traits'],4),
                            'emotion_contribution': round(parts['emotions'],4)}
                           for key, parts in contributions.items()], key=lambda item:item['score'],reverse=True)
    return {'method': 'deterministic lexical prior and weighted preferences; not validated psychology',
            'stable_identity_id': profile['identity_id'], 'stable_traits': dict(t),
            'previous_temporary_emotions': dict(prior), 'relationship_emotions': dict(relationship),
            'appraised_emotions_before_decision': emotions, 'previous_experiences': experiences,
            'evidence_policy': 'Scenario statements are reported claims; appearance and suspicion are not verified facts.',
            'competing_motivations': ['attachment and possible repair', 'self-protection and boundaries',
                                      'uncertainty reduction', 'emotional regulation and autonomy'],
            'decision_preferences': preferences,
            'authority': 'recommendation only; emotions and personality never authorize external actions'}
