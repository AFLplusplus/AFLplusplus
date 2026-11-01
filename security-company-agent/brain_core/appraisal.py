"""Provider-independent emotional-state representations; never biological claims."""
from __future__ import annotations
import math
import re

EMOTIONS = ('attachment', 'anger', 'sadness', 'fear', 'hope', 'trust', 'empathy',
            'frustration', 'caution', 'assertiveness', 'emotional_regulation', 'guilt', 'jealousy')
NEUTRAL = dict.fromkeys(EMOTIONS, 0.5)
NEUTRAL.update(guilt=0.0, jealousy=0.0)

def state_emotions(values):
    """Read older state without resetting existing indexes or rewriting history."""
    return {key: values.get(key, NEUTRAL[key]) for key in EMOTIONS}

def validate_emotions(values):
    if not isinstance(values, dict) or set(values) != set(EMOTIONS):
        raise ValueError('Model must return every declared simulated emotional index.')
    for name, value in values.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError(f'Invalid simulated {name} index.')
    return {name: float(values[name]) for name in EMOTIONS}

def lexical_appraisal(text):
    """Transparent lexical prior, not inference or psychological measurement."""
    text = text.casefold()
    groups = {
        'attachment': ('love', 'attached', 'attachment', 'invested'),
        'anger': ('angry', 'anger', 'betrayal', 'betrayed'),
        'sadness': ('hurt', 'sad', 'disappointment', 'grief'),
        'fear': ('fear', 'afraid', 'losing', 'anxious'),
        'hope': ('hope', 'repair', 'reconcile', 'rebuild'),
        'trust': ('trust', 'reliable', 'honest', 'safe'),
        'empathy': ('understand', 'empathy', 'care', 'perspective'),
        'frustration': ('indecisive', 'frustrated', 'uncertain', 'conflict'),
        'caution': ('appears', 'suspect', 'evidence', 'uncertain'),
        'assertiveness': ('boundaries', 'boundary', 'assertive', 'needs'),
        'emotional_regulation': ('pause', 'reflect', 'regulate', 'calm'),
        'guilt': ('guilt', 'guilty', 'remorse', 'regret', 'guuilty'),
        'jealousy': ('jealous', 'jealousy', 'jelous', 'insecure', 'envy'),
    }
    values = {key: min(0.9, 0.15 + 0.25 * sum(bool(re.search(r'\b' + re.escape(word) + r'\b', text))
                                              for word in words)) for key, words in groups.items()}
    if any(term in text for term in ('distrust', 'no longer trust', 'not trust', 'using you')):
        values['trust'] = 0.15
    if re.search(r'\b(?:i|you) made a mistake\b', text) and re.search(r'\b(?:blamed|blaming)\b', text):
        values.update(guilt=0.8, empathy=0.65, fear=max(values['fear'],0.6))
    if re.search(r'\b(?:no evidence|without evidence) of (?:dishonesty|cheating)\b', text):
        values['trust'] = 0.65
    if re.search(r'\b(?:jealous|jealousy|jelous)\b', text):
        values.update(jealousy=0.8, fear=max(values['fear'],0.55))
    return values

offline_appraisal = lexical_appraisal  # backward-compatible name for demonstration tests

def update_emotions(previous, proposed):
    proposed = validate_emotions(proposed)
    return {name: round(0.35 * previous.get(name, NEUTRAL[name]) + 0.65 * proposed[name], 3)
            for name in EMOTIONS}
