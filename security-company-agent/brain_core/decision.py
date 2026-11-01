"""Structured recommendation contract shared by replaceable model providers."""
import math
import re
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
SCHEMA['properties']['narrative'] = dict(TEXT,description='Speak as I in a simulated personality, describing this particular situation.')
# These shared TEXT schemas need copies before attaching field-specific guidance.
for field,description in {
        'evidence':'Describe what the scenario reports happened. Do not put a proposed action here.',
        'uncertainty':'Name concrete unknown facts or consequences in a sentence. Never use none, partial or uncertainty reduction.',
        'rationale':'Explain the consequences and the relevant competing emotions, not generic autonomy slogans.'}.items():
    SCHEMA['properties']['decision']['properties'][field]=dict(TEXT,description=description)

def validate_decision(data):
    validate_schema({key:value for key,value in data.items() if not key.startswith('_')}, SCHEMA)
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

def validate_schema(value, schema):
    """Validate the small JSON-schema subset used by this contract at runtime."""
    kind=schema['type']
    if kind=='object':
        if not isinstance(value,dict) or set(value)!=set(schema['properties']):
            raise ValueError('Unexpected or missing structured fields.')
        for key,subschema in schema['properties'].items():validate_schema(value[key],subschema)
    elif kind=='array':
        if not isinstance(value,list) or not schema['minItems']<=len(value)<=schema['maxItems']:
            raise ValueError('Invalid structured list.')
        for item in value:validate_schema(item,schema['items'])
    elif kind=='string':
        if not isinstance(value,str) or not schema['minLength']<=len(value.strip())<=schema['maxLength']:
            raise ValueError('Invalid structured text.')
    elif kind=='number':
        if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value) or not schema['minimum']<=value<=schema['maximum']:
            raise ValueError('Invalid structured number.')

def validate_quality(data, scenario, *, previous=None, appraisal=None):
    """Reject obvious placeholders/copying; never substitute a preferred decision."""
    from .studio import relevance_score
    label=data['emotion'].casefold().strip()
    known=r'\b(guilt|guilty|remorse|jealousy|jealous|fear|afraid|anger|angry|sad|sadness|hope|trust|empathy|concern|concerned|curious|curiosity|anxiety|anxious|attachment|conflicted|neutral|calm|regret|frustration|hurt|shame|relief|joy|happy|grief|disappointment|insecurity|insecure|cautious)\b'
    if label in ('emotion','mixed','n/a') or re.search(r'\b(?:user_emotion|unknown|string)\b',label) or not re.search(known,label):
        raise ValueError('Emotion label is a placeholder or unrecognized affect.')
    d=data['decision']
    if not re.search(r'\b(?:I|my)\b',data['narrative'],re.I):
        raise ValueError('Use first-person simulated language.')
    if len(d['options'])<2 or len(set(x.casefold().strip() for x in d['options']))!=len(d['options']):
        raise ValueError('Provide distinct concrete alternatives.')
    for text in [*d['options'],d['recommended_action']]:
        if len(text.split())<3 or text.casefold().strip() in ('set_boundaries','seek_clarity','pause_and_regulate','explore_repair'):
            raise ValueError('An option ID is not a concrete recommendation.')
    if any(not re.search(known,item.casefold()) for item in d['conflicting_emotions']):
        raise ValueError('Competing emotion labels are not meaningful.')
    if not relevance_score(scenario,d['evidence']+' '+d['rationale']):
        raise ValueError('Evidence and rationale lack concrete scenario grounding.')
    if previous and appraisal and all(data['emotions'].get(k)==v for k,v in previous.items()) and any(
            abs(appraisal.get(k,v)-v)>.1 for k,v in previous.items()):
        raise ValueError('Unchanged copied state despite materially different appraisal; request a fresh assessment.')

def emotional_transition(result, saved_state):
    """Show distinct persisted-before, raw model proposal and persisted-after values."""
    before=result.get('_before_state',{}).get('emotions',{})
    proposed=result.get('emotions',{})
    after=saved_state.get('emotions',{})
    return [{'Emotion':name.replace('_',' ').title(),'Before':before.get(name),
             'Model proposed':proposed.get(name),'After':after.get(name)} for name in EMOTIONS]
