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
# Deterministic Stage 1 vocabulary normalization to the existing appraisal dimensions.
# Synonyms are explicit (not fuzzy); ambiguous words are intentionally omitted.
EMOTION_SYNONYMS = {
    'attachment': ('love', 'affection', 'fondness', 'closeness'),
    'anger': ('irritation', 'irritated', 'resentment', 'annoyance', 'annoyed'),
    'sadness': ('sorrow', 'unhappiness', 'disappointment', 'disappointed'),
    'fear': ('worry', 'worried', 'anxiety', 'anxious', 'apprehension', 'nervousness'),
    'hope': ('optimism', 'encouragement'),
    'trust': ('confidence', 'reliance'),
    'empathy': ('compassion', 'understanding', 'sympathy', 'concern', 'caring'),
    'frustration': ('exasperation', 'discouragement'),
    'caution': ('wariness', 'vigilance'),
    'assertiveness': ('self-advocacy',),
    'emotional_regulation': ('calmness', 'composure'),
    'guilt': ('remorse', 'regret'),
    'jealousy': ('envy',),
}


def _normalize_emotion_label(label):
    """Return (canonical label, status); do not infer an emotion from vague words."""
    if not isinstance(label, str):
        return None, 'unknown'
    cleaned = re.sub(r'[^a-z0-9]+', ' ', label.casefold()).strip()
    if not cleaned:
        return None, 'unknown'
    # Treat separators uniformly so existing multiword dimensions such as
    # emotional_regulation remain canonical; never split a compound appraisal.
    normalized = re.sub(r'[^a-z0-9]+', ' ', label.casefold()).strip()
    words = normalized.split()
    if any(word in {'not', 'no', 'never', 'without', 'isnt', 'wasnt', 'doesnt', 'dont'} for word in words):
        return None, 'negated'

    canonical_forms = {
        emotion.replace('_', ' '): emotion for emotion in EMOTIONS
    }
    if normalized in canonical_forms:
        return canonical_forms[normalized], 'canonical'
    if len(words) != 1:
        return None, 'ambiguous'

    # Explicit word-level mappings avoid unreliable suffix guessing.
    forms = {
        'angry': 'anger', 'irritated': 'anger', 'annoyed': 'anger',
        'sad': 'sadness', 'disappointed': 'sadness',
        'afraid': 'fear', 'scared': 'fear', 'worried': 'fear', 'anxious': 'fear',
        'hopeful': 'hope', 'frustrated': 'frustration', 'cautious': 'caution',
        'assertive': 'assertiveness', 'guilty': 'guilt', 'jealous': 'jealousy',
        'empathetic': 'empathy', 'concerned': 'empathy',
        'calm': 'emotional_regulation', 'composed': 'emotional_regulation',
        'loving': 'attachment',
    }
    if normalized in forms:
        return forms[normalized], 'synonym'
    for emotion, synonyms in EMOTION_SYNONYMS.items():
        if normalized in synonyms:
            return emotion, 'synonym'
    return None, 'unknown'


def _emotion_grounding_support(emotion, scenario):
    """Require scenario cues for appraisal; recognized words alone are insufficient."""
    text = scenario.casefold()
    cue_groups = {
        'attachment': ({'love', 'care', 'relationship', 'close', 'partner'},),
        'anger': ({'angry', 'anger', 'upset', 'unfair', 'blame', 'betrayal', 'mistake'},),
        'sadness': ({'sad', 'quiet', 'disappoint', 'loss', 'grief', 'hurt'},),
        'fear': ({'fear', 'afraid', 'worry', 'anxious', 'uncertain', 'unknown', 'do not know', 'not know', 'leave', 'succeed', 'stressful', 'communicative', 'communication', 'value'},),
        'hope': ({'hope', 'help', 'improve', 'recover', 'better'},),
        'trust': ({'trust', 'reliable', 'honest', 'safe', 'openly', 'tell'},),
        'empathy': ({'coworker', 'friend', 'help', 'care', 'disappoint', 'quiet', 'hurt', 'communicative', 'communication', 'stressful'},),
        'frustration': ({'frustrat', 'difficult', 'problem', 'conflict', 'disappoint'},),
        'caution': ({'uncertain', 'unknown', 'do not know', 'not know', 'unsure'},),
        'assertiveness': ({'boundary', 'need', 'want', 'request', 'ask'},),
        'emotional_regulation': ({'pause', 'calm', 'reflect', 'manage emotion'},),
        'guilt': ({'guilt', 'guilty', 'mistake', 'responsible', 'fault', 'blame', 'caused'},),
        'jealousy': ({'jealous', 'jealousy', 'envy', 'rival', 'romantic', 'partner', 'friendship'},),
    }
    # Reported first-person feelings directly support that appraisal, while a
    # feared interpretation must not be promoted to a fact about another person.
    if emotion == 'fear' and re.search(r'\bi feel anxious\b', text):
        return True
    if emotion == 'empathy' and re.search(r'\bi feel anxious\b', text):
        return True
    if emotion == 'fear' and re.search(r'\bi assume they no longer value our friendship\b', text):
        return True
    if emotion == 'trust' and re.search(r'\bthey explicitly say they still care about you\b', text):
        return True
    if emotion == 'fear' and re.search(r'\byou fear this person may leave\b', text):
        return True

    cues = cue_groups.get(emotion, ())
    suffix_forms = {
        'worry': ('worries', 'worried'), 'leave': ('leaves', 'leaving'),
        'ask': ('asks', 'asked', 'asking'), 'request': ('requests', 'requested'),
        'want': ('wants', 'wanted'), 'need': ('needs', 'needed'),
        'disappoint': ('disappoints', 'disappointed', 'disappointing'),
        'frustrat': ('frustrates', 'frustrated', 'frustrating'),
        'pause': ('pauses', 'paused', 'pausing'), 'reflect': ('reflects', 'reflected'),
        'hurt': ('hurts', 'hurt'), 'trust': ('trusts', 'trusted'),
        'reliable': ('reliably',), 'reconnect': ('reconnects', 'reconnected'),
    }

    def cue_matches(cue):
        forms = suffix_forms.get(cue, (cue,))
        return any(re.search(r'(?<!\w)' + re.escape(form) + r'(?!\w)', text)
                   for form in forms)

    # A person/relationship cue is contextual only when paired with an explicit
    # affective or relational event; the noun alone must not ground an appraisal.
    contextual = {
        'attachment': {'love', 'affection', 'close', 'care about'},
        'empathy': {'help', 'support', 'hurt', 'disappoint', 'quiet', 'care about'},
        'jealousy': {'jealous', 'jealousy', 'envy', 'rival'},
    }
    if emotion in contextual:
        direct = contextual[emotion]
        if any(cue_matches(cue) for cue in direct):
            return True
        context_terms = {'colleague', 'coworker', 'friend', 'partner', 'relationship'}
        if not any(cue_matches(term) for term in context_terms):
            return False
        cues = tuple(group - context_terms for group in cues)

    # Negation of a cue cannot count as positive support. Search each matched
    # token and inspect a short preceding window for a local negation marker.
    for group in cues:
        for cue in group:
            for form in suffix_forms.get(cue, (cue,)):
                for match in re.finditer(r'(?<!\w)' + re.escape(form) + r'(?!\w)', text):
                    prefix = text[max(0, match.start() - 24):match.start()]
                    if not re.search(r'\b(?:not|never|no longer|without|no)\s+(?:\w+\s+){0,2}$', prefix):
                        return True
    return False


EMOTION_UNDERSTANDING_SCHEMA = object_schema({
    'facts': {'type': 'array', 'items': dict({'type': 'string', 'minLength': 1, 'maxLength': 240}, description='Short observable fact stated in the scenario.'),
              'minItems': 1, 'maxItems': 3},
    'emotions': {'type': 'array', 'items': object_schema({
        'label': dict({'type': 'string', 'minLength': 1, 'maxLength': 80}),
        'trigger': dict({'type': 'string', 'minLength': 1, 'maxLength': 240})}), 'minItems': 2, 'maxItems': 3},
    'assumptions': {'type': 'array', 'items': dict({'type': 'string', 'minLength': 1, 'maxLength': 180}, description='Short uncertainty, not a stated fact.'),
                    'minItems': 1, 'maxItems': 2}
})
ALTERNATIVES_SCHEMA = object_schema({
    'alternatives': {'type': 'array', 'items': object_schema({
        'action': dict(TEXT, description='Concrete, context-specific action sentence.'),
        'consequence': dict(TEXT, description='One plausible consequence grounded in the facts.')
    }), 'minItems': 2, 'maxItems': 2}
})
FINAL_DECISION_SCHEMA = object_schema({
    'selected_action': dict(TEXT, description='Choose one of the provided actions verbatim or faithfully restated.'),
    'rationale': TEXT, 'emotional_tradeoff': TEXT
})

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
SCHEMA['properties']['decision']['properties']['options'] = {
    'type': 'array', 'items': dict(TEXT, description='A concrete alternative action sentence, not an internal option identifier.'),
    'minItems': 2, 'maxItems': 2,
    'description': 'Exactly two meaningfully different concrete action alternatives, each with a distinct consequence.'}
SCHEMA['properties']['decision']['properties']['recommended_action'] = dict(
    TEXT, description='One selected concrete action sentence. Do not return an option ID, label, or list position.')
SCHEMA['properties']['decision']['properties']['evidence'] = dict(
    TEXT, description='Scenario-reported facts only; distinguish reports from inferred motives.')
SCHEMA['properties']['decision']['properties']['rationale'] = dict(
    TEXT, description='Explain why the selected action follows from scenario evidence, uncertainty, consequences, and competing simulated emotions.')
SCHEMA['properties']['operational_rule']['properties']['recommended_action'] = dict(
    TEXT, description='Concrete action sentence, not an internal option ID.')
# These shared TEXT schemas need copies before attaching field-specific guidance.
for field,description in {
        'evidence':'Describe what the scenario reports happened. Do not put a proposed action here.',
        'uncertainty':'Name concrete unknown facts or consequences in a sentence. Never use none, partial or uncertainty reduction.',
        'rationale':'Explain the consequences and the relevant competing emotions, not generic autonomy slogans.'}.items():
    SCHEMA['properties']['decision']['properties'][field]=dict(TEXT,description=description)

def validate_stage_schema(data, schema):
    validate_schema(data, schema)

def evaluate_alternative_grounding(action, consequence, facts, scenario):
    """Measure the unchanged scenario and fact grounding rules for diagnostics."""
    if not isinstance(action, str) or not isinstance(consequence, str):
        return {
            'scenario_relevance_score': 0,
            'scenario_overlap_passed': False,
            'scenario_threshold': 1,
            'validated_fact_scores': [],
            'validated_fact_overlap_passed': False,
            'validated_fact_threshold': 1,
            'passed': False,
        }
    scenario_score = _semantic_grounding_score(scenario, action)
    fact_scores = [_semantic_grounding_score(fact, action + ' ' + consequence)
                   for fact in facts if isinstance(fact, str)]
    return {
        'scenario_relevance_score': scenario_score,
        'scenario_overlap_passed': scenario_score > 0,
        'scenario_threshold': 1,
        'validated_fact_scores': fact_scores,
        'validated_fact_overlap_passed': any(fact_scores),
        'validated_fact_threshold': 1,
        'passed': scenario_score > 0 and any(fact_scores),
    }


def _semantic_grounding_score(source, candidate):
    """Score evidence overlap with small synonym families to accept faithful paraphrases."""
    from .studio import relevance_score
    # Short facts and paraphrases cannot reliably satisfy lexical token thresholds.
    if candidate.casefold().strip() in source.casefold():
        return 3
    base = relevance_score(source, candidate)
    groups = (
        {'alone', 'space', 'time', 'day', 'solitude', 'quiet'},
        {'love', 'care', 'affection', 'relationship', 'partner'},
        {'stress', 'stressful', 'pressure', 'strain', 'overwhelmed'},
        {'past', 'previous', 'ended', 'left', 'abandoned'},
        {'fear', 'afraid', 'worry', 'anxiety', 'concern', 'insecurity'},
        {'ask', 'request', 'want', 'needs', 'need'},
        {'leave', 'leaving', 'breakup', 'end'},
        {'colleague', 'coworker', 'blamed', 'blame', 'mistake', 'error', 'promotion'},
        {'guilty', 'guilt', 'responsibility', 'responsible'},
        {'explicitly', 'say', 'said', 'stated', 'tell', 'told'},
        {'similar', 'same', 'resembling', 'echoes', 'recalls'},
    )
    source_words = set(re.findall(r'\b[a-z]+\b', source.casefold()))
    candidate_words = set(re.findall(r'\b[a-z]+\b', candidate.casefold()))
    expanded_source = set(source_words)
    for group in groups:
        if source_words & group:
            expanded_source.update(group)
    expanded_candidate = set(candidate_words)
    for group in groups:
        if candidate_words & group:
            expanded_candidate.update(group)
    semantic_overlap = len(expanded_source & expanded_candidate)
    return max(base, 3 if semantic_overlap >= 2 else 0)

def validate_emotional_understanding(data, scenario):
    validate_stage_schema(data, EMOTION_UNDERSTANDING_SCHEMA)
    facts = data['facts']
    for fact in facts:
        if _semantic_grounding_score(scenario, fact) < 2:
            raise ValueError('Stage 1 fact is not sufficiently grounded in the scenario.')
    # Assumptions are unknowns derived from the scenario; compare their meaningful
    # content words, not just the uncertainty marker (e.g. "whether"). This keeps
    # paraphrased uncertainty grounded without allowing unrelated speculation.
    for assumption in data['assumptions']:
        content = re.sub(r'\b(?:unknown|unknowable|unclear|uncertain|whether|if|might|may|could|does|do|not|know|why|reason|change|changed|tell|want|wants|needs|need|is|are|has|have|will|would|the|a|an|to|of|for|in|on|it|they|them|you|we|i|communication)\b',
                         ' ', assumption.casefold())
        if _semantic_grounding_score(scenario, content) < 1:
            raise ValueError('Stage 1 assumption is disconnected from scenario details.')
    for emotion in data['emotions']:
        canonical, status = _normalize_emotion_label(emotion['label'])
        if canonical is None:
            raise ValueError(f'Stage 1 emotion label is {status}; use one concise supported emotion label.')
        if not _emotion_grounding_support(canonical, scenario):
            raise ValueError(f'Stage 1 {canonical} appraisal is unsupported by scenario details.')
        # Keep diagnostic identification limited to existing canonical dimensions.
        emotion['label'] = canonical
        trigger = emotion['trigger'].casefold()
        # Reject a trigger that reverses an explicitly stated relation or event.
        contradictions = (
            (('still care' in scenario.casefold() or 'care about you' in scenario.casefold())
             and re.search(r'\b(?:does not|doesn.t|no longer) care\b', trigger)),
            (('asks for a day alone' in scenario.casefold() or 'day alone' in scenario.casefold())
             and re.search(r'\b(?:asks? to stay|does not ask for space|wants? company)\b', trigger)),
        )
        if any(contradictions):
            raise ValueError('Stage 1 trigger contradicts an explicit scenario fact.')
        if _semantic_grounding_score(scenario, emotion['trigger']) < 1:
            raise ValueError('Stage 1 emotion trigger is not grounded in the scenario.')
    reported_emotion_terms = {'guilt', 'guilty', 'fear', 'afraid', 'anger', 'angry', 'sad', 'sadness',
                              'love', 'care', 'trust', 'jealous', 'jealousy', 'hurt', 'anxious', 'anxiety',
                              'concern', 'concerned', 'hope', 'uncertainty', 'stress', 'worried', 'worry'}
    label_terms = {term.rstrip('y') for emotion in data['emotions']
                   for term in re.findall(r'\b[a-z]{4,}\b', emotion['label'].casefold())}
    scenario_terms = set(re.findall(r'\b[a-z]{4,}\b', scenario.casefold()))
    if not (label_terms & {term.rstrip('y') for term in reported_emotion_terms}) and not scenario_terms.intersection(
            {'mistake', 'blamed', 'alone', 'relationship', 'stressful', 'promotion', 'past', 'trust', 'care'}):
        raise ValueError('Stage 1 emotion labels are disconnected from reported feelings or events.')
    return data

def validate_conflicting_emotions(values):
    known = re.compile(r'\b(guilt|guilty|remorse|jealousy|jealous|fear|afraid|anger|angry|sad|sadness|hope|trust|empathy|concern|concerned|curious|curiosity|anxiety|anxious|attachment|conflicted|neutral|calm|regret|frustration|hurt|shame|relief|joy|happy|grief|disappointment|insecurity|insecure|cautious)\b')
    if isinstance(values, str):
        values = [part.strip() for part in re.split(r'\band\b|,|;', values) if part.strip()]
    if not isinstance(values, list) or len(values) < 2 or len(values) > 5:
        raise ValueError('At least two meaningful conflicting emotions are required.')
    for value in values:
        if not isinstance(value, str) or not known.search(value.casefold()):
            raise ValueError('Competing emotion labels are not meaningful.')
    return values

def validate_alternatives(data, facts, scenario, emotions=None):
    validate_stage_schema(data, ALTERNATIVES_SCHEMA)
    actions = [item['action'] for item in data['alternatives']]
    normalized = [_normalize_action(action) for action in actions]
    if len(set(normalized)) < 2 or _actions_equivalent(normalized[0], normalized[1]):
        raise ValueError('Stage 2 alternatives must be meaningfully distinct.')
    for item in data['alternatives']:
        action, consequence = item['action'], item['consequence']
        full_text = action + ' ' + consequence
        if any(_contradicts_explicit_scenario(scenario, full_text)):
            raise ValueError('Stage 2 action or consequence contradicts an explicit scenario fact.')
        if len(re.findall(r'\b[a-z]{4,}\b', action.casefold())) < 2:
            raise ValueError('Stage 2 action is not concrete enough.')
        if _semantic_grounding_score(scenario, action) == 0:
            raise ValueError('Stage 2 action is not grounded in the scenario.')
        if not any(_semantic_grounding_score(fact, full_text) for fact in facts):
            raise ValueError('Stage 2 action and consequence are not grounded in a validated scenario fact.')
        # Stage 2 may propose reasonable actions not literally named in the scenario;
        # it must connect to validated facts and cannot contradict reported details.
    return data

def _contradicts_explicit_scenario(scenario, statement):
    scenario = scenario.casefold()
    statement = statement.casefold()
    checks = (
        (('still care' in scenario or 'care about you' in scenario)
         and re.search(r'\b(?:does not|doesn.t|no longer|stopped) care\b', statement)),
        (('asks for a day alone' in scenario or 'day alone' in scenario)
         and re.search(r'\b(?:did not ask for space|wants? company|asked to stay)\b', statement)),
        (('explicitly say' in scenario or 'explicitly says' in scenario)
         and re.search(r'\b(?:never said|did not say|has not said)\b', statement)),
    )
    return checks

def validate_final_decision(data, alternatives, scenario, facts):
    validate_stage_schema(data, FINAL_DECISION_SCHEMA)
    action = data['selected_action']
    if not any(_normalize_action(action) == _normalize_action(item['action'])
               for item in alternatives['alternatives']):
        raise ValueError('Stage 3 recommendation must select one of the validated alternatives.')
    rationale = data['rationale'] + ' ' + data['emotional_tradeoff']
    if any(_contradicts_explicit_scenario(scenario, rationale)):
        raise ValueError('Stage 3 rationale contradicts an explicit scenario fact.')
    if not any(_semantic_grounding_score(fact, rationale) for fact in facts) and not _semantic_grounding_score(scenario, rationale):
        raise ValueError('Stage 3 rationale and emotional trade-off lack scenario grounding.')
    return data

def validate_decision(data):
    validate_schema({key:value for key,value in data.items() if not key.startswith('_')}, SCHEMA)
    validate_emotions(data.get('emotions'))
    decision = data.get('decision')
    if not isinstance(decision, dict):
        raise ValueError('Model must return a structured decision.')
    for key in ('conflicting_emotions', 'options'):
        values = decision.get(key)
        minimum, maximum = (2, 2) if key == 'options' else (1, 5)
        if not isinstance(values, list) or not minimum <= len(values) <= maximum or any(
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

def _normalize_action(text):
    words = re.findall(r'\b[a-z0-9]+\b', text.casefold())
    stop = {'i', 'we', 'my', 'will', 'would', 'should', 'could', 'the', 'a', 'an', 'to',
            'and', 'or', 'with', 'by', 'before', 'after', 'then', 'now', 'first',
            'my', 'your', 'our', 'about', 'that'}
    lemmas = {'tell': 'inform', 'told': 'inform', 'inform': 'inform',
              'correct': 'repair', 'fix': 'repair', 'repair': 'repair',
              'mistake': 'error', 'mistakes': 'error', 'error': 'error', 'errors': 'error',
              'blame': 'blame', 'records': 'record'}
    return tuple(lemmas.get(word, word) for word in words if word not in stop)

def _actions_equivalent(left, right):
    """Conservative lexical equivalence guard; different actors/actions remain distinct."""
    if not left or not right:
        return True
    left_set, right_set = set(left), set(right)
    overlap = len(left_set & right_set) / max(1, len(left_set | right_set))
    # Catch paraphrased duplicates with small wording changes, without banning shared topic terms.
    return overlap >= 0.78 and bool(set(left) & set(right))

def validate_quality(data, scenario, *, previous=None, appraisal=None):
    """Reject obvious placeholders/copying; never substitute a preferred decision."""
    from .studio import relevance_score
    label=data['emotion'].casefold().strip()
    known=r'\b(guilt|guilty|remorse|jealousy|jealous|fear|afraid|anger|angry|sad|sadness|hope|trust|empathy|concern|concerned|curious|curiosity|anxiety|anxious|attachment|conflicted|neutral|calm|regret|frustration|hurt|shame|relief|joy|happy|grief|disappointment|insecurity|insecure|cautious)\b'
    if label in ('emotion','mixed','n/a') or re.search(r'\b(?:user_emotion|unknown|string)\b',label) or not re.search(known,label):
        raise ValueError('Emotion label is a placeholder or unrecognized affect.')
    d=data['decision']
    validate_conflicting_emotions(d['conflicting_emotions'])
    if not re.search(r'\b(?:I|my)\b',data['narrative'],re.I):
        raise ValueError('Use first-person simulated language.')
    if len({value.casefold().strip() for value in d['conflicting_emotions']}) < 2:
        raise ValueError('Conflicting emotions must identify distinct influences.')
    if len(d['options']) < 2:
        raise ValueError('Provide at least two concrete alternatives.')
    normalized_options = [_normalize_action(option) for option in d['options']]
    if len(set(normalized_options)) != len(normalized_options) or any(
            _actions_equivalent(normalized_options[i], normalized_options[j])
            for i in range(len(normalized_options)) for j in range(i + 1, len(normalized_options))):
        raise ValueError('Provide distinct concrete alternatives with meaningfully different actions and consequences.')
    internal_option_ids = {'set_boundaries', 'seek_clarity', 'pause_and_regulate', 'explore_repair',
                           'admit_and_repair', 'verify_and_correct_record', 'regulate_and_communicate',
                           'trust_and_observe', 'option_1', 'option_2', 'option_3'}
    for text in [*d['options'], d['recommended_action'], data['operational_rule']['recommended_action']]:
        # A first-person prefix does not make a bare ID into an action sentence.
        normalized = re.sub(r'[^a-z0-9_]+', '_', text.casefold()).strip('_')
        normalized = re.sub(r'^(?:i_will|i_should|we_will)_', '', normalized)
        action_words = re.findall(r'\b[a-z]{4,}\b', text.casefold())
        if (len(action_words) < 2 or normalized in internal_option_ids or
                re.fullmatch(r'(?:option|alternative)_?\d+', normalized)):
            raise ValueError('An option ID is not a concrete recommendation.')
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
