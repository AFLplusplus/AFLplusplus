"""Local conversational sessions and deterministic intent routing."""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass

from . import studio


@dataclass(frozen=True)
class Route:
    intent: str
    confidence: str
    reason: str


def _has_negated_training_intent(folded: str) -> bool:
    """Detect explicit denials of lesson creation before considering training cues."""
    return bool(re.search(
        r'\b(?:do not|don.t|never|not|without)\s+(?:create|make|write|teach|train|save|modify|add)\b'
        r'|\bnot\s+(?:a\s+)?(?:training|lesson|memory)\s+(?:request|submission|update)\b'
        r'|\b(?:no|without)\s+(?:new\s+)?(?:training|lesson|memory)\b', folded))


def classify_intent(text: str) -> Route:
    """Route explicit user goals before structured fields or durable draft state."""
    body = (text or '').strip()
    folded = body.casefold()
    negated_training = _has_negated_training_intent(folded)

    # A clearly requested analysis or read-only recall is never a training submission,
    # even if the request mentions memory, lesson labels, or a pending training workflow.
    analysis = bool(re.search(
        r'\b(analy[sz]e|analysis|interpret|reason(?:ing)?|what should i do|how should i|'
        r'how do i respond|what should i say|help me decide|should i|thoughtful response|'
        r'what would be a thoughtful|how should i interpret this situation)\b', folded))
    starts_teaching_workflow = bool(re.search(
        r'\b(i want to teach|brain,? i want to teach|teach you something)\b', folded)) and not negated_training
    explicit_analysis_request = bool(re.search(
        r'\b(analy[sz]e|analysis|interpret|reason(?:ing)?|how should i|what should i|'
        r'how do i respond|what should i say|help me decide|should i|thoughtful response)\b', folded))
    explicit_analysis_request = explicit_analysis_request and not starts_teaching_workflow
    lesson_question_field = bool(re.search(
        r'(?im)^\s*(?:scenario summary|emotional context|observed facts|assumptions(?: or uncertainties)?|'
        r'corrective principle|recommended response pattern)\s*:', body))
    if lesson_question_field:
        # These labels are content in a structured submission, not routing cues.
        explicit_analysis_request = bool(re.search(
            r'\b(analy[sz]e|analysis|interpret|reason(?:ing)?)\b', folded)) and not starts_teaching_workflow
    # The teaching lead-in only applies to the message that starts the workflow;
    # later labeled submissions remain training even if lesson content contains
    # a question-like phrase.
    recall = bool(re.search(
        r'\b(what do you remember|search approved memory|recall|what did i teach you|'
        r'what have i taught you|show (my )?approved lessons|retrieve (approved )?memory|'
        r'find (my )?(approved )?lesson|search (my )?approved lessons?)\b', folded))
    if recall and not analysis:
        return Route('memory_recall', 'explicit', 'Explicit read-only approved-memory retrieval request.')

    if not explicit_analysis_request and re.search(r'\b(approve|accept) (this )?(lesson|proposal)\b', folded):
        return Route('lesson_approval', 'explicit', 'Explicit approval of the current proposal.')
    if not explicit_analysis_request and re.search(r'\b(reject|decline|discard) (this )?(lesson|proposal)\b', folded):
        return Route('lesson_rejection', 'explicit', 'Explicit rejection of the current proposal.')
    if not explicit_analysis_request and re.search(r'\b(cancel|discard|abandon) (my |this |the )?(training|lesson|draft|proposal)\b', folded):
        return Route('training_cancel', 'explicit', 'Explicit request to cancel the current training draft.')
    if not explicit_analysis_request and re.search(r'\b(resume|continue) (my |this |the )?(training|lesson|draft|proposal)\b', folded):
        return Route('training_resume', 'explicit', 'Explicit request to resume the current training draft.')

    explicit_structured_submission = bool(re.search(
        r'\b(submit as a lesson|structured lesson submission|lesson fields submission)\b', folded))
    fields = extract_lesson_fields(body)
    explicit_readonly_analysis = explicit_analysis_request and (
        negated_training or (not explicit_structured_submission and not fields and not lesson_question_field))
    if explicit_readonly_analysis:
        return Route('emotional_reasoning', 'explicit', 'Explicit request to analyze or interpret a situation.')
    if explicit_analysis_request and fields and not negated_training and not lesson_question_field:
        return Route('emotional_reasoning', 'explicit', 'Explicit analysis request takes precedence over embedded lesson fields.')
    if explicit_analysis_request and explicit_structured_submission and extract_lesson_fields(body) and not negated_training:
        return Route('training', 'structured', 'User explicitly identified the labeled text as a structured lesson submission.')
    if negated_training and not re.search(r'\b(cancel|discard|abandon) (my |this |the )?(training|lesson|draft|proposal)\b', folded):
        return Route('emotional_reasoning', 'explicit', 'Training or memory changes were explicitly disallowed.')

    if re.search(r'\b(you were wrong|your interpretation was wrong|correction:|correct your|that was incorrect|you misunderstood)\b', folded):
        return Route('correction', 'explicit', 'Explicit correction wording.')
    # A field block following an explicit teaching request starts a training draft;
    # otherwise require the complete six-field record unless the text clearly isn't analysis.
    explicit_teaching = bool(re.search(r'\b(i want to teach|teach you|teach a lesson|create a lesson|submit a lesson|train you|training lesson|lesson proposal)\b', folded)) and not negated_training
    if fields and not explicit_readonly_analysis and not negated_training:
        return Route('training', 'structured', 'Recognized labeled lesson fields were supplied for supervised training.')
    if explicit_teaching and not explicit_readonly_analysis:
        return Route('training', 'explicit', 'Explicit positive teaching intent.')
    if re.search(r'\b(what (do|did) you remember|what (was|is) the lesson about|tell me about (the )?(approved )?lesson)\b', folded):
        return Route('memory_recall', 'likely', 'Question asks about previously approved memory.')
    if re.search(r'\b(search|find|look up|retrieve) (approved )?(memory|lesson|lessons)\b', folded):
        return Route('memory_recall', 'likely', 'Explicit read-only memory search request.')
    if re.search(r'\b(what happened|someone .* stopped responding|stopped responding|feels? hurt|i feel|they feel|uncertain about|interpret this)\b', folded):
        return Route('emotional_reasoning', 'likely', 'Emotional context or interpretation request.')
    if len(body.split()) <= 15 and re.search(r'\b(hello|hi|hey|good morning|good evening|how are you|thank you|thanks|who are you)\b', folded):
        return Route('general', 'likely', 'Short greeting or identity question.')
    return Route('emotional_reasoning', 'default', 'Unclassified content uses the grounded reasoning route.')


_FIELD_MAP = {
    'scenario summary': 'scenario_summary', 'scenario': 'scenario_summary',
    'emotional context': 'emotional_context', 'emotions': 'emotional_context',
    'observed facts': 'observed_facts', 'facts': 'observed_facts',
    'assumptions or uncertainties': 'assumptions_or_uncertainties',
    'assumptions/uncertainties': 'assumptions_or_uncertainties',
    'uncertainties': 'assumptions_or_uncertainties', 'assumptions': 'assumptions_or_uncertainties',
    'corrective principle': 'corrective_principle', 'principle': 'corrective_principle',
    'recommended response pattern': 'recommended_response_pattern',
    'response pattern': 'recommended_response_pattern',
    'relationship context': 'relationship_context', 'relationship': 'relationship_context',
}


def extract_lesson_fields(text):
    """Parse only recognized labeled fields, preserving their supplied text."""
    fields, current = {}, None
    # Accept a field label at the beginning of a line or after a sentence.
    # A new recognized label ends the prior value; unknown colon text is retained.
    labels = '|'.join(re.escape(label) for label in sorted(_FIELD_MAP, key=len, reverse=True))
    marker = re.compile(rf'(?i)(?<![\w/])({labels})\s*:')
    for line in (text or '').splitlines():
        matches = list(marker.finditer(line))
        if not matches:
            if current and line.strip():
                fields[current].append(line.strip())
            continue
        prefix = line[:matches[0].start()].strip()
        if prefix and current:
            fields[current].append(prefix)
        for index, match in enumerate(matches):
            key = _FIELD_MAP[match.group(1).casefold()]
            fields.setdefault(key, [])
            current = key
            start = match.end()
            end = matches[index + 1].start() if index + 1 < len(matches) else len(line)
            value = line[start:end].strip()
            if value:
                fields[key].append(value)
    return {key: '\n'.join(values).strip() for key, values in fields.items()}


def lesson_fields_complete(fields):
    required = ('scenario_summary', 'emotional_context', 'observed_facts',
                'assumptions_or_uncertainties', 'corrective_principle',
                'recommended_response_pattern')
    return all(fields.get(key, '').strip() for key in required)


def missing_lesson_fields(fields):
    labels = {
        'scenario_summary': 'Scenario summary',
        'emotional_context': 'Emotional context',
        'observed_facts': 'Observed facts',
        'assumptions_or_uncertainties': 'Assumptions or uncertainties',
        'corrective_principle': 'Corrective principle',
        'recommended_response_pattern': 'Recommended response pattern',
    }
    return [label for key, label in labels.items() if not fields.get(key, '').strip()]


def prepare_lesson(text, *, existing=None):
    from . import lessons
    fields = dict(existing or {})
    fields.update(extract_lesson_fields(text))
    if not lesson_fields_complete(fields):
        return None, fields
    proposal = lessons.propose(
        scenario=fields['scenario_summary'], corrective_principle=fields['corrective_principle'],
        emotional_context=fields['emotional_context'], observed_facts=fields['observed_facts'],
        uncertainties=fields['assumptions_or_uncertainties'],
        response_pattern=fields['recommended_response_pattern'],
        relationship_context=fields.get('relationship_context', ''))
    return proposal, fields


def _ensure_chat_schema(db):
    db.execute('''CREATE TABLE IF NOT EXISTS conversations (
        conversation_id TEXT PRIMARY KEY, title TEXT NOT NULL,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS conversation_messages (
        message_id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('user','assistant','system')),
        created_at TEXT NOT NULL, content TEXT NOT NULL,
        message_type TEXT NOT NULL, related_lesson_id TEXT,
        inference_status TEXT NOT NULL DEFAULT 'not_applicable',
        FOREIGN KEY(conversation_id) REFERENCES conversations(conversation_id) ON DELETE CASCADE)''')
    db.execute('CREATE INDEX IF NOT EXISTS idx_messages_conversation ON conversation_messages(conversation_id,created_at)')
    db.execute('''CREATE TABLE IF NOT EXISTS conversation_lesson_state (
        conversation_id TEXT PRIMARY KEY REFERENCES conversations(conversation_id) ON DELETE CASCADE,
        state_json TEXT NOT NULL, updated_at TEXT NOT NULL)''')


def create_session(title='New conversation', *, data_dir=None, db_path=None):
    studio.initialize_store(data_dir=data_dir, db_path=db_path)
    session_id = str(uuid.uuid4())
    with studio.connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
        _ensure_chat_schema(db)
        now = studio.now()
        db.execute('INSERT INTO conversations(conversation_id,title,created_at,updated_at) VALUES(?,?,?,?)',
                   (session_id, (title or 'New conversation')[:120], now, now))
    return session_id


def _target(data_dir, db_path):
    return studio.Path(db_path) if db_path is not None else (studio.Path(data_dir) / 'brain.sqlite3' if data_dir is not None else studio.DB)


def save_lesson_state(conversation_id, state, *, data_dir=None, db_path=None):
    """Persist only the reviewable proposal/workflow state in the shared studio DB."""
    if state is not None and not isinstance(state, dict):
        raise ValueError('Lesson state must be a mapping or None.')
    with studio.connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
        _ensure_chat_schema(db)
        if not db.execute('SELECT 1 FROM conversations WHERE conversation_id=?', (conversation_id,)).fetchone():
            raise ValueError('Conversation does not exist.')
        if state is None:
            db.execute('DELETE FROM conversation_lesson_state WHERE conversation_id=?', (conversation_id,))
        else:
            db.execute('''INSERT INTO conversation_lesson_state(conversation_id,state_json,updated_at)
                          VALUES(?,?,?) ON CONFLICT(conversation_id) DO UPDATE SET
                          state_json=excluded.state_json,updated_at=excluded.updated_at''',
                       (conversation_id, studio.json.dumps(state, ensure_ascii=False), studio.now()))


def load_lesson_state(conversation_id, *, data_dir=None, db_path=None):
    if not _target(data_dir, db_path).exists():
        return None
    with studio.connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
        _ensure_chat_schema(db)
        row = db.execute('SELECT state_json FROM conversation_lesson_state WHERE conversation_id=?',
                         (conversation_id,)).fetchone()
    return studio.json.loads(row[0]) if row else None


def list_sessions(*, data_dir=None, db_path=None, limit=100):
    if not _target(data_dir, db_path).exists():
        return []
    with studio.connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='conversations'").fetchone():
            return []
        return [dict(zip(('conversation_id','title','created_at','updated_at','message_count'), row))
                for row in db.execute('''SELECT c.conversation_id,c.title,c.created_at,c.updated_at,
                    (SELECT COUNT(*) FROM conversation_messages m WHERE m.conversation_id=c.conversation_id)
                    FROM conversations c ORDER BY c.updated_at DESC LIMIT ?''', (limit,))]


def save_message(conversation_id, role, content, *, message_type='chat', related_lesson_id=None,
                 inference_status='not_applicable', message_id=None, data_dir=None, db_path=None):
    if role not in ('user', 'assistant', 'system') or not isinstance(content, str) or len(content) > 16000:
        raise ValueError('Invalid message.')
    msg_id = message_id or str(uuid.uuid4())
    with studio.connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
        _ensure_chat_schema(db)
        if not db.execute('SELECT 1 FROM conversations WHERE conversation_id=?', (conversation_id,)).fetchone():
            raise ValueError('Conversation does not exist.')
        db.execute('INSERT OR IGNORE INTO conversation_messages(message_id,conversation_id,role,created_at,content,message_type,related_lesson_id,inference_status) VALUES(?,?,?,?,?,?,?,?)',
                   (msg_id, conversation_id, role, studio.now(), content, message_type, related_lesson_id, inference_status))
        db.execute('UPDATE conversations SET updated_at=? WHERE conversation_id=?', (studio.now(), conversation_id))
    return msg_id


def load_messages(conversation_id, *, data_dir=None, db_path=None):
    if not _target(data_dir, db_path).exists():
        return []
    with studio.connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='conversation_messages'").fetchone():
            return []
        rows = db.execute('SELECT message_id,role,created_at,content,message_type,related_lesson_id,inference_status FROM conversation_messages WHERE conversation_id=? ORDER BY rowid', (conversation_id,)).fetchall()
    keys = ('message_id','role','created_at','content','message_type','related_lesson_id','inference_status')
    return [dict(zip(keys, row)) for row in rows]


def rename_session(conversation_id, title, *, data_dir=None, db_path=None):
    with studio.connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
        changed = db.execute('UPDATE conversations SET title=?,updated_at=? WHERE conversation_id=?',
                             (title[:120], studio.now(), conversation_id)).rowcount
        if not changed:
            raise ValueError('Conversation does not exist.')


def delete_session(conversation_id, *, confirmed=False, data_dir=None, db_path=None):
    if confirmed is not True:
        raise ValueError('Explicit confirmation is required to delete conversation history.')
    with studio.connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
        changed = db.execute('DELETE FROM conversations WHERE conversation_id=?', (conversation_id,)).rowcount
        if not changed:
            raise ValueError('Conversation does not exist.')


def respond_general(text, profile):
    folded = text.casefold()
    if re.search(r'\b(how are you|how do you feel)\b', folded):
        return 'I do not have feelings or consciousness. I can help you think through what is happening and distinguish facts from uncertainties.'
    if re.search(r'\b(who are you|hello|hi|hey|good morning|good evening)\b', folded):
        return f"Hello. I am {profile.get('identity_name', 'Sovereign Brain')}. I am here to help you reflect carefully. I do not have personal feelings, but I can discuss emotional situations based on what you tell me."
    return 'I can help reflect on that. What would you like to explore?'
