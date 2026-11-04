"""Human-supervised emotional lessons stored in the local studio database.

Lessons are deterministic records: this module does not infer facts, call a model,
write simulated affective state, or modify the persistent personality.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
import uuid
from datetime import datetime, timezone

from . import studio

MAX_FIELD = 4000
MAX_SUMMARY = 800


def _text(value, name, limit=MAX_FIELD, *, required=False):
    if not isinstance(value, str):
        raise ValueError(f'{name} must be text.')
    value = value.strip()
    if required and not value:
        raise ValueError(f'{name} is required.')
    if len(value) > limit:
        raise ValueError(f'{name} must be at most {limit} characters.')
    return value


def _tokens(text):
    return set(re.findall(r'\b[a-z0-9]{4,}\b', text.casefold())) - {
        'this', 'that', 'with', 'from', 'have', 'your', 'about', 'they',
        'them', 'were', 'what', 'when', 'where', 'which', 'should', 'would',
        'could', 'their', 'there', 'being', 'been', 'into', 'because',
    }


def propose(*, scenario, corrective_principle, emotional_context='', observed_facts='',
            uncertainties='', response_pattern='', relationship_context=''):
    """Assemble a reviewable lesson using only fields supplied by the trainer."""
    scenario = _text(scenario, 'Scenario summary', MAX_SUMMARY, required=True)
    principle = _text(corrective_principle, 'Corrective principle', required=True)
    record = {
        'lesson_id': str(uuid.uuid4()),
        'created_at': datetime.now(timezone.utc).isoformat(),
        'source_type': 'human_supervised',
        'source_provenance': 'trainer_entered',
        'scenario_summary': scenario,
        'emotional_context': _text(emotional_context, 'Emotional context'),
        'observed_facts': _text(observed_facts, 'Observed facts'),
        'assumptions_or_uncertainties': _text(uncertainties, 'Assumptions or uncertainties'),
        'corrective_principle': principle,
        'recommended_response_pattern': _text(response_pattern, 'Recommended response pattern'),
        'relationship_context': _text(relationship_context, 'Relationship context', 300),
        'approval_status': 'proposed',
    }
    return record


def _validate(record):
    if not isinstance(record, dict):
        raise ValueError('Lesson must be a proposed record.')
    required = ('lesson_id', 'created_at', 'source_type', 'source_provenance',
                'scenario_summary', 'emotional_context', 'observed_facts',
                'assumptions_or_uncertainties', 'corrective_principle',
                'recommended_response_pattern', 'relationship_context', 'approval_status')
    if any(key not in record for key in required):
        raise ValueError('Lesson record is incomplete.')
    if record['source_type'] != 'human_supervised' or record['source_provenance'] != 'trainer_entered':
        raise ValueError('Only trainer-entered human-supervised lessons are accepted.')
    if record['approval_status'] != 'proposed':
        raise ValueError('Only an unapproved proposed lesson can be approved.')
    try:
        uuid.UUID(record['lesson_id'])
        datetime.fromisoformat(record['created_at'])
    except (ValueError, TypeError):
        raise ValueError('Lesson identifier or timestamp is invalid.') from None
    for key, label, limit, required_field in (
        ('scenario_summary', 'Scenario summary', MAX_SUMMARY, True),
        ('emotional_context', 'Emotional context', MAX_FIELD, False),
        ('observed_facts', 'Observed facts', MAX_FIELD, False),
        ('assumptions_or_uncertainties', 'Assumptions or uncertainties', MAX_FIELD, False),
        ('corrective_principle', 'Corrective principle', MAX_FIELD, True),
        ('recommended_response_pattern', 'Recommended response pattern', MAX_FIELD, True),
        ('relationship_context', 'Relationship context', 300, False),
    ):
        _text(record[key], label, limit, required=required_field)


def approve(record, *, data_dir=None, db_path=None):
    """Persist a lesson only after explicit caller action, atomically and once."""
    _validate(record)
    approved_at = datetime.now(timezone.utc).isoformat()
    payload = dict(record, approval_status='approved', approved_at=approved_at)
    with studio.connect(initialize=True, data_dir=data_dir, db_path=db_path) as db:
        _ensure_tables(db)
        existing = db.execute('SELECT approval_status FROM supervised_lessons WHERE lesson_id=?',
                              (record['lesson_id'],)).fetchone()
        if existing:
            if existing[0] == 'approved':
                return record['lesson_id']
            raise ValueError('This lesson identifier was already used and cannot be re-approved.')
        db.execute('''INSERT INTO supervised_lessons
            (lesson_id, created_at, approved_at, approval_status, source_type,
             source_provenance, scenario_summary, emotional_context, observed_facts,
             uncertainties, corrective_principle, response_pattern, relationship_context, payload_json)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (record['lesson_id'], record['created_at'], approved_at, 'approved',
             record['source_type'], record['source_provenance'], record['scenario_summary'],
             record['emotional_context'], record['observed_facts'],
             record['assumptions_or_uncertainties'], record['corrective_principle'],
             record['recommended_response_pattern'], record['relationship_context'],
             json.dumps(payload, ensure_ascii=False)))
        db.execute('''CREATE TABLE IF NOT EXISTS supervised_lesson_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            lesson_id TEXT NOT NULL,
            event_type TEXT NOT NULL CHECK(event_type IN ('approved','revoked','corrected')),
            occurred_at TEXT NOT NULL,
            details_json TEXT NOT NULL
        )''')
        db.execute('INSERT INTO supervised_lesson_events(lesson_id,event_type,occurred_at,details_json) VALUES(?,?,?,?)',
                   (record['lesson_id'], 'approved', approved_at, '{}'))
    return record['lesson_id']


def _ensure_tables(db):
    """Create the lesson tables transactionally for stores not yet initialized."""
    db.execute('''CREATE TABLE IF NOT EXISTS supervised_lessons (
        lesson_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, approved_at TEXT,
        revoked_at TEXT, approval_status TEXT NOT NULL CHECK(approval_status IN ('approved','revoked')),
        source_type TEXT NOT NULL, source_provenance TEXT NOT NULL, scenario_summary TEXT NOT NULL,
        emotional_context TEXT NOT NULL, observed_facts TEXT NOT NULL, uncertainties TEXT NOT NULL,
        corrective_principle TEXT NOT NULL, response_pattern TEXT NOT NULL,
        relationship_context TEXT NOT NULL, payload_json TEXT NOT NULL)''')
    db.execute('''CREATE TABLE IF NOT EXISTS supervised_lesson_events (
        event_id INTEGER PRIMARY KEY AUTOINCREMENT, lesson_id TEXT NOT NULL,
        event_type TEXT NOT NULL CHECK(event_type IN ('approved','revoked','corrected')),
        occurred_at TEXT NOT NULL, details_json TEXT NOT NULL)''')


def _lesson_rows(query=None, *, data_dir=None, db_path=None, limit=100, include_revoked=False):
    target = Path(db_path) if db_path is not None else (Path(data_dir) / 'brain.sqlite3' if data_dir is not None else studio.DB)
    if not target.exists():
        return []
    with studio.connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='supervised_lessons'").fetchone():
            return []
        status_clause = '' if include_revoked else "AND approval_status='approved'"
        rows = db.execute(f'''SELECT payload_json, approval_status, approved_at, revoked_at
                              FROM supervised_lessons WHERE 1=1 {status_clause}
                              ORDER BY created_at DESC LIMIT ?''', (limit,)).fetchall()
    output = []
    query_tokens = _tokens(query or '')
    for payload_json, status, approved_at, revoked_at in rows:
        record = json.loads(payload_json)
        if query is not None:
            haystack = ' '.join(str(record.get(key, '')) for key in (
                'scenario_summary', 'emotional_context', 'observed_facts',
                'assumptions_or_uncertainties', 'corrective_principle',
                'recommended_response_pattern', 'relationship_context'))
            overlap = query_tokens & _tokens(haystack)
            # Small deterministic concept aliases bridge common paraphrases without
            # introducing fuzzy/vector retrieval or changing any approved record.
            concepts = (
                {'rejection', 'reject', 'abandonment', 'abandoned', 'left', 'leave'},
                {'memory', 'memories', 'past', 'previous', 'history', 'experience'},
                {'fear', 'anxiety', 'anxious', 'worry', 'worried', 'insecurity'},
                {'proof', 'evidence', 'established', 'fact', 'facts'},
                {'silence', 'quiet', 'withdrawn', 'less', 'communicative', 'communication'},
                {'intentions', 'intent', 'motives', 'motive', 'reason'},
            )
            query_terms = _tokens(query or '')
            lesson_terms = _tokens(haystack)
            expanded_query, expanded_lesson = set(query_terms), set(lesson_terms)
            for group in concepts:
                if query_terms & group:
                    expanded_query.update(group)
                if lesson_terms & group:
                    expanded_lesson.update(group)
            concept_overlap = expanded_query & expanded_lesson
            if not overlap and len(concept_overlap) < 2:
                continue
            matched = sorted(overlap or concept_overlap)
            record['relevance'] = {'matched_terms': matched,
                                   'explanation': ('Matches trainer-entered lesson terms: ' + ', '.join(matched)
                                                   if overlap else 'Deterministic paraphrase concepts matched: ' + ', '.join(matched))}
        else:
            record['relevance'] = {'matched_terms': [], 'explanation': 'Listed as an approved lesson; no query-specific relevance was calculated.'}
        record['approval_status'] = status
        record['approved_at'] = approved_at
        record['revoked_at'] = revoked_at
        output.append(record)
    return output


def retrieve(query, limit=3, *, data_dir=None, db_path=None):
    """Return approved, non-revoked lessons with an inspectable relevance reason."""
    matches = _lesson_rows(query, data_dir=data_dir, db_path=db_path, limit=500)
    matches.sort(key=lambda item: (len(item['relevance']['matched_terms']), item['created_at']), reverse=True)
    return matches[:max(0, limit)]


def list_lessons(*, data_dir=None, db_path=None, include_revoked=False, limit=100):
    return _lesson_rows(data_dir=data_dir, db_path=db_path, limit=limit, include_revoked=include_revoked)


def revoke(lesson_id, *, data_dir=None, db_path=None):
    """Revoke an approved lesson and append an audit event in one transaction."""
    at = datetime.now(timezone.utc).isoformat()
    with studio.connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
        _ensure_tables(db)
        changed = db.execute("UPDATE supervised_lessons SET approval_status='revoked', revoked_at=? WHERE lesson_id=? AND approval_status='approved'",
                             (at, lesson_id)).rowcount
        if not changed:
            raise ValueError('Approved lesson does not exist or is already revoked.')
        db.execute('INSERT INTO supervised_lesson_events(lesson_id,event_type,occurred_at,details_json) VALUES(?,?,?,?)',
                   (lesson_id, 'revoked', at, '{}'))


def correct(lesson_id, updates, *, data_dir=None, db_path=None):
    """Correct an approved record by auditing and replacing its trainer-entered fields."""
    allowed = {'scenario_summary', 'emotional_context', 'observed_facts',
               'assumptions_or_uncertainties', 'corrective_principle',
               'recommended_response_pattern', 'relationship_context'}
    if not isinstance(updates, dict) or not updates or set(updates) - allowed:
        raise ValueError('Correction must contain valid lesson fields.')
    at = datetime.now(timezone.utc).isoformat()
    with studio.connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
        _ensure_tables(db)
        row = db.execute("SELECT payload_json FROM supervised_lessons WHERE lesson_id=? AND approval_status='approved'",
                         (lesson_id,)).fetchone()
        if not row:
            raise ValueError('Approved lesson does not exist or is revoked.')
        payload = json.loads(row[0])
        labels = {'scenario_summary': ('Scenario summary', MAX_SUMMARY, True),
                  'emotional_context': ('Emotional context', MAX_FIELD, False),
                  'observed_facts': ('Observed facts', MAX_FIELD, False),
                  'assumptions_or_uncertainties': ('Assumptions or uncertainties', MAX_FIELD, False),
                  'corrective_principle': ('Corrective principle', MAX_FIELD, True),
                  'recommended_response_pattern': ('Recommended response pattern', MAX_FIELD, False),
                  'relationship_context': ('Relationship context', 300, False)}
        normalized = {key: _text(value, labels[key][0], labels[key][1], required=labels[key][2])
                      for key, value in updates.items()}
        payload.update(normalized)
        payload['corrected_at'] = at
        for key in normalized:
            column = {'assumptions_or_uncertainties': 'uncertainties',
                      'recommended_response_pattern': 'response_pattern'}.get(key, key)
            db.execute(f'UPDATE supervised_lessons SET {column}=? WHERE lesson_id=?',
                       (normalized[key], lesson_id))
        db.execute('UPDATE supervised_lessons SET payload_json=? WHERE lesson_id=?',
                   (json.dumps(payload, ensure_ascii=False), lesson_id))
        db.execute('INSERT INTO supervised_lesson_events(lesson_id,event_type,occurred_at,details_json) VALUES(?,?,?,?)',
                   (lesson_id, 'corrected', at, json.dumps({'fields': sorted(normalized)})))
    return lesson_id


def audit_events(lesson_id, *, data_dir=None, db_path=None):
    from pathlib import Path
    target = Path(db_path) if db_path is not None else (Path(data_dir) / 'brain.sqlite3' if data_dir is not None else studio.DB)
    if not target.exists():
        return []
    with studio.connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='supervised_lesson_events'").fetchone():
            return []
        rows = db.execute('SELECT event_id,lesson_id,event_type,occurred_at,details_json FROM supervised_lesson_events WHERE lesson_id=? ORDER BY event_id',
                          (lesson_id,)).fetchall()
    return [{'event_id': r[0], 'lesson_id': r[1], 'event_type': r[2], 'occurred_at': r[3],
             'details': json.loads(r[4])} for r in rows]
