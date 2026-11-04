"""Local experience and relationship retrieval behind a replaceable storage boundary."""
import json
import sqlite3
from pathlib import Path
from . import studio, lessons

def experiences(query, limit=3, *, data_dir=None, db_path=None):
    candidates=[]
    for row in studio.inspect_turns(100, data_dir=data_dir, db_path=db_path):
        result=json.loads(row['result_json'])
        if result.get('_provenance',{}).get('source') == 'offline_fixture':
            continue
        # Legacy turns without provenance are visible in history, not presumed model evidence.
        if not result.get('_provenance',{}).get('source'):
            continue
        score=studio.relevance_score(query,row['scenario'])
        if score:
            candidates.append((score,row['id'],{'turn_id':row['id'],
                'scenario_excerpt':row['scenario'][:200], 'previous_recommendation':
                    result.get('decision',{}).get('recommended_action', '')[:300],
                'trainer_rating':row['rating'], 'trainer_correction':row['commentary'][:600]}))
    return [item[2] for item in sorted(candidates,key=lambda item:(item[0],item[1]),reverse=True)[:limit]]

def supervised_lessons(query, limit=3, *, data_dir=None, db_path=None):
    """Retrieve explicit human-approved lessons without inferring or changing state."""
    return lessons.retrieve(query, limit=limit, data_dir=data_dir, db_path=db_path)


def relationship(label, *, data_dir=None, db_path=None):
    if not isinstance(label, str) or not label.strip():
        return {}
    db_path = Path(db_path) if db_path is not None else (Path(data_dir) / 'brain.sqlite3' if data_dir is not None else studio.DB)
    if not db_path.exists():
        return {}
    with studio.connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
        try:
            row=db.execute('SELECT emotions_json FROM relationship_states WHERE label=?',
                           (label.strip().casefold(),)).fetchone()
        except sqlite3.OperationalError:
            return {}
    return json.loads(row[0]) if row else {}

def save_relationship(label, emotions, *, data_dir=None, db_path=None, initialize=False):
    if not isinstance(label, str) or not label.strip():
        return
    # Labels identify trainer-defined contexts; unlabeled situations never share a relationship bucket.
    target_db = Path(db_path) if db_path is not None else (Path(data_dir) / 'brain.sqlite3' if data_dir is not None else studio.DB)
    if not target_db.exists():
        return
    with studio.connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
        try:
            db.execute('INSERT INTO relationship_states(label,emotions_json,updated) VALUES(?,?,?) '
                       'ON CONFLICT(label) DO UPDATE SET emotions_json=excluded.emotions_json, updated=excluded.updated',
                       (label.strip().casefold(),json.dumps(emotions),studio.now()))
        except sqlite3.OperationalError:
            return
