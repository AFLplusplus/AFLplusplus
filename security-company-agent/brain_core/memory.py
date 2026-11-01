"""Local experience and relationship retrieval behind a replaceable storage boundary."""
import json
import re
from . import studio

def experiences(query, limit=3):
    words=set(re.findall(r'\b\w{4,}\b',query.casefold())) - {'with','that','this','have','someone','their','they'}
    candidates=[]
    for row in studio.recent_turns(100):
        result=json.loads(row['result_json'])
        if result.get('_provenance',{}).get('source') == 'offline_fixture':
            continue
        # Legacy turns without provenance are visible in history, not presumed model evidence.
        if not result.get('_provenance',{}).get('source'):
            continue
        score=len(words & set(re.findall(r'\b\w{4,}\b',row['scenario'].casefold())))
        if score:
            candidates.append((score,row['id'],{'turn_id':row['id'],
                'scenario_excerpt':row['scenario'][:200], 'previous_recommendation':
                    result.get('decision',{}).get('recommended_action', '')[:300],
                'trainer_rating':row['rating'], 'trainer_correction':row['commentary'][:600]}))
    return [item[2] for item in sorted(candidates,key=lambda item:(item[0],item[1]),reverse=True)[:limit]]

def relationship(label):
    if not label.strip():
        return {}
    with studio.connect() as db:
        db.execute('CREATE TABLE IF NOT EXISTS relationship_states '
                   '(label TEXT PRIMARY KEY, emotions_json TEXT NOT NULL, updated TEXT NOT NULL)')
        row=db.execute('SELECT emotions_json FROM relationship_states WHERE label=?',
                       (label.strip().casefold(),)).fetchone()
    return json.loads(row[0]) if row else {}

def save_relationship(label, emotions):
    if not label.strip():
        return
    # Labels identify trainer-defined contexts; unlabeled situations never share a relationship bucket.
    relationship(label)
    with studio.connect() as db:
        db.execute('INSERT INTO relationship_states(label,emotions_json,updated) VALUES(?,?,?) '
                   'ON CONFLICT(label) DO UPDATE SET emotions_json=excluded.emotions_json, updated=excluded.updated',
                   (label.strip().casefold(),json.dumps(emotions),studio.now()))
