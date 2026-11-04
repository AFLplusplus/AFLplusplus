"""Local SQLite memory and document processing for the training studio."""
from __future__ import annotations
import json
import os
import sqlite3
import re
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
DATA = HERE / "studio_data"
DB = DATA / "brain.sqlite3"
ALLOWED_EXTENSIONS = {".txt", ".md", ".pdf", ".docx"}
MAX_UPLOAD = 10 * 1024 * 1024

def now():
    return datetime.now(timezone.utc).isoformat()

@contextmanager
def connect(*, initialize=False, data_dir=None, db_path=None):
    data_dir = Path(data_dir) if data_dir is not None else DATA
    db_path = Path(db_path) if db_path is not None else (data_dir / 'brain.sqlite3' if data_dir != DATA else DB)
    if initialize:
        db_path.parent.mkdir(parents=True, exist_ok=True)
    elif not db_path.exists():
        raise FileNotFoundError(db_path)
    conn = sqlite3.connect(db_path if initialize else f'file:{db_path.as_posix()}?mode=rw', uri=not initialize)
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        if initialize:
            conn.executescript("""
    CREATE TABLE IF NOT EXISTS turns (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      created TEXT NOT NULL,
      scenario TEXT NOT NULL,
      feedback TEXT NOT NULL DEFAULT '',
      result_json TEXT NOT NULL,
      state_json TEXT NOT NULL,
      rating TEXT,
      commentary TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS documents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      created TEXT NOT NULL,
      filename TEXT NOT NULL,
      content TEXT NOT NULL,
      char_count INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS research (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      created TEXT NOT NULL,
      query TEXT NOT NULL,
      title TEXT NOT NULL,
      url TEXT NOT NULL,
      excerpt TEXT NOT NULL,
      approved INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS relationship_states (
      label TEXT PRIMARY KEY,
      emotions_json TEXT NOT NULL,
      updated TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS supervised_lessons (
      lesson_id TEXT PRIMARY KEY,
      created_at TEXT NOT NULL,
      approved_at TEXT,
      revoked_at TEXT,
      approval_status TEXT NOT NULL CHECK(approval_status IN ('approved','revoked')),
      source_type TEXT NOT NULL,
      source_provenance TEXT NOT NULL,
      scenario_summary TEXT NOT NULL,
      emotional_context TEXT NOT NULL,
      observed_facts TEXT NOT NULL,
      uncertainties TEXT NOT NULL,
      corrective_principle TEXT NOT NULL,
      response_pattern TEXT NOT NULL,
      relationship_context TEXT NOT NULL,
      payload_json TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS supervised_lesson_events (
      event_id INTEGER PRIMARY KEY AUTOINCREMENT,
      lesson_id TEXT NOT NULL,
      event_type TEXT NOT NULL CHECK(event_type IN ('approved','revoked','corrected')),
      occurred_at TEXT NOT NULL,
      details_json TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS conversations (
      conversation_id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS conversation_messages (
      message_id TEXT PRIMARY KEY,
      conversation_id TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('user','assistant','system')),
      created_at TEXT NOT NULL,
      content TEXT NOT NULL,
      message_type TEXT NOT NULL,
      related_lesson_id TEXT,
      inference_status TEXT NOT NULL DEFAULT 'not_applicable',
      FOREIGN KEY(conversation_id) REFERENCES conversations(conversation_id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_messages_conversation
      ON conversation_messages(conversation_id, created_at);
    """)
        with conn:
            yield conn
    finally:
        conn.close()

def add_turn(scenario, feedback, result, state, *, data_dir=None, db_path=None):
    if result.get('_trainer_pending'):
        raise ValueError('Unreviewed inference cannot be saved as a training record.')
    if result.get('_provenance', {}).get('source') == 'approved_training' and not result.get('_trainer_approved'):
        raise ValueError('Approved training records require explicit trainer approval.')
    if not result.get('_trainer_approved') and result.get('_provenance', {}).get('source') not in ('offline_fixture', 'unit_test_mock'):
        raise ValueError('Training records require explicit trainer approval.')
    with connect(initialize=True, data_dir=data_dir, db_path=db_path) as db:
        cur = db.execute("INSERT INTO turns(created,scenario,feedback,result_json,state_json) VALUES(?,?,?,?,?)",
                        (now(), scenario, feedback, json.dumps(result), json.dumps(state)))
        return cur.lastrowid

def rate_turn(turn_id, rating, commentary, *, data_dir=None, db_path=None):
    if rating not in ("good", "partial", "poor"):
        raise ValueError("Unknown rating")
    with connect(initialize=True, data_dir=data_dir, db_path=db_path) as db:
        row = db.execute("SELECT result_json FROM turns WHERE id=?", (turn_id,)).fetchone()
        if not row:
            raise ValueError("Training turn does not exist; feedback was not saved.")
        result = json.loads(row[0])
        if result.get('_trainer_pending'):
            raise ValueError("Unreviewed inference cannot receive saved trainer feedback.")
        if not result.get('_trainer_approved'):
            raise ValueError("Training turn requires an explicit saved approval action.")
        db.execute("UPDATE turns SET rating=?, commentary=? WHERE id=?",
                   (rating, commentary[:4000], turn_id))

def initialize_store(*, data_dir=None, db_path=None):
    """Initialize the existing local SQLite store and its additive tables."""
    with connect(initialize=True, data_dir=data_dir, db_path=db_path):
        pass


def inspect_turns(limit=20, *, data_dir=None, db_path=None):
    """Read existing turns without creating the data directory or database."""
    db_path = Path(db_path) if db_path is not None else (Path(data_dir) / 'brain.sqlite3' if data_dir is not None else DB)
    if not db_path.exists():
        return []
    with connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
        return [dict(zip(("id","created","scenario","feedback","result_json","state_json","rating","commentary"), row))
                for row in db.execute("SELECT id,created,scenario,feedback,result_json,state_json,rating,commentary FROM turns ORDER BY id DESC LIMIT ?", (limit,))]

def recent_turns(limit=20, *, data_dir=None, db_path=None):
    db_path = Path(db_path) if db_path is not None else (Path(data_dir) / 'brain.sqlite3' if data_dir is not None else DB)
    if not db_path.exists():
        return []
    with connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
        return [dict(zip(("id","created","scenario","feedback","result_json","state_json","rating","commentary"), row))
                for row in db.execute("SELECT id,created,scenario,feedback,result_json,state_json,rating,commentary FROM turns ORDER BY id DESC LIMIT ?", (limit,))]

def relevance_tokens(text):
    stop={'with','that','this','have','someone','they','their','about','from','your','what',
          'when','were','would','could','should','will','feel','feels','feeling','emotions',
          'emotion','decide','decision','situation','because','which','them','then','into',
          'does','want','make','made','both','also','only','completely','increasingly'}
    return set(re.findall(r'\b\w{4,}\b',text.casefold()))-stop

def relevance_score(query, text):
    # Require two substantive matches, not a shared pronoun such as "your".
    overlap=relevance_tokens(query) & relevance_tokens(text)
    return len(overlap) if len(overlap)>=2 else 0

def feedback_context(query, limit=3, max_chars=2000, *, initialize=False, data_dir=None, db_path=None):
    """Retrieve relevant trainer corrections with explicit local source IDs."""
    target_db = Path(db_path) if db_path is not None else (Path(data_dir) / 'brain.sqlite3' if data_dir is not None else DB)
    if not initialize and not target_db.exists():
        return []
    with connect(initialize=False, data_dir=data_dir, db_path=target_db) as db:
        rows = db.execute('SELECT id,scenario,rating,commentary FROM turns '
                          "WHERE trim(commentary) != '' ORDER BY id DESC LIMIT 100").fetchall()
    ranked = []
    for id, scenario, rating, correction in rows:
        score = relevance_score(query, scenario + ' ' + correction)
        if score:
            ranked.append((score, id, {'turn_id': id, 'rating': rating,
                                      'scenario_excerpt': scenario[:250], 'correction': correction[:1200]}))
    ranked.sort(key=lambda item: (item[0], item[1]), reverse=True)
    selected, budget = [], max_chars
    for _, _, item in ranked[:limit]:
        size = len(json.dumps(item))
        if size <= budget:
            selected.append(item)
            budget -= size
    return selected

def decode_document(name, content):
    extension = Path(name).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("Supported: PDF, DOCX, TXT, MD")
    if not content or len(content) > MAX_UPLOAD:
        raise ValueError("File must be nonempty and at most 10 MB")
    from io import BytesIO
    if extension in (".txt", ".md"):
        text = content.decode("utf-8-sig", errors="replace")
    elif extension == ".pdf":
        from pypdf import PdfReader
        reader = PdfReader(BytesIO(content))
        if len(reader.pages) > 150:
            raise ValueError("PDF exceeds 150 pages")
        text = "\n".join((p.extract_text() or "") for p in reader.pages)
    else:
        from docx import Document
        doc = Document(BytesIO(content))
        text = "\n".join(p.text for p in doc.paragraphs)
    if not text.strip():
        raise ValueError("No readable text found. Scanned PDFs need OCR (not enabled).")
    return text[:250000]

def add_document(filename, text, *, data_dir=None, db_path=None):
    with connect(initialize=True, data_dir=data_dir, db_path=db_path) as db:
        cur = db.execute("INSERT INTO documents(created,filename,content,char_count) VALUES(?,?,?,?)",
                         (now(), Path(filename).name[:240], text, len(text)))
        return cur.lastrowid

def inspect_documents(*, data_dir=None, db_path=None):
    db_path = Path(db_path) if db_path is not None else (Path(data_dir) / 'brain.sqlite3' if data_dir is not None else DB)
    if not db_path.exists():
        return []
    with connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
        return [dict(zip(("id","filename","char_count"), row))
                for row in db.execute("SELECT id,filename,char_count FROM documents ORDER BY id DESC")]

def documents(*, data_dir=None, db_path=None):
    db_path = Path(db_path) if db_path is not None else (Path(data_dir) / 'brain.sqlite3' if data_dir is not None else DB)
    if not db_path.exists():
        return []
    with connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
        return [dict(zip(("id","filename","char_count"), row))
                for row in db.execute("SELECT id,filename,char_count FROM documents ORDER BY id DESC")]

def relevant_context(query, max_chars=11000, *, initialize=False, data_dir=None, db_path=None):
    # Simple word overlap retrieval for the MVP. Upgrade to embeddings in next phase.
    words = {w.lower() for w in query.split() if len(w) > 3}
    target_db = Path(db_path) if db_path is not None else (Path(data_dir) / 'brain.sqlite3' if data_dir is not None else DB)
    if not initialize and not target_db.exists():
        return ''
    with connect(initialize=False, data_dir=data_dir, db_path=target_db) as db:
        rows = db.execute("SELECT filename,content FROM documents ORDER BY id DESC LIMIT 60").fetchall()
        research = db.execute("SELECT title,url,excerpt FROM research WHERE approved=1 ORDER BY id DESC LIMIT 30").fetchall()
    candidates = [(sum(w in content.lower() for w in words), f"DOCUMENT: {name}\n{content[:4500]}")
                  for name, content in rows]
    candidates += [(sum(w in excerpt.lower() for w in words),
                    f"RESEARCH: {title} | {url}\n{excerpt[:2500]}")
                   for title,url,excerpt in research]
    candidates.sort(key=lambda x: x[0], reverse=True)
    return "\n\n".join(text for score,text in candidates if score > 0)[:max_chars]

def research_search(query, *, data_dir=None, db_path=None):
    """Search via optional Tavily API; results are UNAPPROVED drafts."""
    import urllib.request
    key = os.getenv("TAVILY_API_KEY", "").strip()
    if not key:
        raise RuntimeError("Set TAVILY_API_KEY to enable web research.")
    request = urllib.request.Request(
        "https://api.tavily.com/search",
        data=json.dumps({"query": query[:500], "max_results": 5, "search_depth": "basic"}).encode(),
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + key},
        method="POST")
    with urllib.request.urlopen(request, timeout=25) as response:
        results = json.load(response).get("results", [])
    saved = []
    with connect(initialize=True, data_dir=data_dir, db_path=db_path) as db:
        for item in results[:5]:
            url = item.get("url", "")
            if urlparse(url).scheme != "https":
                continue
            title = str(item.get("title", ""))[:300]
            excerpt = str(item.get("content", ""))[:4000]
            cur = db.execute("INSERT INTO research(created,query,title,url,excerpt) VALUES(?,?,?,?,?)",
                             (now(), query[:500], title, url, excerpt))
            saved.append({"id": cur.lastrowid,"title":title,"url":url,"excerpt":excerpt})
    return saved

def inspect_research_items(*, data_dir=None, db_path=None):
    db_path = Path(db_path) if db_path is not None else (Path(data_dir) / 'brain.sqlite3' if data_dir is not None else DB)
    if not db_path.exists():
        return []
    with connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
        return [dict(zip(("id","title","url","excerpt","approved"), row))
                for row in db.execute("SELECT id,title,url,excerpt,approved FROM research ORDER BY id DESC LIMIT 50")]

def research_items(*, data_dir=None, db_path=None):
    db_path = Path(db_path) if db_path is not None else (Path(data_dir) / 'brain.sqlite3' if data_dir is not None else DB)
    if not db_path.exists():
        return []
    with connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
        return [dict(zip(("id","title","url","excerpt","approved"), row))
                for row in db.execute("SELECT id,title,url,excerpt,approved FROM research ORDER BY id DESC LIMIT 50")]

def approve_research(id, approved, *, data_dir=None, db_path=None):
    if type(approved) is not bool:
        raise ValueError("Research approval must be an explicit boolean decision.")
    with connect(initialize=False, data_dir=data_dir, db_path=db_path) as db:
        changed = db.execute("UPDATE research SET approved=? WHERE id=?", (int(approved), id)).rowcount
        if not changed:
            raise ValueError("Research item does not exist; approval was not saved.")
