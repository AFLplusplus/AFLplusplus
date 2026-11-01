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
def connect():
    DATA.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB)
    try:
        conn.execute("PRAGMA foreign_keys=ON")
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
    """)
        with conn:
            yield conn
    finally:
        conn.close()

def add_turn(scenario, feedback, result, state):
    with connect() as db:
        cur = db.execute("INSERT INTO turns(created,scenario,feedback,result_json,state_json) VALUES(?,?,?,?,?)",
                        (now(), scenario, feedback, json.dumps(result), json.dumps(state)))
        return cur.lastrowid

def rate_turn(turn_id, rating, commentary):
    if rating not in ("good", "partial", "poor"):
        raise ValueError("Unknown rating")
    with connect() as db:
        db.execute("UPDATE turns SET rating=?, commentary=? WHERE id=?",
                   (rating, commentary[:4000], turn_id))

def recent_turns(limit=20):
    with connect() as db:
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

def feedback_context(query, limit=3, max_chars=2000):
    """Retrieve relevant trainer corrections with explicit local source IDs."""
    with connect() as db:
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

def add_document(filename, text):
    with connect() as db:
        cur = db.execute("INSERT INTO documents(created,filename,content,char_count) VALUES(?,?,?,?)",
                         (now(), Path(filename).name[:240], text, len(text)))
        return cur.lastrowid

def documents():
    with connect() as db:
        return [dict(zip(("id","filename","char_count"), row))
                for row in db.execute("SELECT id,filename,char_count FROM documents ORDER BY id DESC")]

def relevant_context(query, max_chars=11000):
    # Simple word overlap retrieval for the MVP. Upgrade to embeddings in next phase.
    words = {w.lower() for w in query.split() if len(w) > 3}
    with connect() as db:
        rows = db.execute("SELECT filename,content FROM documents ORDER BY id DESC LIMIT 60").fetchall()
        research = db.execute("SELECT title,url,excerpt FROM research WHERE approved=1 ORDER BY id DESC LIMIT 30").fetchall()
    candidates = [(sum(w in content.lower() for w in words), f"DOCUMENT: {name}\n{content[:4500]}")
                  for name, content in rows]
    candidates += [(sum(w in excerpt.lower() for w in words),
                    f"RESEARCH: {title} | {url}\n{excerpt[:2500]}")
                   for title,url,excerpt in research]
    candidates.sort(key=lambda x: x[0], reverse=True)
    return "\n\n".join(text for score,text in candidates if score > 0)[:max_chars]

def research_search(query):
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
    with connect() as db:
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

def research_items():
    with connect() as db:
        return [dict(zip(("id","title","url","excerpt","approved"), row))
                for row in db.execute("SELECT id,title,url,excerpt,approved FROM research ORDER BY id DESC LIMIT 50")]

def approve_research(id, approved):
    with connect() as db:
        db.execute("UPDATE research SET approved=? WHERE id=?", (int(bool(approved)), id))
