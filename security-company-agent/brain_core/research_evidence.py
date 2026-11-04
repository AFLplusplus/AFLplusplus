"""Validation and provenance wrapping for untrusted web-search results."""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import urllib.parse


MAX_TITLE_LENGTH = 500
MAX_SNIPPET_LENGTH = 2000
MAX_URL_LENGTH = 2048


@dataclass(frozen=True)
class ResearchEvidence:
    """A bounded source record; content remains untrusted and is not executable."""
    claim: str
    snippet: str
    source_url: str
    title: str
    retrieved_at: str
    confidence: float
    uncertainty: str
    content_trusted: bool = False


def _validated_url(value):
    if not isinstance(value, str) or not value or len(value) > MAX_URL_LENGTH:
        return None
    if value != value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    try:
        parsed = urllib.parse.urlsplit(value)
        # Accessing .port/.hostname also detects malformed authority syntax.
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError:
        return None
    if parsed.scheme.casefold() != 'https' or not hostname or parsed.username is not None:
        return None
    if not parsed.netloc or not hostname.strip('.'):
        return None
    return value


def validate_search_results(results, *, retrieved_at=None):
    """Convert valid adapter results to evidence without inferring facts.

    Search-provided title and snippet text are copied verbatim (within their
    source bounds), including any hostile instructions. They remain marked as
    untrusted data: callers must not execute or follow instructions in them.
    No publication date, factual claim, or confidence score is inferred; the
    confidence is deliberately conservative and the uncertainty explains why.
    Invalid records are rejected individually. Duplicate canonical source URLs
    (case-insensitive host/scheme and ignoring fragments) are emitted once.
    """
    if not isinstance(results, (list, tuple)):
        return ()
    timestamp = retrieved_at or datetime.now(timezone.utc).isoformat()
    if not isinstance(timestamp, str) or not timestamp.strip():
        timestamp = datetime.now(timezone.utc).isoformat()
    evidence = []
    seen = set()
    for result in results:
        if not isinstance(result, dict):
            continue
        url = _validated_url(result.get('url'))
        title, snippet = result.get('title'), result.get('snippet')
        if url is None or not isinstance(title, str) or not isinstance(snippet, str):
            continue
        title = title[:MAX_TITLE_LENGTH]
        snippet = snippet[:MAX_SNIPPET_LENGTH]
        if not title.strip() or not snippet.strip():
            continue
        parsed = urllib.parse.urlsplit(url)
        canonical_url = urllib.parse.urlunsplit((
            'https', parsed.netloc.casefold(), parsed.path or '/', parsed.query, ''))
        dedupe_key = hashlib.sha256(canonical_url.encode('utf-8')).digest()
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        evidence.append(ResearchEvidence(
            claim=snippet,
            snippet=snippet,
            source_url=url,
            title=title,
            retrieved_at=timestamp,
            confidence=0.25,
            uncertainty='Search snippet is unverified; source content and factual accuracy have not been independently checked.',
            content_trusted=False))
    return tuple(evidence)
