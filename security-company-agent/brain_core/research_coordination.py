"""Independent reasoning and explicitly authorized web-research coordination."""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile

from .fallback_state import FallbackState
from .provider_selection import ProviderSelection, SelectionReason
from .providers import ProviderID
from .web_search import search as brave_search


@dataclass(frozen=True)
class ResearchJourneyResult:
    reasoning_status: FallbackState
    research_status: str
    selected_provider: ProviderID | None
    next_provider: ProviderID | None
    evidence: tuple[dict, ...]
    reasoning_diagnostic: str | None
    research_diagnostic: str | None


class ResearchAuthorizationLedger:
    """SQLite-backed one-time claims stored separately from the Brain database."""
    def __init__(self, db_path=None):
        if db_path is None:
            data_dir = Path(os.environ.get(
                'SOVEREIGNBRAIN_RUNTIME_DIR', Path(tempfile.gettempdir()) / 'SovereignBrain'))
            db_path = data_dir / 'research_authorizations.sqlite3'
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @staticmethod
    def request_fingerprint(query):
        canonical = ' '.join(query.split()) if isinstance(query, str) else ''
        return hashlib.sha256(canonical.casefold().encode('utf-8')).hexdigest(), canonical

    def _connect(self):
        connection = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        connection.execute('PRAGMA busy_timeout = 30000')
        return connection

    def _initialize(self):
        connection = self._connect()
        try:
            connection.execute('''
                CREATE TABLE IF NOT EXISTS research_authorization_claims (
                    journey_id TEXT NOT NULL,
                    authorization_id TEXT NOT NULL,
                    request_fingerprint TEXT NOT NULL,
                    claimed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (journey_id, authorization_id, request_fingerprint)
                )
            ''')
        finally:
            connection.close()

    def claim(self, *, journey_id, authorization_id, request_fingerprint):
        """Commit the unique claim before execution; a claim is never released."""
        connection = self._connect()
        try:
            connection.execute('BEGIN IMMEDIATE')
            cursor = connection.execute(
                '''INSERT OR IGNORE INTO research_authorization_claims
                   (journey_id, authorization_id, request_fingerprint)
                   VALUES (?, ?, ?)''',
                (journey_id, authorization_id, request_fingerprint))
            claimed = cursor.rowcount == 1
            connection.commit()
            return claimed
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


_DEFAULT_RESEARCH_AUTHORIZATIONS = ResearchAuthorizationLedger()


class ResearchCoordinator:
    """Run supplied reasoning/search lanes independently, with per-query deduping.

    Reasoning is a callback supplied by the backend caller and is expected to
    return one of SB-05's states or a result holding `state` and optional
    `provider`/`failure_category` fields. Web search requires a second, explicit
    authorization for the exact normalized query. Consent to cloud inference
    does not grant research authorization. Callers must supply a journey ID
    and one-time authorization ID; an injected shared ledger atomically consumes
    each authorization before external search execution.
    """
    def __init__(self, *, reasoning_runner, search_runner=None, authorization_ledger=None):
        if not callable(reasoning_runner):
            raise TypeError('reasoning_runner must be callable')
        if authorization_ledger is None:
            authorization_ledger = _DEFAULT_RESEARCH_AUTHORIZATIONS
        if not isinstance(authorization_ledger, ResearchAuthorizationLedger):
            raise TypeError('authorization_ledger must be a shared ResearchAuthorizationLedger')
        self._reasoning_runner = reasoning_runner
        self._search_runner = search_runner or brave_search
        self._authorization_ledger = authorization_ledger

    @staticmethod
    def _query_key(query):
        return ResearchAuthorizationLedger.request_fingerprint(query)

    @staticmethod
    def _reasoning_result(value):
        state = getattr(value, 'state', value)
        provider = getattr(value, 'selected_provider', None)
        next_provider = getattr(value, 'next_provider', None)
        category = getattr(value, 'failure_category', None)
        try:
            state = state if isinstance(state, FallbackState) else FallbackState(state)
        except (TypeError, ValueError):
            state = FallbackState.FAILED
        safe = {'resource_limit', 'invalid_or_unvalidated_output', 'timeout',
                'connection', 'authentication', 'provider_error', 'internal_error', 'unknown'}
        category = category if category in safe else ('unknown' if state == FallbackState.FAILED else None)
        for name in ('provider', 'next_provider'):
            candidate = provider if name == 'provider' else next_provider
            if candidate is not None and not isinstance(candidate, ProviderID):
                try:
                    candidate = ProviderID(candidate)
                except (ValueError, TypeError):
                    candidate = None
            if name == 'provider':
                provider = candidate
            else:
                next_provider = candidate
        return state, provider, next_provider, category

    def run(self, *, query, research_authorized=False, authorization_id=None,
            journey_id=None, reasoning_authorized=False, reasoning_selection=None,
            reasoning_runner=None, search_runner=None, transport=None):
        """Advance both lanes independently and return sanitized combined state."""
        query_key, normalized_query = self._query_key(query)
        reasoning_status = FallbackState.FAILED
        selected_provider = next_provider = None
        reasoning_diagnostic = None

        if not reasoning_authorized:
            reasoning_status = FallbackState.FAILED
            reasoning_diagnostic = 'reasoning_not_authorized'
        else:
            try:
                selection = reasoning_selection or ProviderSelection(
                    None, SelectionReason.NO_CONFIGURED_PROVIDER)
                callback = reasoning_runner or self._reasoning_runner
                raw = callback(selection=selection)
                (reasoning_status, selected_provider,
                 next_provider, reasoning_diagnostic) = self._reasoning_result(raw)
            except Exception:
                reasoning_status = FallbackState.FAILED
                reasoning_diagnostic = 'reasoning_failed'

        # Research is independent: a reasoning failure does not suppress an
        # explicitly authorized exact-query search, and vice versa.
        if not research_authorized:
            research_status, evidence, research_diagnostic = 'awaiting_authorization', (), None
        elif not normalized_query:
            research_status, evidence, research_diagnostic = 'invalid_query', (), 'invalid_query'
        elif (not isinstance(journey_id, str) or not journey_id.strip()
              or not isinstance(authorization_id, str) or not authorization_id.strip()):
            research_status, evidence, research_diagnostic = 'invalid_authorization', (), 'invalid_authorization'
        else:
            claimed = self._authorization_ledger.claim(
                journey_id=journey_id.strip(), authorization_id=authorization_id.strip(),
                request_fingerprint=query_key)
            if not claimed:
                research_status, evidence, research_diagnostic = 'duplicate', (), 'duplicate_authorization'
            else:
                try:
                    runner = search_runner or self._search_runner
                    if runner is brave_search:
                        result = runner(normalized_query, authorized=True, transport=transport)
                    else:
                        result = runner(normalized_query, authorized=True)
                    if not isinstance(result, dict):
                        raise ValueError('invalid search result')
                    research_status = result.get('status', 'http_error')
                    if research_status == 'ok':
                        evidence = tuple(result.get('results', ()))
                        research_diagnostic = None
                    else:
                        evidence = ()
                        research_diagnostic = research_status if research_status in {
                            'missing_key', 'timeout', 'http_error', 'empty', 'unauthorized',
                            'invalid_query'} else 'http_error'
                except Exception:
                    research_status, evidence, research_diagnostic = (
                        'http_error', (), 'http_error')

        return ResearchJourneyResult(
            reasoning_status=reasoning_status,
            research_status=research_status,
            selected_provider=selected_provider,
            next_provider=next_provider,
            evidence=tuple(evidence),
            reasoning_diagnostic=reasoning_diagnostic,
            research_diagnostic=research_diagnostic)
