"""Permission-gated Brave Search adapter with sanitized, bounded results."""
from dataclasses import dataclass
import json
import os
import socket
import urllib.error
import urllib.parse
import urllib.request

BRAVE_SEARCH_ENDPOINT = 'https://api.search.brave.com/res/v1/web/search'
MAX_RESULTS = 5


@dataclass(frozen=True)
class WebSearchConfiguration:
    api_key_configured: bool


def web_search_configuration(*, environ=None):
    """Detect a usable-looking Brave key without exposing or validating its value."""
    env = os.environ if environ is None else environ
    raw = str(env.get('BRAVE_API_KEY', '')).strip()
    configured = bool(raw and not raw.upper().startswith(('PASTE_', 'YOUR_', 'REPLACE_')))
    return WebSearchConfiguration(configured)


def search(query, *, authorized=False, transport=None, max_results=MAX_RESULTS,
           timeout_seconds=10, configuration=None):
    """Search only after explicit caller authorization; no consent is persisted.

    `transport` may be a callable receiving `(request, timeout_seconds)` and
    returning a response-like object with `read()`, or an opener with `open()`.
    Results contain only title, URL, snippet and source metadata. Status and
    error values are sanitized and never include the credential or response body.
    """
    if not authorized:
        return {'status': 'unauthorized', 'results': [], 'error': None}

    config = configuration or web_search_configuration()
    if not getattr(config, 'api_key_configured', False):
        return {'status': 'missing_key', 'results': [], 'error': None}

    try:
        limit = min(MAX_RESULTS, max(0, int(max_results)))
    except (TypeError, ValueError, OverflowError):
        limit = MAX_RESULTS
    if not limit:
        return {'status': 'empty', 'results': [], 'error': None}
    if not isinstance(query, str) or not query.strip():
        return {'status': 'invalid_query', 'results': [], 'error': None}

    key = str(os.environ.get('BRAVE_API_KEY', '')).strip()
    if not key or key.upper().startswith(('PASTE_', 'YOUR_', 'REPLACE_')):
        return {'status': 'missing_key', 'results': [], 'error': None}

    params = urllib.parse.urlencode({'q': query.strip(), 'count': limit})
    request = urllib.request.Request(
        f'{BRAVE_SEARCH_ENDPOINT}?{params}',
        headers={'Accept': 'application/json', 'X-Subscription-Token': key}, method='GET')
    try:
        if transport is None:
            raise RuntimeError('Injected transport is required for authorized search.')
        if callable(transport):
            response = transport(request, timeout_seconds)
        else:
            response = transport.open(request, timeout=timeout_seconds)
        context = response if hasattr(response, '__enter__') else _ResponseContext(response)
        with context as opened:
            payload = json.loads(opened.read(1_048_577))
    except (TimeoutError, socket.timeout):
        return {'status': 'timeout', 'results': [], 'error': 'timeout'}
    except urllib.error.HTTPError as error:
        try:
            error.close()
        except Exception:
            pass
        return {'status': 'http_error', 'results': [], 'error': 'http_error'}
    except urllib.error.URLError as error:
        if isinstance(getattr(error, 'reason', None), (TimeoutError, socket.timeout)):
            return {'status': 'timeout', 'results': [], 'error': 'timeout'}
        return {'status': 'http_error', 'results': [], 'error': 'http_error'}
    except (OSError, ValueError, TypeError):
        return {'status': 'http_error', 'results': [], 'error': 'http_error'}

    try:
        items = payload.get('web', {}).get('results', [])
    except (AttributeError, TypeError):
        return {'status': 'http_error', 'results': [], 'error': 'invalid_response'}
    results = []
    for item in items:
        if not isinstance(item, dict):
            continue
        title, url, snippet = item.get('title'), item.get('url'), item.get('description')
        if not all(isinstance(value, str) for value in (title, url, snippet)):
            continue
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != 'https' or not parsed.hostname:
            continue
        results.append({'title': title[:500], 'url': url[:2048], 'snippet': snippet[:2000],
                        'source': {'provider': 'brave', 'domain': parsed.hostname[:253]}})
        if len(results) >= limit:
            break
    return {'status': 'ok' if results else 'empty', 'results': results, 'error': None}


class _ResponseContext:
    def __init__(self, response):
        self.response = response

    def __enter__(self):
        return self.response

    def __exit__(self, exc_type, exc, traceback):
        close = getattr(self.response, 'close', None)
        if close:
            close()
        return False
