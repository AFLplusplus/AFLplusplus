"""Mock-only tests for the permission-gated Brave Search adapter."""
from pathlib import Path
import io
import json
import os
import sys
import unittest
import urllib.error
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from brain_core import web_search


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self, size=-1):
        return json.dumps(self.payload).encode()


class WebSearchTests(unittest.TestCase):
    def test_configuration_detects_missing_and_present_key_without_exposing_it(self):
        self.assertFalse(web_search.web_search_configuration(environ={}).api_key_configured)
        config = web_search.web_search_configuration(environ={'BRAVE_API_KEY': 'synthetic-test-key'})
        self.assertTrue(config.api_key_configured)
        self.assertNotIn('synthetic-test-key', repr(config))

    def test_missing_key_returns_sanitized_status_without_transport(self):
        with patch.dict(os.environ, {'BRAVE_API_KEY': ''}, clear=False):
            result = web_search.search('synthetic query', authorized=True,
                                       transport=lambda *_: self.fail('transport called'))
        self.assertEqual(result, {'status': 'missing_key', 'results': [], 'error': None})

    def test_unauthorized_request_never_calls_transport(self):
        with patch.dict(os.environ, {'BRAVE_API_KEY': 'synthetic-test-key'}, clear=False):
            result = web_search.search('synthetic query', transport=lambda *_: self.fail('transport called'))
        self.assertEqual(result, {'status': 'unauthorized', 'results': [], 'error': None})

    def test_success_returns_structured_results_limited_to_five(self):
        payload = {'web': {'results': [
            {'title': f'Result {index}', 'url': f'https://example{index}.test/page',
             'description': f'Snippet {index}'} for index in range(8)]}}
        calls = []
        def transport(request, timeout):
            calls.append((request, timeout))
            return FakeResponse(payload)
        with patch.dict(os.environ, {'BRAVE_API_KEY': 'synthetic-test-key'}, clear=False):
            result = web_search.search('synthetic query', authorized=True, transport=transport)
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(len(result['results']), 5)
        self.assertEqual(set(result['results'][0]), {'title', 'url', 'snippet', 'source'})
        self.assertEqual(result['results'][0]['source']['provider'], 'brave')
        self.assertEqual(calls[0][1], 10)
        self.assertEqual(calls[0][0].get_header('X-subscription-token'), 'synthetic-test-key')

    def test_timeout_is_sanitized(self):
        with patch.dict(os.environ, {'BRAVE_API_KEY': 'synthetic-test-key'}, clear=False):
            result = web_search.search('synthetic query', authorized=True,
                                       transport=lambda *_: (_ for _ in ()).throw(TimeoutError()))
        self.assertEqual(result, {'status': 'timeout', 'results': [], 'error': 'timeout'})

    def test_http_error_is_sanitized_and_empty_results_have_empty_status(self):
        def failure(*_):
            raise urllib.error.HTTPError('https://example.test', 403, 'private details', {}, io.BytesIO())
        with patch.dict(os.environ, {'BRAVE_API_KEY': 'synthetic-test-key'}, clear=False):
            failed = web_search.search('synthetic query', authorized=True, transport=failure)
            empty = web_search.search('synthetic query', authorized=True,
                                       transport=lambda *_: FakeResponse({'web': {'results': []}}))
        self.assertEqual(failed, {'status': 'http_error', 'results': [], 'error': 'http_error'})
        self.assertEqual(empty, {'status': 'empty', 'results': [], 'error': None})


if __name__ == '__main__':
    unittest.main()
