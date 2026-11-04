"""OpenAI Responses API adapter with exact-payload one-shot authorization."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .providers import InferenceRequest, InferenceResult, ProviderID

OPENAI_ENDPOINT = 'https://api.openai.com/v1/responses'
MAX_OPENAI_CONTEXT_CHARS = 36000
OPENAI_MODEL_PRICING_USD_PER_MILLION = {}


def estimate_openai_cost(model, input_tokens, output_tokens):
    """Estimate only with explicitly verified, locally configured model prices."""
    prices = OPENAI_MODEL_PRICING_USD_PER_MILLION.get(model)
    if (not isinstance(prices, dict) or input_tokens is None or output_tokens is None
            or type(input_tokens) is not int or type(output_tokens) is not int
            or input_tokens < 0 or output_tokens < 0):
        return None
    try:
        input_rate, output_rate = prices['input'], prices['output']
        if (isinstance(input_rate, bool) or isinstance(output_rate, bool)
                or not isinstance(input_rate, (int, float)) or not isinstance(output_rate, (int, float))
                or input_rate < 0 or output_rate < 0):
            return None
        return (input_tokens * input_rate + output_tokens * output_rate) / 1_000_000
    except (KeyError, TypeError, ValueError):
        return None


@dataclass(frozen=True)
class OpenAIConfiguration:
    model: str
    api_key_configured: bool
    errors: tuple[str, ...]
    endpoint: str = OPENAI_ENDPOINT
    api_key: str | None = None

    def __repr__(self):
        return (f'OpenAIConfiguration(model={self.model!r}, api_key_configured={self.api_key_configured!r}, '
                f'errors={self.errors!r}, endpoint={self.endpoint!r})')

    @property
    def configured(self):
        return not self.errors

    def __str__(self):
        return self.__repr__()


def openai_readiness(configuration=None):
    """Report local OpenAI configuration readiness, never provider connectivity.

    The function reads environment configuration only when no configuration
    object is supplied and does not perform network requests.
    """
    if configuration is None:
        try:
            config = openai_configuration()
        except Exception:
            return {'status': 'UNAVAILABLE', 'reason': 'invalid_configuration'}
    else:
        config = configuration
    if not isinstance(config, OpenAIConfiguration):
        return {'status': 'UNAVAILABLE', 'reason': 'invalid_configuration'}
    if config.errors:
        if any('API key' in error for error in config.errors):
            return {'status': 'UNAVAILABLE', 'reason': 'missing_key'}
        if any('model is not configured' in error for error in config.errors):
            return {'status': 'UNAVAILABLE', 'reason': 'missing_model'}
        return {'status': 'UNAVAILABLE', 'reason': 'invalid_configuration'}
    if not config.api_key_configured:
        return {'status': 'UNAVAILABLE', 'reason': 'missing_key'}
    if not config.model:
        return {'status': 'UNAVAILABLE', 'reason': 'missing_model'}
    return {'status': 'AVAILABLE', 'reason': None}


def openai_configuration(*, environ=None):
    """Inspect environment only; no discovery or network request is performed."""
    env = os.environ if environ is None else environ
    model = str(env.get('SOVEREIGN_OPENAI_MODEL', '')).strip()
    if (not model or len(model) > 120 or any(ord(char) < 32 for char in model)
            or any(char in model for char in ('/', '\\', '?', '#'))):
        model = ''
    if model.upper().startswith(('YOUR_', 'PASTE_', 'REPLACE_')):
        model = ''
    raw_key = str(env.get('OPENAI_API_KEY', '')).strip()
    key_present = bool(raw_key and not raw_key.upper().startswith(('PASTE_', 'YOUR_', 'REPLACE_')))
    errors = []
    if not key_present:
        errors.append('OpenAI API key is not configured.')
    if not model:
        errors.append('OpenAI model is not configured; set SOVEREIGN_OPENAI_MODEL to a model enabled for your account.')
    return OpenAIConfiguration(model, key_present, tuple(errors), api_key=raw_key if key_present else None)


def responses_payload(request: InferenceRequest):
    """Build a text-only Responses request. Tools and storage are explicitly disabled."""
    if not request.model or not request.messages:
        raise ValueError('OpenAI request requires a model and input messages.')
    if type(request.max_output_tokens) is not int or not 1 <= request.max_output_tokens <= 768:
        raise ValueError('OpenAI output token limit is outside the application safety cap.')
    instructions, content = [], []
    for message in request.messages:
        if not isinstance(message, dict):
            raise ValueError('OpenAI request messages must be text-only conversation roles.')
        role, text = message.get('role'), message.get('content')
        if role == 'system':
            role = 'developer'
        if not isinstance(text, str):
            raise ValueError('OpenAI request messages must be text-only conversation roles.')
        if not text.strip():
            continue
        if role not in ('developer', 'user', 'assistant'):
            raise ValueError('OpenAI request messages must be text-only conversation roles.')
        if role == 'developer':
            instructions.append(text)
        else:
            content.append({'role': role, 'content': [{'type': 'input_text', 'text': text}]})
    if not content:
        raise ValueError('OpenAI request has no user or assistant input.')
    if sum(len(item['content'][0]['text']) for item in content) + sum(map(len, instructions)) > MAX_OPENAI_CONTEXT_CHARS:
        raise ValueError('OpenAI context exceeds the configured size limit.')
    payload = {'model': request.model, 'input': content, 'store': False,
               'tools': [], 'max_output_tokens': request.max_output_tokens}
    if instructions:
        payload['instructions'] = '\n\n'.join(instructions)
    if request.json_schema:
        payload['text'] = {'format': {'type': 'json_schema', 'name': 'sovereign_reasoning_v1',
                                      'strict': True, 'schema': request.json_schema}}
    return payload


def _output_text(payload):
    direct = payload.get('output_text')
    if isinstance(direct, str) and direct.strip():
        return direct
    chunks = []
    for item in payload.get('output') or []:
        if not isinstance(item, dict):
            continue
        for part in item.get('content') or []:
            if isinstance(part, dict) and part.get('type') in ('output_text', 'text'):
                if isinstance(part.get('text'), str):
                    chunks.append(part['text'])
    return ''.join(chunks)


def _error_category(status, diagnostic=''):
    text = diagnostic.casefold()
    if any(word in text for word in ('insufficient_quota', 'billing', 'credits', 'quota')):
        return 'insufficient_credits_or_quota'
    if status == 401:
        return 'authentication'
    if status == 403:
        return 'account_or_model_access'
    if status == 429:
        return 'rate_limit'
    if status in (400, 404, 422):
        return 'account_or_model_access' if any(w in text for w in ('model', 'permission', 'access')) else 'invalid_request'
    if status >= 500:
        return 'provider_unavailable'
    return 'provider_http_error'


class OpenAIResponsesProvider:
    provider_id = ProviderID.OPENAI_CLOUD

    def __init__(self, *, model, api_key, endpoint=OPENAI_ENDPOINT, timeout_seconds=60,
                 max_output_tokens=768, opener=None):
        parsed = urlsplit(endpoint)
        if (parsed.scheme != 'https' or parsed.hostname != 'api.openai.com'
                or parsed.path.rstrip('/') != '/v1/responses' or parsed.username or parsed.password
                or parsed.port not in (None, 443) or parsed.query or parsed.fragment
                or endpoint != OPENAI_ENDPOINT):
            raise ValueError('OpenAI endpoint must be the official HTTPS Responses API endpoint.')
        if (not isinstance(model, str) or not model.strip() or len(model) > 120
                or any(ord(char) < 32 for char in model)
                or any(char in model for char in ('/', '\\', '?', '#'))
                or not isinstance(api_key, str) or not api_key.strip()
                or type(timeout_seconds) not in (int, float) or not 1 <= timeout_seconds <= 180):
            raise ValueError('OpenAI configuration is incomplete or invalid.')
        if type(max_output_tokens) is not int or not 1 <= max_output_tokens <= 768:
            raise ValueError('OpenAI output token limit is invalid.')
        self.endpoint, self.model, self._api_key = endpoint, model, api_key
        self.timeout_seconds, self.max_output_tokens = timeout_seconds, max_output_tokens
        self.reported_cost_usd = None
        self._lock = threading.Lock()
        self._opener = opener or urllib.request.build_opener(_NoRedirect())
        self._approved = None
        self._used = set()

    @staticmethod
    def payload(request):
        return responses_payload(request)

    @classmethod
    def fingerprint(cls, request):
        canonical = json.dumps(cls.payload(request), sort_keys=True, ensure_ascii=False, separators=(',', ':'))
        return hashlib.sha256(canonical.encode('utf-8')).hexdigest()

    def authorize_once(self, request, approved_fingerprint):
        fingerprint = self.fingerprint(request)
        if not hmac.compare_digest(fingerprint, approved_fingerprint):
            raise PermissionError('Approval does not match the exact OpenAI payload.')
        with self._lock:
            if fingerprint in self._used or self._approved is not None:
                raise PermissionError('Approved OpenAI request was already executed or is pending.')
            self._approved = fingerprint

    def authorize_payload_once(self, payload):
        """Authorize the canonical Responses payload already bound to cloud consent."""
        if not isinstance(payload, dict):
            raise PermissionError('Approval does not match the exact OpenAI Responses payload.')
        try:
            canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
        except (TypeError, ValueError) as error:
            raise PermissionError('Approval does not match the exact OpenAI Responses payload.') from error
        fingerprint = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
        if (payload.get('model') != self.model or payload.get('store') is not False
                or payload.get('tools') != [] or payload.get('max_output_tokens') != self.max_output_tokens):
            raise PermissionError('Approval does not match the exact OpenAI Responses payload.')
        with self._lock:
            if fingerprint in self._used or self._approved is not None:
                raise PermissionError('Approved OpenAI request was already executed or is pending.')
            self._approved = fingerprint

    def infer(self, request):
        fingerprint = self.fingerprint(request)
        body = self.payload(request)
        canonical_payload = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(',', ':'))
        payload_fingerprint = hashlib.sha256(canonical_payload.encode('utf-8')).hexdigest()
        with self._lock:
            approved_fingerprint = self._approved
            if approved_fingerprint not in (fingerprint, payload_fingerprint) or fingerprint in self._used:
                raise PermissionError('Explicit approval is required for this exact OpenAI request.')
            self._approved = None
            self._used.add(fingerprint)
            self._used.add(payload_fingerprint)
        started = time.perf_counter()
        try:
            req = urllib.request.Request(
                self.endpoint, data=json.dumps(body, ensure_ascii=False, separators=(',', ':')).encode('utf-8'),
                headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + self._api_key}, method='POST')
            with self._opener.open(req, timeout=min(self.timeout_seconds, request.timeout_seconds)) as response:
                raw = response.read(1_048_577)
            if len(raw) > 1_048_576:
                raise _ResponseFailure('malformed_response')
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise _ResponseFailure('malformed_response')
            if payload.get('status') not in (None, 'completed') or payload.get('incomplete_details'):
                raise _ResponseFailure('incomplete_response')
            text = _output_text(payload)
            if not text.strip():
                raise _ResponseFailure('empty_response')
            structured = None
            if request.json_schema:
                structured = json.loads(text)
                if not isinstance(structured, dict):
                    raise _ResponseFailure('malformed_structured_output')
                validator = getattr(self, '_schema_validator', None)
                if validator is None:
                    try:
                        from .decision import validate_schema
                    except (ImportError, AttributeError):
                        validate_schema = None
                    if validate_schema is None:
                        validator = _validate_json_schema
                    elif _schema_matches_validator(request.json_schema):
                        validator = validate_schema
                    else:
                        validator = _validate_json_schema
                try:
                    validator(structured, request.json_schema)
                except (AttributeError, TypeError, ValueError, KeyError) as error:
                    raise _ResponseFailure('malformed_structured_output') from error
            usage = payload.get('usage') if isinstance(payload.get('usage'), dict) else {}
            input_tokens, output_tokens = usage.get('input_tokens'), usage.get('output_tokens')
            if type(input_tokens) is not int or input_tokens < 0:
                input_tokens = None
            if type(output_tokens) is not int or output_tokens < 0:
                output_tokens = None
            response_id = payload.get('id') if isinstance(payload.get('id'), str) else None
            return InferenceResult(self.provider_id, request.model, text, structured, 'success', None,
                time.perf_counter() - started, input_tokens, output_tokens, response_id,
                estimate_openai_cost(request.model, input_tokens, output_tokens), True, True)
        except _ResponseFailure as error:
            category = error.category
        except urllib.error.HTTPError as error:
            try:
                diagnostic = error.read(8192).decode('utf-8', errors='replace')
            except Exception:
                diagnostic = ''
            category = _error_category(error.code, diagnostic)
            error.close()
        except (TimeoutError, socket.timeout):
            category = 'timeout'
        except urllib.error.URLError:
            category = 'connection'
        except (ssl.SSLError, ConnectionError, OSError):
            category = 'connection'
        except json.JSONDecodeError:
            category = 'malformed_structured_output' if request.json_schema else 'malformed_response'
        except (ValueError, KeyError, IndexError, TypeError, UnicodeError):
            category = 'malformed_response'
        except Exception:
            category = 'provider_exception'
        return InferenceResult(self.provider_id, request.model, '', None, 'failed', category,
            time.perf_counter() - started, None, None, None, None, True, True)


def _schema_matches_validator(schema):
    """The app's compact validator expects additional internal bounds on strings/arrays."""
    if not isinstance(schema, dict):
        return False
    kind = schema.get('type')
    if kind == 'object':
        return all(_schema_matches_validator(child) for child in schema.get('properties', {}).values())
    if kind == 'array':
        return all(key in schema for key in ('minItems', 'maxItems')) and _schema_matches_validator(schema.get('items'))
    if kind == 'string':
        return 'minLength' in schema and 'maxLength' in schema
    if kind == 'number':
        return 'minimum' in schema and 'maximum' in schema
    return False


def _validate_json_schema(value, schema):
    """Fail-closed validator for the JSON Schema subset emitted by this adapter."""
    if not isinstance(schema, dict) or schema.get('type') != 'object':
        raise ValueError('Unsupported structured-output schema.')
    if not isinstance(value, dict) or set(value) != set(schema.get('properties', {})):
        raise ValueError('Structured output fields do not match the schema.')

    def validate(item, spec):
        kind = spec.get('type')
        if kind == 'object':
            if not isinstance(item, dict) or set(item) != set(spec.get('properties', {})):
                raise ValueError('Invalid object fields.')
            for key, child in spec['properties'].items():
                validate(item[key], child)
        elif kind == 'array':
            if not isinstance(item, list):
                raise ValueError('Expected an array.')
            if not spec.get('minItems', 0) <= len(item) <= spec.get('maxItems', len(item)):
                raise ValueError('Array size is invalid.')
            for child in item:
                validate(child, spec['items'])
        elif kind == 'string':
            if not isinstance(item, str) or not spec.get('minLength', 0) <= len(item) <= spec.get('maxLength', len(item)):
                raise ValueError('String length is invalid.')
        elif kind == 'number':
            if isinstance(item, bool) or not isinstance(item, (int, float)):
                raise ValueError('Expected a number.')
            if not spec.get('minimum', item) <= item <= spec.get('maximum', item):
                raise ValueError('Number is out of range.')
        else:
            raise ValueError('Unsupported schema type.')

    for key, spec in schema['properties'].items():
        validate(value[key], spec)


class _ResponseFailure(ValueError):
    def __init__(self, category):
        super().__init__(category)
        self.category = category


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        raise urllib.error.URLError('redirects disabled')
