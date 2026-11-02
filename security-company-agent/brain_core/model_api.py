"""Replaceable OpenAI-compatible transport; no agent execution or provider logs."""
from __future__ import annotations
from dataclasses import dataclass
import json
import os
import socket
import time
import threading
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from .runtime_guard import available_memory_gib
from .model_policy import DEFAULT_LOCAL_MODEL, policy_for

class ModelError(RuntimeError):
    """A safe, user-facing error; excludes response bodies, prompts and credentials."""

class MemoryGuardError(ModelError):
    """Resource limit failure, distinct from structured model-output failure."""

class ModelOutputError(ModelError):
    """Safe validation error with a stable optional diagnostic reference."""

    def __init__(self, message, *, diagnostic_id=None):
        super().__init__(message)
        self.diagnostic_id = diagnostic_id

_REQUEST_LOCK = threading.Lock()

@dataclass(frozen=True)
class ModelConfig:
    base_url: str = 'http://127.0.0.1:11434/v1'
    model: str = DEFAULT_LOCAL_MODEL
    timeout: float = 180
    allow_remote: bool = False
    reasoning_effort: str | None = 'none'
    max_output_tokens: int | None = None
    context_tokens: int | None = None
    keep_alive_seconds: int | None = None

    def __post_init__(self):
        parsed = urlsplit(self.base_url)
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ModelError('Model endpoint must not contain credentials, query strings or fragments.')
        try:
            parsed.port
        except ValueError:
            raise ModelError('Invalid model endpoint port.') from None
        if not parsed.hostname or parsed.path.rstrip('/') != '/v1':
            raise ModelError('Model endpoint must be an absolute URL ending in /v1.')
        if parsed.scheme != 'https' and not (parsed.scheme == 'http' and self.local):
            raise ModelError('Use HTTPS for enterprise gateways; HTTP is allowed only on loopback.')
        if not self.local and not self.allow_remote:
            raise ModelError('Remote inference requires explicit authorization for session data and references.')
        if not self.model.strip() or not 1 <= self.timeout <= 600:
            raise ModelError('Invalid model name or timeout.')
        for name, value in (('output', self.max_output_tokens), ('context', self.context_tokens)):
            if value is not None and (type(value) is not int or value < 1):
                raise ModelError(f'Invalid {name} token setting.')
        if self.keep_alive_seconds is not None and type(self.keep_alive_seconds) is not int:
            raise ModelError('Invalid keep-alive setting.')

    @property
    def local(self):
        return urlsplit(self.base_url).hostname in ('127.0.0.1', 'localhost', '::1')

    @classmethod
    def from_env(cls, *, allow_remote=False):
        endpoint = os.getenv('BRAIN_API_BASE', 'http://127.0.0.1:11434/v1').rstrip('/')
        effort = os.getenv('BRAIN_REASONING_EFFORT')
        if effort is None:
            effort = 'none' if urlsplit(endpoint).port == 11434 else None
        model = os.getenv('BRAIN_MODEL', DEFAULT_LOCAL_MODEL)
        policy = policy_for(model)
        return cls(endpoint, model, float(os.getenv('BRAIN_TIMEOUT_SECONDS', '180')),
                   allow_remote, effort or None,
                   min(policy.output_tokens, int(os.getenv('BRAIN_MAX_OUTPUT_TOKENS', '0')) or policy.output_tokens),
                   min(policy.context_tokens, int(os.getenv('BRAIN_CONTEXT_TOKENS', '0')) or policy.context_tokens),
                   min(policy.keep_alive_seconds, int(os.getenv('BRAIN_KEEP_ALIVE_SECONDS', '0'))))

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ModelError('Model endpoint redirects are disabled to protect session data.')

def opener_for(config):
    handlers = [NoRedirect()]
    if config.local:
        handlers.append(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(*handlers)

def complete(messages, config, schema):
    # Prevent multiple callers in this process from queueing concurrent inference.
    with _REQUEST_LOCK:
        return _complete(messages, config, schema)

def _complete(messages, config, schema):
    local_ollama = config.local and urlsplit(config.base_url).port == 11434
    policy = policy_for(config.model)
    if local_ollama:
        # Check before every request; an installed or resident model does not bypass the guard.
        memory = available_memory_gib()
        if memory is None:
            raise MemoryGuardError('Local inference is on hold because available physical RAM cannot be verified.')
        if memory < policy.minimum_available_gib:
            raise MemoryGuardError(f'Local inference is on hold: {memory:.2f} GiB RAM is available; '
                                   f'{config.model} requires at least {policy.minimum_available_gib:.1f} GiB available before a request. '
                                   'No generation request was sent.')
        # Ollama's native API is required to enforce request-scoped context and residency.
        base_endpoint = config.base_url.rsplit('/v1', 1)[0].rstrip('/')
        endpoint = base_endpoint + '/api/chat'
        body = {'model': config.model, 'messages': messages, 'stream': False,
                'format': schema,
                'options': {'temperature': 0.3,
                            'num_ctx': min(policy.context_tokens,
                                           config.context_tokens or policy.context_tokens),
                            'num_predict': min(policy.output_tokens,
                                               config.max_output_tokens or policy.output_tokens)},
                'keep_alive': min(policy.keep_alive_seconds,
                                  config.keep_alive_seconds if config.keep_alive_seconds is not None else 0)}
    else:
        # Non-local integrations retain the OpenAI-compatible response contract.
        body = {'model': config.model, 'messages': messages, 'temperature': 0.3,
                'max_tokens': min(policy.output_tokens, config.max_output_tokens or policy.output_tokens), 'stream': False,
                'response_format': {'type': 'json_schema', 'json_schema': {
                    'name': 'emotional_decision', 'strict': True, 'schema': schema}}}
        if config.reasoning_effort:
            body['reasoning_effort'] = config.reasoning_effort
        endpoint = config.base_url.rstrip('/') + '/chat/completions'
    headers = {'Content-Type': 'application/json'}
    # Local Ollama needs no credential. Only enterprise requests use the configured secret.
    if not config.local and os.getenv('BRAIN_API_KEY'):
        headers['Authorization'] = 'Bearer ' + os.environ['BRAIN_API_KEY']
    request = urllib.request.Request(endpoint, data=json.dumps(body).encode('utf-8'),
                                     headers=headers, method='POST')
    started = time.perf_counter()
    try:
        with opener_for(config).open(request, timeout=config.timeout) as response:
            raw = response.read(1_048_577)
        if len(raw) > 1_048_576:
            raise ModelOutputError('Model response exceeded the response-size limit.')
        payload = json.loads(raw)
        if local_ollama:
            if payload.get('done_reason') == 'length':
                raise ModelOutputError('Model output was truncated. Shorten references or increase the output budget.')
            content = payload['message']['content']
        else:
            choice = payload['choices'][0]
            if choice.get('finish_reason') == 'length':
                raise ModelOutputError('Model output was truncated. Shorten references or increase the output budget.')
            content = choice['message']['content']
        if not isinstance(content, str) or not content.strip():
            raise ModelOutputError('Model returned no structured answer.')
        result = json.loads(content)
        if not isinstance(result, dict):
            raise ModelOutputError('Model output must be a JSON object.')
        return result, {'model': config.model, 'seconds': round(time.perf_counter() - started, 3),
                        'source': 'local_model' if config.local else 'authorized_gateway'}
    except urllib.error.HTTPError as error:
        status = error.code
        diagnostic = error.read(16384).decode('utf-8', errors='replace').casefold()
        error.close()
        if local_ollama and status in (404, 405):
            raise ModelError('Ollama native chat endpoint is unavailable; no compatibility fallback was attempted.') from None
        if status >= 500 and any(marker in diagnostic for marker in (
                'out of memory', 'requires more system memory', 'unable to allocate', 'insufficient memory')):
            raise MemoryGuardError('The local model service reported insufficient memory. '
                                   'No automatic retry or replacement model will be attempted.') from None
        raise ModelError(f'Model service returned HTTP {status}. Check model availability and configuration.') from None
    except (TimeoutError, socket.timeout):
        raise ModelError('Model request timed out. Your saved history is unchanged.') from None
    except urllib.error.URLError:
        raise ModelError('Cannot connect to the model service. Check that it is running on the configured endpoint.') from None
    except (ValueError, KeyError, IndexError, TypeError, UnicodeError):
        raise ModelOutputError('Model returned invalid structured output. No training turn was saved.') from None

def local_inventory(timeout=2):
    config = ModelConfig()
    try:
        with opener_for(config).open('http://127.0.0.1:11434/api/tags', timeout=timeout) as response:
            return [item['name'] for item in json.load(response).get('models', [])]
    except (OSError, ValueError, KeyError):
        return []

def ollama_server_info(timeout=2):
    """Return safe native Ollama runtime details without loading a model."""
    config = ModelConfig()
    result = {'version': None, 'loaded_models': None, 'parallel_setting': 'unknown'}
    try:
        opener = opener_for(config)
        with opener.open('http://127.0.0.1:11434/api/version', timeout=timeout) as response:
            result['version'] = json.load(response).get('version')
        with opener.open('http://127.0.0.1:11434/api/ps', timeout=timeout) as response:
            result['loaded_models'] = json.load(response).get('models', [])
    except (OSError, ValueError, KeyError):
        return result
    # OLLAMA_NUM_PARALLEL is server-process configuration; the HTTP API does not expose it.
    return result
