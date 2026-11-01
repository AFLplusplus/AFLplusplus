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
    """An incomplete or invalid model response; not evidence of a RAM failure."""

_REQUEST_LOCK = threading.Lock()

@dataclass(frozen=True)
class ModelConfig:
    base_url: str = 'http://127.0.0.1:11434/v1'
    model: str = DEFAULT_LOCAL_MODEL
    timeout: float = 180
    allow_remote: bool = False
    reasoning_effort: str | None = 'none'

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

    @property
    def local(self):
        return urlsplit(self.base_url).hostname in ('127.0.0.1', 'localhost', '::1')

    @classmethod
    def from_env(cls, *, allow_remote=False):
        endpoint = os.getenv('BRAIN_API_BASE', 'http://127.0.0.1:11434/v1').rstrip('/')
        effort = os.getenv('BRAIN_REASONING_EFFORT')
        if effort is None:
            effort = 'none' if urlsplit(endpoint).port == 11434 else None
        return cls(endpoint, os.getenv('BRAIN_MODEL', DEFAULT_LOCAL_MODEL),
                   float(os.getenv('BRAIN_TIMEOUT_SECONDS', '180')), allow_remote, effort or None)

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
    if config.local and urlsplit(config.base_url).port == 11434:
        # Check before any request; an installed or resident model does not bypass the guard.
        memory = available_memory_gib()
        threshold = policy_for(config.model).minimum_available_gib
        if memory is None:
            raise MemoryGuardError('Local inference is on hold because available physical RAM cannot be verified.')
        if memory < threshold:
            raise MemoryGuardError(f'Local inference is on hold: {memory:.2f} GiB RAM is available; '
                                   f'{config.model} requires at least {threshold:.1f} GiB available before a request. '
                                   'No generation request was sent.')
    body = {'model': config.model, 'messages': messages, 'temperature': 0.3,
            'max_tokens': policy_for(config.model).output_tokens, 'stream': False,
            'response_format': {'type': 'json_schema', 'json_schema': {
                'name': 'emotional_decision', 'strict': True, 'schema': schema}}}
    if config.reasoning_effort:
        body['reasoning_effort'] = config.reasoning_effort
    headers = {'Content-Type': 'application/json'}
    # Local Ollama needs no credential. Only enterprise requests use the configured secret.
    if not config.local and os.getenv('BRAIN_API_KEY'):
        headers['Authorization'] = 'Bearer ' + os.environ['BRAIN_API_KEY']
    request = urllib.request.Request(config.base_url.rstrip('/') + '/chat/completions',
                                     data=json.dumps(body).encode('utf-8'), headers=headers, method='POST')
    started = time.perf_counter()
    try:
        with opener_for(config).open(request, timeout=config.timeout) as response:
            raw = response.read(1_048_577)
        if len(raw) > 1_048_576:
            raise ModelOutputError('Model response exceeded the response-size limit.')
        payload = json.loads(raw)
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
