"""Testable application service for exact-payload cloud fallback approval."""
from __future__ import annotations

from dataclasses import dataclass
import hmac
import json
import threading
from typing import Any, Callable
from urllib.parse import urlsplit

from .cloud_consent import CloudApprovalManager, CloudBudget, approximate_token_count
from .providers import InferenceRequest


@dataclass(frozen=True)
class CloudRequest:
    """An immutable, UI-safe handle to a registered one-time approval."""
    approval_id: str
    fingerprint: str
    conversation_id: str
    provider: str
    model: str
    region: str
    endpoint: str
    payload_json: str
    token_estimate: int
    max_output_tokens: int

    @property
    def preview(self) -> dict[str, Any]:
        return json.loads(self.payload_json)


@dataclass(frozen=True)
class CloudExecution:
    request: CloudRequest
    result: Any


class CloudOrchestrationError(RuntimeError):
    """Safe orchestration failure with no implied retry or authorization."""

    DIAGNOSTICS = frozenset({'authorization', 'request_execution', 'response_validation', 'unknown'})

    SUBSTAGES = frozenset({
        'provider_construction', 'authorization_setup', 'adapter_inference',
        'result_accounting', 'unknown'
    })

    def __init__(self, message: str, *, diagnostic: str = 'unknown', substage: str = 'unknown'):
        super().__init__(message)
        self.diagnostic = (diagnostic if isinstance(diagnostic, str) and diagnostic in self.DIAGNOSTICS
                           else 'unknown')
        self.substage = (substage if isinstance(substage, str) and substage in self.SUBSTAGES
                         else 'unknown')


class CloudOrchestrator:
    """Coordinates cloud request preparation and single-use execution."""
    PROVIDER = 'alibaba_qwen_cloud'

    def __init__(self, *, consent: CloudApprovalManager,
                 payload_factory: Callable[..., tuple[Any, str, dict, dict]],
                 provider_factory: Callable[..., Any], api_key: Callable[[], str],
                 provider_payload: Callable[[dict, Any], dict] | None = None,
                 provider_fingerprint: Callable[[Any, dict], str] | None = None,
                 result_writer: Callable[..., Any] | None = None,
                 token_counter: Callable[[str], int] = approximate_token_count,
                 budget: CloudBudget = CloudBudget(), result_accountant=None,
                 provider: str | None = None, region: str = 'global',
                 provider_settings: Callable[[], Any] | None = None,
                 request_timeout_seconds: int = 60,
                 validate_payload: Callable[[dict, dict], bool] | None = None):
        self._consent = consent
        self._payload_factory = payload_factory
        self._provider_factory = provider_factory
        self._api_key = api_key
        self._provider_request_payload = provider_payload or (lambda payload, request: payload)
        self._provider_fingerprint = provider_fingerprint or (lambda request, payload: provider_factory.fingerprint(request))
        self._result_writer = result_writer
        self._result_accountant = result_accountant
        self._provider = provider or self.PROVIDER
        self._region = region
        self._provider_settings_mode = provider_settings is not None or provider == 'openai_cloud'
        self._provider_settings = provider_settings
        self._settings_factory = provider_settings
        if type(request_timeout_seconds) is not int or not 1 <= request_timeout_seconds <= 180:
            raise ValueError('Cloud request timeout is outside the safe range.')
        self._request_timeout_seconds = request_timeout_seconds
        self._validate_payload = validate_payload
        self._token_counter = token_counter
        self._budget = budget
        self._pending: dict[str, tuple[CloudRequest, Any, dict, dict, tuple]] = {}
        self._retired: set[str] = set()
        self._executing: set[str] = set()
        self._completed: set[str] = set()
        self._lock = threading.RLock()

    def get_pending_request(self, conversation_id: str) -> CloudRequest | None:
        with self._lock:
            item = self._pending.get(conversation_id)
            return item[0] if item else None

    def prepare_fallback(self, *, user_text: str, conversation_id: str,
                         profile: dict, approved_lessons: list,
                         local_error: Exception, eligible: bool = True) -> CloudRequest:
        if not eligible:
            raise CloudOrchestrationError('This local failure is not eligible for cloud fallback.')
        if not isinstance(local_error, Exception):
            raise TypeError('A local inference failure is required.')
        registered_approval = None
        try:
            if self._provider_settings is None:
                settings, endpoint, payload, schema = self._payload_factory(
                    user_text, profile, approved_lessons, session_id=conversation_id)
            else:
                settings = self._settings_factory()
                try:
                    payload, schema = self._payload_factory(
                        user_text, profile, approved_lessons, session_id=conversation_id, settings=settings)
                except TypeError as error:
                    if "settings" not in str(error):
                        raise
                    payload, schema = self._payload_factory(
                        user_text, profile, approved_lessons, session_id=conversation_id)
                endpoint = settings.endpoint
            if not getattr(settings, 'configured', False) or not getattr(settings, 'api_key_configured', False):
                raise CloudOrchestrationError('Cloud configuration is incomplete.')
            parsed = urlsplit(endpoint)
            if self._provider == 'openai_cloud':
                endpoint_ok = (endpoint == 'https://api.openai.com/v1/responses'
                               and parsed.scheme == 'https' and parsed.hostname == 'api.openai.com'
                               and parsed.port in (None, 443) and not parsed.username and not parsed.password
                               and not parsed.query and not parsed.fragment)
            else:
                endpoint_ok = (parsed.scheme == 'https' and not parsed.username and not parsed.password
                               and not parsed.netloc.endswith(':443') and not parsed.netloc.endswith(':80')
                               and ':' not in parsed.netloc and not parsed.query and not parsed.fragment
                               and bool(parsed.hostname))
            if not endpoint_ok:
                raise CloudOrchestrationError('Cloud endpoint is not a valid approved HTTPS endpoint.')
            frozen_payload = json.loads(json.dumps(payload, ensure_ascii=False))
            if self._provider == 'openai_cloud' and not isinstance(frozen_payload, dict):
                raise CloudOrchestrationError('OpenAI payload must be an object.')
            serialized = json.dumps(frozen_payload, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
            tokens = self._token_counter(serialized)
            approved_output_cap = int(frozen_payload.get('max_output_tokens',
                                      frozen_payload.get('max_tokens', self._budget.max_output_tokens)))
            configured_output_cap = (self._budget.max_output_tokens if self._provider == 'openai_cloud'
                                     else min(768, int(frozen_payload.get('max_tokens', 768))))
            if approved_output_cap > configured_output_cap:
                raise CloudOrchestrationError('Payload output cap exceeds its configured safety limit.')
            schema_format = frozen_payload.get('response_format', {})
            if 'text' in frozen_payload and isinstance(frozen_payload['text'], dict):
                schema_format = frozen_payload['text'].get('format', {})
            schema_spec = (schema_format.get('json_schema', schema_format)
                           if isinstance(schema_format, dict) else {})
            reasoning_schema = frozen_payload.get('reasoning_schema', schema)
            if frozen_payload.get('model') != settings.model or not isinstance(schema, dict):
                raise CloudOrchestrationError('Cloud payload does not match the approved reasoning request contract.')
            if self._validate_payload is not None:
                valid = self._validate_payload(frozen_payload, schema)
            elif self._provider == 'openai_cloud' and self._settings_factory is None:
                valid = (isinstance(frozen_payload.get('messages'), list)
                         and frozen_payload.get('stream') is False
                         and schema_format.get('type') == 'json_schema'
                         and schema_spec.get('strict') is True
                         and schema_spec.get('schema') == schema)
            elif self._provider == 'openai_cloud':
                valid = (isinstance(frozen_payload.get('input'), list)
                         and frozen_payload.get('input')
                         and all(isinstance(item, dict) and item.get('role') in ('user', 'assistant')
                                 and isinstance(item.get('content'), list) and item.get('content')
                                 and all(isinstance(part, dict) and part.get('type') == 'input_text'
                                         and isinstance(part.get('text'), str) and bool(part.get('text').strip())
                                         for part in item['content']) for item in frozen_payload['input'])
                         and frozen_payload.get('store') is False
                         and (frozen_payload.get('instructions') is None
                              or isinstance(frozen_payload.get('instructions'), str))
                         and frozen_payload.get('tools') == []
                         and 1 <= frozen_payload.get('max_output_tokens', 0) <= self._budget.max_output_tokens
                         and isinstance(schema, dict)
                         and schema_format.get('type') == 'json_schema'
                         and schema_format.get('name') == ('sovereign_general_answer_v1'
                                                            if schema.get('properties', {}).get('answer', {}).get('type') == 'string'
                                                            else 'sovereign_reasoning_v1')
                         and schema_format.get('strict') is True
                         and schema_format.get('schema') == schema
                         and set(frozen_payload).issubset({'model', 'input', 'store', 'tools',
                                                           'max_output_tokens', 'instructions', 'text'}))
            else:
                valid = (isinstance(frozen_payload.get('messages'), list)
                         and frozen_payload.get('stream') is False
                         and frozen_payload.get('temperature') == 0.2
                         and schema_format.get('type') == 'json_schema'
                         and schema_spec.get('strict') is True
                         and schema_spec.get('schema') == reasoning_schema)

            if (self._provider == 'openai_cloud' and isinstance(schema, dict)
                    and schema.get('properties', {}).get('answer', {}).get('type') == 'string'):
                valid = (valid
                         and schema_format.get('name') == 'sovereign_general_answer_v1'
                         and schema_format.get('schema') == schema)
            if not valid:
                raise CloudOrchestrationError('Cloud payload does not match the approved reasoning request contract.')
            if self._provider == 'openai_cloud' and self._settings_factory is not None and int(frozen_payload.get('max_output_tokens', 0)) < 1:
                raise CloudOrchestrationError('OpenAI output token cap is missing or invalid.')
            if approved_output_cap > self._budget.max_output_tokens:
                raise CloudOrchestrationError('Payload output cap exceeds the application safety limit.')
            approval_payload = frozen_payload
            if self._provider == 'openai_cloud' and self._settings_factory is not None:
                if frozen_payload.get('tools') != [] or frozen_payload.get('store') is not False:
                    raise CloudOrchestrationError('OpenAI requests must disable tools and server-side storage.')
                from .openai_provider import InferenceRequest as _OpenAIRequest, responses_payload
                input_items = frozen_payload.get('input')
                if not isinstance(input_items, list) or not input_items:
                    raise CloudOrchestrationError('OpenAI request input is invalid.')
                approved_messages_list = []
                instructions = frozen_payload.get('instructions')
                if instructions is not None:
                    if not isinstance(instructions, str) or not instructions.strip():
                        raise CloudOrchestrationError('OpenAI instructions are invalid.')
                    approved_messages_list.append({'role': 'system', 'content': instructions})
                for item in input_items:
                    if not isinstance(item, dict) or item.get('role') not in ('user', 'assistant'):
                        raise CloudOrchestrationError('OpenAI input item is invalid.')
                    content_items = item.get('content')
                    if not isinstance(content_items, list) or not content_items:
                        raise CloudOrchestrationError('OpenAI input content is invalid.')
                    text_parts = []
                    for part in content_items:
                        if (not isinstance(part, dict) or part.get('type') != 'input_text'
                                or not isinstance(part.get('text'), str)):
                            raise CloudOrchestrationError('OpenAI accepts text input only.')
                        text_parts.append(part['text'])
                    approved_messages_list.append({'role': item['role'], 'content': ''.join(text_parts)})
                request_schema = frozen_payload.get('text', {}).get('format', {}).get('schema', schema)
                if not isinstance(request_schema, dict):
                    raise CloudOrchestrationError('OpenAI response schema is invalid.')
                approved_inference = _OpenAIRequest(
                    tuple(approved_messages_list), settings.model, approved_output_cap,
                    self._request_timeout_seconds, request_schema)
                canonical_response_payload = responses_payload(approved_inference)
                if canonical_response_payload != frozen_payload:
                    raise CloudOrchestrationError('OpenAI payload is not in its canonical approved form.')
                schema = request_schema
                approval_payload = frozen_payload
                serialized = json.dumps(frozen_payload, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
                tokens = self._token_counter(serialized)
            approval = self._consent.prepare(
                provider=self._provider, model=settings.model, region=getattr(settings, 'region', self._region),
                payload=approval_payload, session_id=conversation_id,
                token_estimate=tokens, prompt_tokens=tokens,
                estimated_cost_usd=None,
                budget=CloudBudget(
                    max_prompt_tokens=self._budget.max_prompt_tokens,
                    max_output_tokens=approved_output_cap,
                    max_estimated_cost_usd=self._budget.max_estimated_cost_usd,
                    session_limit_usd=self._budget.session_limit_usd,
                    daily_limit_usd=self._budget.daily_limit_usd))
            self._consent.register(approval)
            registered_approval = approval
            request = CloudRequest(
                approval.approval_id, approval.payload_fingerprint, conversation_id,
                self._provider, settings.model, getattr(settings, 'region', self._region), endpoint,
                serialized, tokens, approval.max_output_tokens)
            with self._lock:
                previous = self._pending.get(conversation_id)
                self._pending[conversation_id] = (
                    request, settings, schema, frozen_payload, tuple(approved_lessons))
            if previous is not None:
                self._retire(previous)
                with self._lock:
                    self._retired.add(previous[0].approval_id)
            return request
        except CloudOrchestrationError as error:
            if registered_approval is not None:
                self._retire_registered(registered_approval, frozen_payload, conversation_id)
            raise error
        except Exception as error:
            if registered_approval is not None:
                self._retire_registered(registered_approval, frozen_payload, conversation_id)
            raise CloudOrchestrationError('Cloud fallback could not be prepared safely.') from error

    def _retire(self, pending) -> None:
        request, _, _, payload, _ = pending
        self._retire_registered(request, payload, request.conversation_id)

    def _retire_registered(self, approval, payload, conversation_id: str) -> None:
        try:
            self._consent.consume(
                approval.approval_id, provider=approval.provider, model=approval.model,
                region=approval.region, payload=payload, session_id=conversation_id,
                user_approved=False)
        except PermissionError:
            pass

    def approve_and_execute(self, *, request: CloudRequest, conversation_id: str) -> CloudExecution:
        with self._lock:
            if request.approval_id in self._retired:
                raise CloudOrchestrationError('This request was superseded and must be prepared again.')
            pending = self._pending.get(conversation_id)
            if (pending is None or pending[0] != request or request.conversation_id != conversation_id
                    or request.approval_id in self._executing or request.approval_id in self._completed):
                raise CloudOrchestrationError('No unused matching request belongs to this conversation.',
                                              diagnostic='authorization')
            self._executing.add(request.approval_id)
        _, settings, schema, payload, lessons_snapshot = pending
        try:
            if self._provider == 'openai_cloud' and self._settings_factory is None:
                from types import SimpleNamespace
                active_settings = SimpleNamespace(model=request.model, region=request.region,
                                                  configured=True, api_key_configured=bool(self._api_key()))
            else:
                active_settings = self._settings_factory() if self._settings_factory is not None else settings
        except Exception as error:
            with self._lock:
                self._pending.pop(conversation_id, None)
                self._retired.add(request.approval_id)
                self._executing.discard(request.approval_id)
            try:
                self._retire(pending)
            except Exception:
                pass
            raise CloudOrchestrationError('Provider configuration changed; prepare a new request.',
                                          diagnostic='authorization') from error
        approved_payload = payload
        fingerprint, canonical = self._consent.fingerprint(
            request.provider, request.model, request.region, approved_payload)
        preview_fingerprint, preview_canonical = self._consent.fingerprint(
            request.provider, request.model, request.region, request.preview)
        payload_canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
        preview_payload_canonical = json.dumps(request.preview, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
        identity_matches = (active_settings.model == request.model
                            and getattr(active_settings, 'region', self._region) == request.region
                            and getattr(active_settings, 'configured', False)
                            and getattr(active_settings, 'api_key_configured', False))
        if (fingerprint != request.fingerprint or payload_canonical != preview_payload_canonical
                or fingerprint != preview_fingerprint or not identity_matches):
            try:
                with self._lock:
                    self._pending.pop(conversation_id, None)
                    self._retired.add(request.approval_id)
                self._retire(pending)
            finally:
                with self._lock:
                    self._executing.discard(request.approval_id)
            raise CloudOrchestrationError('Approved payload or identity changed; prepare a new request.',
                                          diagnostic='authorization')
        consumed = False
        try:
            # Consume authorization before provider construction/inference; no I/O can
            # occur before this boundary, and any following error remains consumed.
            if self._provider == 'openai_cloud':
                if self._settings_factory is not None:
                    from .openai_provider import InferenceRequest as _OpenAIRequest
                    openai_messages_list = []
                    if payload.get('instructions'):
                        openai_messages_list.append({'role': 'system', 'content': payload['instructions']})
                    for item in payload['input']:
                        openai_messages_list.append({
                            'role': item['role'],
                            'content': ''.join(part['text'] for part in item['content']),
                        })
                    inference = _OpenAIRequest(tuple(openai_messages_list), request.model,
                                                request.max_output_tokens, self._request_timeout_seconds, schema)
                    provider_payload = payload
                else:
                    inference = InferenceRequest(tuple(payload['messages']), request.model,
                                                 request.max_output_tokens, self._request_timeout_seconds, schema)
                    provider_payload = payload
            else:
                inference = InferenceRequest(tuple(payload['messages']), request.model,
                                             request.max_output_tokens, self._request_timeout_seconds, schema)
                provider_payload = self._provider_request_payload(payload, inference)
                approved_provider_payload = payload
            provider_fingerprint_data = self._consent.fingerprint(
                request.provider, request.model, request.region, provider_payload)
            payload_matches = (provider_payload.get('model') == request.model
                               and provider_fingerprint_data[0] == request.fingerprint
                               and json.loads(provider_fingerprint_data[1])['payload'] == request.preview
                               and json.dumps(provider_payload, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
                               == json.dumps(request.preview, ensure_ascii=False, sort_keys=True, separators=(',', ':')))
            if not payload_matches:
                with self._lock:
                    self._pending.pop(conversation_id, None)
                    self._retired.add(request.approval_id)
                self._retire(pending)
                raise CloudOrchestrationError('Provider payload differs from the approved preview.',
                                              diagnostic='authorization')
            provider_fingerprint = (self._provider_fingerprint(inference, provider_payload)
                                    if self._provider != 'openai_cloud' else None)
            # Consume immediately before provider construction and I/O. No provider
            # boundary is called before this succeeds.
            self._consent.consume(
                request.approval_id, provider=request.provider, model=request.model,
                region=request.region, payload=(provider_payload if self._provider == 'openai_cloud' else payload),
                session_id=conversation_id,
                user_approved=True, success=False, error_category='execution_started', finalize=False)
            consumed = True
            with self._lock:
                self._pending.pop(conversation_id, None)
                self._completed.add(request.approval_id)
            if self._provider == 'openai_cloud' and self._settings_factory is not None:
                try:
                    active_settings = self._settings_factory()
                except Exception as error:
                    raise CloudOrchestrationError(
                        'Provider configuration changed; authorization remains consumed.',
                        diagnostic='authorization') from error
                active_key = getattr(active_settings, 'api_key', None)
                configured_key = self._api_key()
                if (active_settings.model != request.model
                        or not getattr(active_settings, 'configured', False)
                        or not getattr(active_settings, 'api_key_configured', False)
                        or not isinstance(active_key, str) or not isinstance(configured_key, str)
                        or not hmac.compare_digest(active_key, configured_key)):
                    raise CloudOrchestrationError(
                        'Provider configuration changed; authorization remains consumed.',
                        diagnostic='authorization')
            current_api_key = (active_settings.api_key if self._provider == 'openai_cloud'
                               and self._settings_factory is not None else self._api_key())
            provider_kwargs = {
                'base_url': request.endpoint, 'model': request.model, 'region': request.region,
                'api_key': current_api_key, 'allowed_hosts': (urlsplit(request.endpoint).hostname,),
                'timeout_seconds': self._request_timeout_seconds,
                'max_output_tokens': request.max_output_tokens,
            }
            if self._provider == 'openai_cloud':
                provider_kwargs = {
                    'model': request.model, 'api_key': current_api_key,
                    'endpoint': request.endpoint,
                    'timeout_seconds': self._request_timeout_seconds,
                    'max_output_tokens': request.max_output_tokens,
                }
            try:
                provider = self._provider_factory(**provider_kwargs)
            except Exception as error:
                raise CloudOrchestrationError(
                    'Cloud provider could not be initialized; authorization remains consumed.',
                    diagnostic='request_execution', substage='provider_construction') from error
            try:
                if self._provider == 'openai_cloud':
                    if self._settings_factory is not None:
                        provider.authorize_payload_once(provider_payload)
                    else:
                        provider.authorize_once(inference, request.fingerprint)
                else:
                    provider.authorize_once(inference, provider_fingerprint)
            except Exception as error:
                raise CloudOrchestrationError(
                    'Cloud provider authorization setup failed; authorization remains consumed.',
                    diagnostic='request_execution', substage='authorization_setup') from error
            try:
                result = provider.infer(inference)
            except Exception as error:
                raise CloudOrchestrationError(
                    'Cloud adapter inference failed; authorization remains consumed.',
                    diagnostic='request_execution', substage='adapter_inference') from error
            try:
                if self._result_accountant is not None:
                    self._result_accountant(
                        request=request, result=result, conversation_id=conversation_id)
                else:
                    self._consent.record_result(
                        request.approval_id, success=result.status == 'success',
                        input_tokens=getattr(result, 'input_tokens', None),
                        output_tokens=getattr(result, 'output_tokens', None),
                        reported_cost_usd=getattr(result, 'reported_cost_usd', None),
                        error_category=getattr(result, 'error_category', None))
            except Exception as error:
                raise CloudOrchestrationError(
                    'Cloud result accounting failed; authorization remains consumed.',
                    diagnostic='request_execution', substage='result_accounting') from error
            if self._result_writer is not None and result.status == 'success':
                try:
                    self._result_writer(conversation_id, result, lessons_snapshot)
                except Exception as error:
                    raise CloudOrchestrationError(
                        'Cloud response could not be persisted; authorization remains consumed.',
                        diagnostic='response_validation') from error
            return CloudExecution(request, result)
        except Exception as error:
            with self._lock:
                self._pending.pop(conversation_id, None)
                if consumed:
                    self._completed.add(request.approval_id)
            if consumed and not isinstance(error, CloudOrchestrationError):
                try:
                    self._consent.record_result(
                        request.approval_id, success=False, error_category='execution_failed')
                except Exception:
                    pass
            if isinstance(error, CloudOrchestrationError):
                if (error.diagnostic == 'request_execution' and error.substage != 'result_accounting'
                        and error.substage != 'authorization_setup'):
                    try:
                        self._consent.record_result(
                            request.approval_id, success=False, error_category='execution_failed')
                    except Exception:
                        # Ignore duplicate finalization attempts without altering the first result.
                        pass
                raise error
            if consumed:
                raise CloudOrchestrationError(
                    'Approved request failed; authorization remains consumed and will not be retried.',
                    diagnostic='request_execution', substage='unknown') from error
            raise CloudOrchestrationError(
                'Cloud authorization failed safely; no request was retried.', diagnostic='unknown') from error
        finally:
            with self._lock:
                self._executing.discard(request.approval_id)

    def decline_fallback(self, *, request: CloudRequest, conversation_id: str) -> bool:
        with self._lock:
            pending = self._pending.get(conversation_id)
            if pending is None or pending[0] != request or request.conversation_id != conversation_id:
                return False
            self._pending.pop(conversation_id, None)
            self._retired.add(request.approval_id)
        self._retire(pending)
        return True
