"""Testable application service for exact-payload cloud fallback approval."""
from __future__ import annotations

from dataclasses import dataclass
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
                 budget: CloudBudget = CloudBudget(), result_accountant=None):
        self._consent = consent
        self._payload_factory = payload_factory
        self._provider_factory = provider_factory
        self._api_key = api_key
        self._provider_request_payload = provider_payload or (lambda payload, request: payload)
        self._provider_fingerprint = provider_fingerprint or (lambda request, payload: provider_factory.fingerprint(request))
        self._result_writer = result_writer
        self._result_accountant = result_accountant
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
            settings, endpoint, payload, schema = self._payload_factory(
                user_text, profile, approved_lessons, session_id=conversation_id)
            if not getattr(settings, 'configured', False) or not getattr(settings, 'api_key_configured', False):
                raise CloudOrchestrationError('Cloud configuration is incomplete.')
            parsed = urlsplit(endpoint)
            if (parsed.scheme != 'https' or parsed.username or parsed.password
                    or parsed.netloc.endswith(':443') or parsed.netloc.endswith(':80')
                    or ':' in parsed.netloc or parsed.query or parsed.fragment or not parsed.hostname):
                raise CloudOrchestrationError('Cloud endpoint is not a valid approved HTTPS endpoint.')
            frozen_payload = json.loads(json.dumps(payload, ensure_ascii=False))
            serialized = json.dumps(frozen_payload, ensure_ascii=False, indent=2)
            tokens = self._token_counter(serialized)
            approved_output_cap = int(frozen_payload.get('max_tokens', self._budget.max_output_tokens))
            schema_format = frozen_payload.get('response_format', {})
            schema_spec = schema_format.get('json_schema', {}) if isinstance(schema_format, dict) else {}
            reasoning_schema = frozen_payload.get('reasoning_schema', schema)
            if (frozen_payload.get('model') != settings.model
                    or not isinstance(frozen_payload.get('messages'), list)
                    or frozen_payload.get('stream') is not False
                    or frozen_payload.get('temperature') != 0.2
                    or not isinstance(schema, dict)
                    or schema_format.get('type') != 'json_schema'
                    or schema_spec.get('strict') is not True
                    or schema_spec.get('schema') != reasoning_schema):
                raise CloudOrchestrationError('Cloud payload does not match the approved reasoning request contract.')
            if approved_output_cap > self._budget.max_output_tokens:
                raise CloudOrchestrationError('Payload output cap exceeds the application safety limit.')
            approval = self._consent.prepare(
                provider=self.PROVIDER, model=settings.model, region=settings.region,
                payload=frozen_payload, session_id=conversation_id,
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
                self.PROVIDER, settings.model, settings.region, endpoint,
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
                raise CloudOrchestrationError('No unused matching request belongs to this conversation.')
            self._executing.add(request.approval_id)
        _, settings, schema, payload, lessons_snapshot = pending
        fingerprint, canonical = self._consent.fingerprint(
            request.provider, request.model, request.region, payload)
        preview_fingerprint, preview_canonical = self._consent.fingerprint(
            request.provider, request.model, request.region, request.preview)
        if (fingerprint != request.fingerprint or canonical != preview_canonical
                or fingerprint != preview_fingerprint or settings.model != request.model
                or settings.region != request.region):
            try:
                with self._lock:
                    self._pending.pop(conversation_id, None)
                    self._retired.add(request.approval_id)
                self._retire(pending)
            finally:
                with self._lock:
                    self._executing.discard(request.approval_id)
            raise CloudOrchestrationError('Approved payload or identity changed; prepare a new request.')
        consumed = False
        try:
            # Consume authorization before provider construction/inference; no I/O can
            # occur before this boundary, and any following error remains consumed.
            inference = InferenceRequest(tuple(payload['messages']), request.model,
                                         request.max_output_tokens, 60, schema)
            provider_payload = self._provider_request_payload(payload, inference)
            if (provider_payload != payload or provider_payload.get('model') != request.model
                    or provider_payload.get('messages') != payload.get('messages')
                    or provider_payload.get('max_tokens') != request.max_output_tokens
                    or self._consent.fingerprint(
                        request.provider, request.model, request.region, provider_payload)[0] != request.fingerprint):
                with self._lock:
                    self._pending.pop(conversation_id, None)
                    self._retired.add(request.approval_id)
                self._retire(pending)
                raise CloudOrchestrationError('Provider payload differs from the approved preview.')
            provider_fingerprint = self._provider_fingerprint(inference, provider_payload)
            # Consume immediately before provider construction and I/O. No provider
            # boundary is called before this succeeds.
            self._consent.consume(
                request.approval_id, provider=request.provider, model=request.model,
                region=request.region, payload=payload, session_id=conversation_id,
                user_approved=True, success=False, error_category='execution_started', finalize=False)
            consumed = True
            with self._lock:
                self._pending.pop(conversation_id, None)
                self._completed.add(request.approval_id)
            provider = self._provider_factory(
                base_url=request.endpoint, model=request.model, region=request.region,
                api_key=self._api_key(), allowed_hosts=(urlsplit(request.endpoint).hostname,),
                timeout_seconds=60, max_output_tokens=request.max_output_tokens)
            provider.authorize_once(inference, provider_fingerprint)
            result = provider.infer(inference)
            self._consent.record_result(
                request.approval_id, success=result.status == 'success',
                input_tokens=getattr(result, 'input_tokens', None),
                output_tokens=getattr(result, 'output_tokens', None),
                reported_cost_usd=getattr(result, 'reported_cost_usd', None),
                error_category=getattr(result, 'error_category', None))
            if self._result_accountant is not None:
                self._result_accountant(
                    request=request, result=result, conversation_id=conversation_id)
            if self._result_writer is not None and result.status == 'success':
                try:
                    self._result_writer(conversation_id, result, lessons_snapshot)
                except Exception as error:
                    raise CloudOrchestrationError('Cloud response could not be persisted; authorization remains consumed.') from error
            return CloudExecution(request, result)
        except Exception as error:
            with self._lock:
                self._pending.pop(conversation_id, None)
                if consumed:
                    self._completed.add(request.approval_id)
            if isinstance(error, CloudOrchestrationError):
                raise error
            if consumed:
                try:
                    self._consent.record_result(
                        request.approval_id, success=False, error_category='execution_failed')
                except Exception:
                    pass
                raise CloudOrchestrationError('Approved request failed; authorization remains consumed and will not be retried.') from error
            raise CloudOrchestrationError('Cloud authorization failed safely; no request was retried.') from error
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
