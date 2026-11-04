"""Immutable one-time approval and local-only accounting for cloud inference."""
from __future__ import annotations
from dataclasses import dataclass
import hashlib, hmac, json, threading, time, uuid

@dataclass(frozen=True)
class CloudBudget:
    max_prompt_tokens: int = 12000
    max_output_tokens: int = 768
    max_estimated_cost_usd: float = 0.25
    session_limit_usd: float = 2.0
    daily_limit_usd: float = 5.0

@dataclass(frozen=True)
class CloudApproval:
    approval_id: str
    payload_fingerprint: str
    provider: str
    model: str
    region: str
    token_estimate: int
    max_output_tokens: int
    estimated_cost_usd: float | None
    payload_json: str
    session_id: str
    created_at: float

class CloudApprovalRequired(PermissionError):
    pass


class CloudApprovalManager:
    """Single-use payload-bound confirmations; records no prompts or secrets."""
    def __init__(self):
        self._lock = threading.RLock()
        self._approvals = {}
        self._used = set()
        self._session_spend = {}
        self._daily_spend = {}
        self._events = []

    @staticmethod
    def fingerprint(provider, model, region, payload):
        canonical = json.dumps({'provider':provider,'model':model,'region':region,'payload':payload},
                               sort_keys=True, ensure_ascii=False, separators=(',',':'))
        return hashlib.sha256(canonical.encode('utf-8')).hexdigest(), canonical

    def prepare(self, *, provider, model, region, payload, session_id, token_estimate,
                estimated_cost_usd=None, budget=CloudBudget(), prompt_tokens=None):
        prompt_tokens = token_estimate if prompt_tokens is None else prompt_tokens
        if prompt_tokens > budget.max_prompt_tokens:
            raise ValueError('Prompt token budget exceeded.')
        if type(budget.max_output_tokens) is not int or not 1 <= budget.max_output_tokens <= 768:
            raise ValueError('Configured output cap is invalid or exceeds application maximum.')
        if estimated_cost_usd is not None and estimated_cost_usd > budget.max_estimated_cost_usd:
            raise ValueError('Per-request estimated cost limit exceeded.')
        day = time.strftime('%Y-%m-%d', time.gmtime())
        with self._lock:
            amount = estimated_cost_usd or 0.0
            if self._session_spend.get(session_id, 0.0) + amount > budget.session_limit_usd:
                raise ValueError('Session spending limit exceeded.')
            if self._daily_spend.get(day, 0.0) + amount > budget.daily_limit_usd:
                raise ValueError('Daily spending limit exceeded.')
        fingerprint, canonical = self.fingerprint(provider, model, region, payload)
        return CloudApproval(uuid.uuid4().hex, fingerprint, provider, model, region,
            token_estimate, budget.max_output_tokens, estimated_cost_usd, canonical, session_id, time.time())

    def register(self, approval):
        with self._lock:
            self._approvals[approval.approval_id] = approval

    def consume(self, approval_id, *, provider, model, region, payload, session_id,
                user_approved, success=None, input_tokens=None, output_tokens=None,
                reported_cost_usd=None, error_category=None, max_age_seconds=600,
                finalize=True):
        with self._lock:
            approval = self._approvals.get(approval_id)
            if not user_approved:
                if approval is not None:
                    del self._approvals[approval_id]
                    self._used.add(approval_id)
                raise CloudApprovalRequired('Fresh explicit approval required; request not sent.')
            if approval is None or approval_id in self._used:
                raise CloudApprovalRequired('Fresh explicit approval required; request not sent.')
            if time.time() - approval.created_at > max_age_seconds:
                del self._approvals[approval_id]
                self._used.add(approval_id)
                raise CloudApprovalRequired('Approval expired; request not sent.')
            fingerprint, canonical = self.fingerprint(provider, model, region, payload)
            if (session_id != approval.session_id or
                    provider != approval.provider or model != approval.model or region != approval.region or
                    not hmac.compare_digest(fingerprint, approval.payload_fingerprint) or
                    canonical != approval.payload_json):
                raise CloudApprovalRequired('Approved payload changed; request not sent.')
            cost = reported_cost_usd if reported_cost_usd is not None else approval.estimated_cost_usd
            if finalize:
                self._used.add(approval_id)
                del self._approvals[approval_id]
            day = time.strftime('%Y-%m-%d', time.gmtime())
            if cost is not None and success:
                self._session_spend[session_id] = self._session_spend.get(session_id, 0.0) + cost
                self._daily_spend[day] = self._daily_spend.get(day, 0.0) + cost
            event = {'timestamp':time.time(),'provider':provider,'model':model,
                     'region':region,'input_tokens':input_tokens,'output_tokens':output_tokens,
                     'cost':cost,'cost_is_estimate':reported_cost_usd is None,'success':success,
                     'error_category':error_category,'authorization_reference':approval_id,
                     '_session_id':approval.session_id, '_finalized':finalize}
            self._events.append(event)
            return approval

    def record_result(self, approval_id, *, success, input_tokens=None, output_tokens=None,
                      reported_cost_usd=None, error_category=None):
        """Finalize execution accounting after a consumed authorization; never reauthorize it."""
        with self._lock:
            event = next((item for item in reversed(self._events)
                          if item.get('authorization_reference') == approval_id
                          and not item.get('_finalized')), None)
            approval = self._approvals.pop(approval_id, None)
            if event is None or approval is None:
                raise CloudApprovalRequired('Consumed authorization has no pending accounting record.')
            self._used.add(approval_id)
            event.update(success=bool(success), input_tokens=input_tokens,
                         output_tokens=output_tokens, error_category=error_category,
                         _finalized=True)
            if reported_cost_usd is not None:
                event['cost'] = reported_cost_usd
                event['cost_is_estimate'] = False
            if success:
                cost = reported_cost_usd if reported_cost_usd is not None else event.get('cost')
                if cost is not None:
                    session_id = event['_session_id']
                    self._session_spend[session_id] = self._session_spend.get(session_id, 0.0) + cost
                    day = time.strftime('%Y-%m-%d', time.gmtime())
                    self._daily_spend[day] = self._daily_spend.get(day, 0.0) + cost

    @property
    def events(self):
        with self._lock:
            return tuple({key: value for key, value in item.items() if not key.startswith('_')}
                         for item in self._events)

def approximate_token_count(text):
    return max(1, (len(text) + 2) // 3)
