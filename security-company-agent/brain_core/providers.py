"""Provider-neutral inference contracts; adapters do not own memory or identity."""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol
import hashlib, hmac, json, socket, ssl, time, urllib.error, urllib.request, urllib.parse

class ProviderID(str, Enum):
    LOCAL_OLLAMA = 'local_ollama'
    ALIBABA_QWEN_CLOUD = 'alibaba_qwen_cloud'

@dataclass(frozen=True)
class InferenceRequest:
    messages: tuple[dict[str, str], ...]
    model: str
    max_output_tokens: int = 768
    timeout_seconds: float = 120
    json_schema: dict[str, Any] | None = None

@dataclass(frozen=True)
class InferenceResult:
    provider: ProviderID
    model: str
    text: str
    structured: dict[str, Any] | None
    status: str
    error_category: str | None
    latency_seconds: float | None
    input_tokens: int | None
    output_tokens: int | None
    request_id: str | None
    estimated_cost: float | None
    cost_is_estimate: bool
    external_transmission: bool

class InferenceProvider(Protocol):
    provider_id: ProviderID
    def infer(self, request: InferenceRequest) -> InferenceResult: ...

def category_for_error(error):
    from .model_api import MemoryGuardError, ModelError, ModelOutputError
    if isinstance(error, MemoryGuardError): return 'resource_limit'
    if isinstance(error, ModelOutputError): return 'invalid_or_unvalidated_output'
    if isinstance(error, (TimeoutError, socket.timeout)): return 'timeout'
    if isinstance(error, ModelError):
        text = str(error).casefold()
        if 'timed out' in text or 'timeout' in text: return 'timeout'
        if 'connect' in text or 'unavailable' in text: return 'connection'
        if 'authentication' in text or 'authorization' in text: return 'authentication'
        return 'provider_error'
    return 'internal_error'

class LocalOllamaProvider:
    provider_id = ProviderID.LOCAL_OLLAMA
    def __init__(self, config): self.config = config
    def infer(self, request):
        from .model_api import complete
        started = time.perf_counter()
        try:
            value, meta = complete(list(request.messages), self.config, request.json_schema)
            return InferenceResult(self.provider_id, request.model, json.dumps(value, ensure_ascii=False), value,
                'success', None, time.perf_counter()-started, meta.get('input_tokens'),
                meta.get('output_tokens'), meta.get('request_id'), None, True, False)
        except Exception as error:
            return InferenceResult(self.provider_id, request.model, '', None, 'failed',
                category_for_error(error), time.perf_counter()-started, None, None, None, None, True, False)

class AlibabaQwenProvider:
    """OpenAI-compatible adapter requiring exact-payload one-time authorization."""
    provider_id = ProviderID.ALIBABA_QWEN_CLOUD
    def __init__(self, *, base_url, model, region, api_key, allowed_hosts,
                 timeout_seconds=60, max_output_tokens=768):
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme != 'https' or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('Alibaba endpoint must be HTTPS without credentials, query, or fragment.')
        if not parsed.hostname or parsed.hostname not in allowed_hosts:
            raise ValueError('Alibaba endpoint host does not match configured region/workspace.')
        if not model or not region or not api_key or not 1 <= timeout_seconds <= 180:
            raise ValueError('Alibaba configuration is incomplete or invalid.')
        self.base_url, self.model, self.region, self._api_key = base_url.rstrip('/'), model, region, api_key
        self.timeout_seconds, self.max_output_tokens = timeout_seconds, max_output_tokens
        self._approved = None
        self._used = set()

    @staticmethod
    def payload(request):
        body = {'model':request.model,'messages':list(request.messages),'stream':False,
                'max_tokens':request.max_output_tokens,'temperature':0.2}
        if request.json_schema:
            body['response_format']={'type':'json_schema','json_schema':{
                'name':'sovereign_reasoning_v1','strict':True,'schema':request.json_schema}}
        return body

    @classmethod
    def fingerprint(cls, request):
        canonical=json.dumps(cls.payload(request),sort_keys=True,ensure_ascii=False,separators=(',',':'))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def authorize_once(self, request, approved_fingerprint):
        fingerprint=self.fingerprint(request)
        if not hmac.compare_digest(fingerprint,approved_fingerprint):
            raise PermissionError('Approval does not match immutable payload.')
        if fingerprint in self._used: raise PermissionError('Approved request already executed.')
        self._approved=fingerprint

    def infer(self, request):
        fingerprint=self.fingerprint(request)
        if fingerprint != self._approved or fingerprint in self._used:
            raise PermissionError('Explicit approval is required for this exact cloud request.')
        self._approved=None
        self._used.add(fingerprint)
        req=urllib.request.Request(self.base_url+'/chat/completions',
            data=json.dumps(self.payload(request),ensure_ascii=False).encode(),
            headers={'Content-Type':'application/json','Authorization':'Bearer '+self._api_key},method='POST')
        started=time.perf_counter()
        try:
            with urllib.request.urlopen(req,timeout=min(self.timeout_seconds,request.timeout_seconds)) as response:
                payload=json.loads(response.read(1_048_577))
            choice=payload['choices'][0]
            if choice.get('finish_reason') == 'length':
                raise ValueError('provider response was truncated')
            text=choice['message']['content']
            structured=json.loads(text) if request.json_schema else None
            usage=payload.get('usage') or {}
            return InferenceResult(self.provider_id,self.model,text,structured,'success',None,
                time.perf_counter()-started,usage.get('prompt_tokens'),usage.get('completion_tokens'),
                payload.get('id'),None,True,True)
        except urllib.error.HTTPError as error:
            status=error.code; error.close(); category='authentication' if status in (401,403) else 'provider_http_error'
        except (TimeoutError,socket.timeout): category='timeout'
        except (urllib.error.URLError,ssl.SSLError): category='connection'
        except (ValueError,KeyError,IndexError,TypeError,UnicodeError): category='invalid_or_truncated_output'
        except Exception: category='unexpected_provider_response'
        return InferenceResult(self.provider_id,self.model,'',None,'failed',category,
            time.perf_counter()-started,None,None,None,None,True,True)

def sanitized_cloud_context(*, scenario, identity_name, identity_mission, approved_lessons=(), recent_turns=()):
    lessons=[]
    for item in approved_lessons[:3]:
        if isinstance(item,dict) and item.get('approval_status','approved')=='approved':
            lessons.append({k:item.get(k) for k in ('lesson_id','source_type','corrective_principle','scenario_summary') if item.get(k) is not None})
    recent=[]
    # Caller must explicitly select relevant recent context; never pass archive by default.
    for item in recent_turns[-3:]:
        if isinstance(item,dict) and item.get('relevant') is True and item.get('role') in ('user','assistant') and isinstance(item.get('content'),str):
            recent.append({'role':item['role'],'content':item['content'][:500]})
    return {'schema_version':'sovereign-context.v1',
        'personality':{'identity_name':str(identity_name)[:100],'mission':str(identity_mission)[:500]},
        'instructions':['Use reported facts only; separate assumptions and interpretations.',
            'Do not invent evidence or infer hidden motives or feelings.',
            'Approved lessons are prior human-supervised principles, not evidence about this event.',
            'Do not change lesson or persistent emotional state.'],
        'approved_lessons':lessons,'recent_context':recent,'scenario':str(scenario)[:8000]}
