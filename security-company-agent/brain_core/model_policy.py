"""Explicit deployment policies; model downloads never imply inference readiness."""
from dataclasses import dataclass
import os

DEFAULT_LOCAL_MODEL = 'qwen3:0.6b'

@dataclass(frozen=True)
class ModelPolicy:
    minimum_available_gib: float
    context_tokens: int
    output_tokens: int
    parallel_requests: int = 1
    keep_alive_seconds: int = 0

def selected_local_model():
    return os.getenv('BRAIN_LOCAL_MODEL', DEFAULT_LOCAL_MODEL).strip()

def policy_for(model):
    if model == 'qwen3:0.6b':
        return ModelPolicy(1.5, 2048, 768)
    # Preserve the more conservative policy for 1.7B and unrecognized models.
    return ModelPolicy(2.5, 4096, 1000)
