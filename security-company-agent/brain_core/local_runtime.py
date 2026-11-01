"""Launch only the standalone local model service, never operational agents."""
import json
import os
from pathlib import Path
import subprocess
import urllib.request
from .model_policy import policy_for, selected_local_model

ROOT = Path(__file__).resolve().parents[1]
OLLAMA = ROOT / 'ollama-runtime' / 'ollama.exe'

def runtime_environment():
    env = os.environ.copy()
    policy = policy_for(selected_local_model())
    # Isolate this new runtime's application identity from the user's existing profile.
    # Windows Go UserHomeDir uses USERPROFILE; this affects only our child process.
    profile = ROOT / 'local_runtime_profile'
    profile.mkdir(exist_ok=True)
    env.update({'USERPROFILE': str(profile), 'OLLAMA_HOST': '127.0.0.1:11434',
                'OLLAMA_MODELS': str(ROOT / 'local_models'), 'OLLAMA_NO_CLOUD': '1',
                'OLLAMA_CONTEXT_LENGTH': str(policy.context_tokens),
                'OLLAMA_NUM_PARALLEL': str(policy.parallel_requests),
                'OLLAMA_MAX_LOADED_MODELS': '1', 'OLLAMA_KEEP_ALIVE': str(policy.keep_alive_seconds),
                'OLLAMA_DEBUG': 'ERROR', 'OLLAMA_DEBUG_LOG_REQUESTS': 'false'})
    return env

def version():
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open('http://127.0.0.1:11434/api/version', timeout=2) as response:
            return json.load(response).get('version')
    except (OSError, ValueError):
        return None

def ensure_server():
    if version():
        return None
    if not OLLAMA.is_file():
        return None
    logs = ROOT / 'local_logs'
    logs.mkdir(exist_ok=True)
    # The vendor may print its generated public application identity at startup.
    # Keep startup output local; never surface key material in chat or UI.
    with (logs / 'ollama-runtime.log').open('ab') as output:
        process = subprocess.Popen([str(OLLAMA), 'serve'], cwd=ROOT,
                                   env=runtime_environment(), stdout=output, stderr=output,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
    (logs / 'ollama.pid').write_text(str(process.pid), encoding='ascii')
    return process.pid
