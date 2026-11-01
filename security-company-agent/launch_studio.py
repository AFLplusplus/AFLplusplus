"""Double-click entry point; loopback services only, with no model auto-download."""
from pathlib import Path
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
import webbrowser
from brain_core.local_runtime import ensure_server

ROOT = Path(__file__).resolve().parent

def health(url):
    try:
        with urllib.request.urlopen(url + '/_stcore/health', timeout=2) as response:
            return response.status == 200 and response.read().strip() == b'ok'
    except OSError:
        return False

def main():
    logs = ROOT / 'local_logs'
    logs.mkdir(exist_ok=True)
    ensure_server()
    metadata = logs / 'studio-url.json'
    if metadata.exists():
        url = json.loads(metadata.read_text(encoding='utf-8'))['url']
        if health(url):
            webbrowser.open(url)
            return
    # Use a free loopback port; persist the actual port for future browser launches.
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    url = f'http://127.0.0.1:{port}'
    with (logs / 'studio.out.log').open('ab') as output:
        process = subprocess.Popen([sys.executable, '-m', 'streamlit', 'run', str(ROOT / 'brain_studio.py'),
                                    '--server.address', '127.0.0.1', '--server.port', str(port),
                                    '--server.headless', 'true', '--browser.gatherUsageStats', 'false'],
                                   cwd=ROOT, stdout=output, stderr=output,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
    metadata.write_text(json.dumps({'url': url, 'pid': process.pid}), encoding='utf-8')
    for _ in range(60):
        if process.poll() is not None:
            raise RuntimeError('Studio failed to start. See local_logs/studio.out.log.')
        if health(url):
            webbrowser.open(url)
            return
        time.sleep(0.5)
    raise RuntimeError('Studio startup timed out. Check local logs.')

if __name__ == '__main__':
    main()
