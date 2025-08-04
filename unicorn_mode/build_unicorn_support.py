#!/usr/bin/env python
#
# By Ziqiao Kong <mio@lazym.io>

import subprocess
import sys
import shutil
import os
import tempfile
import json
from pathlib import Path

# https://stackoverflow.com/questions/1871549/how-to-determine-if-python-is-running-inside-a-virtualenv
def in_venv():
    return sys.prefix != sys.base_prefix

def run_cmd(cmd: str, cwd: Path = None, quiet: bool = False):
    if not cwd:
        cwd = Path(__file__).parent
    if quiet:
        print(f"[*] Runing queitly: \"{cmd}\" under workding directory {cwd}")
    else:
        print(f"[*] Runing: \"{cmd}\" under workding directory {cwd}")
    if quiet:
        try:
            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.PIPE, cwd=cwd)
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed with:\n{e.stdout}\n{e.stderr}")
            raise e
        return out
    else:
        subprocess.check_call(cmd, shell=True, cwd=cwd)
        return None


def detect_from_env_or_file(target: str):
    if target in os.environ:
        return os.environ[target]
    elif (cwd / target).exists():
        with open(cwd / target, mode="r") as f:
            return f.read().strip()
    else:
        return None
    
if sys.platform == 'win32':
    print("[!] Unicornafl does not support Windows so far (no fsrv support).")
    exit(1)
    
cwd = Path(__file__).parent

libs_path = cwd / "lib"
include_path = cwd / "include"
if libs_path.exists():
    print("[!] Cleaning previous artifacts...")
    shutil.rmtree(libs_path)
if include_path.exists():
    print("[!] Cleaning previous headers...")
    shutil.rmtree(include_path)

if not (cwd.parent / "afl-showmap").exists():
    print("[!] Please compile AFL++ firstly.")
    exit(1)

if not shutil.which("cargo"):
    print("[*] No cargo, installing Rust and this might take a while...")
    run_cmd("curl https://sh.rustup.rs -sSf | sh -s -- -y", cwd)

unicornafl_version = detect_from_env_or_file("UNICORNAFL_VERSION")
if not unicornafl_version:
    print("[!] No valid UNICORNAFL_VERSION found")
    exit(1)

if not (cwd / "unicornafl" / ".git").exists():
    print(f"[!] Submodule not existing, will do a checkout firstly")
    run_cmd("git submodule update --init --recursive", cwd)

print(f"[*] We will checkout unicornafl {unicornafl_version}")
run_cmd(f"git fetch --all && git checkout {unicornafl_version}", cwd / "unicornafl")

print(f"[*] Now building unicornafl python bindings")
venv = in_venv()
if not venv:
    print(f"[!] A python venv is highly recommended!")

if not shutil.which("maturin"):
    print(f"[!] No maturin, will install maturin firstly")
    run_cmd("pip install --user maturin")

print(f"[*] Now building unicornafl with maturin")
run_cmd("maturin develop --release", cwd / "unicornafl", True)
print(f"[*] Python bindings built, now testing...")

with tempfile.TemporaryDirectory() as tmpdir:
    dst_file = Path(tmpdir) / "test-instr0"
    print("[*] Testing a rather simple python harness")
    run_cmd(f"../afl-showmap -U -m none -t 2000 -o {dst_file.absolute()} -- python3 ./samples/python_simple/simple_test_harness.py ./sample_inputs/sample1.bin", None, True)

    if dst_file.exists():
        print(f"[*] Cool, it works =).")

print(f"[*] Now building unicornafl C/C++ bindings")
cargo_out = run_cmd(f"cargo build --release --features bindings --message-format=json", cwd / "unicornafl", True)

print("[*] Copying unicornafl libraries and headers")
os.makedirs(libs_path, exist_ok=True)
shutil.copyfile(cwd / "unicornafl" / "target" / "release" / "libunicornafl.a", libs_path / "libunicornafl.a")
if sys.platform == "darwin":
    dylib = "libunicornafl.dylib"
    ucdylib = "libunicorn.so"
else:
    dylib = "libunicornafl.so"
    ucdylib = "libunicorn.so"
shutil.copyfile(cwd / "unicornafl" / "target" / "release" / dylib, libs_path / dylib)
shutil.copytree(cwd / "unicornafl" / "include", include_path)
print(f"[*] Now we have to look for unicorn dynamic libraries")
unicorn_dylib = None
lns = cargo_out.decode('utf-8').split('\n')
for ln in lns:
    if len(ln.strip()) > 0:
        ln_json = json.loads(ln)
        if "reason" in ln_json and ln_json['reason'] == "build-script-executed":
            if "linked_libs" in ln_json and any(["unicorn" in x for x in ln_json['linked_libs']]):
                if "out_dir" in ln_json:
                    out_dir = Path(ln_json['out_dir'])
                    shutil.copytree(out_dir / "lib", libs_path, dirs_exist_ok=True)
                    shutil.copytree(out_dir / "include", include_path, dirs_exist_ok=True)
                    print(f"[*] Copied from {out_dir.absolute()}")


print(f"""[*] All done! You have compiled unicornafl without any issue.
    You could start using python bindings by `import unicornafl`.
    For C/C++ users, please see {libs_path.absolute()} for libraries and {include_path.absolute()} for headers.
    For Rust users, either add:
        unicornafl = {{ git = "https://github.com/AFLplusplus/unicornafl", rev="{unicornafl_version}" }}
    or
        unicornafl = {{ path = "{(cwd/'unicornafl').absolute()}" }}
    to your Cargo.toml.
    
    Please also have a look at { (cwd / 'unicornafl' / 'docs').absolute() } which contains vary hints and usages.
    
    If you have any issue about unicornafl, please let us know.
""")