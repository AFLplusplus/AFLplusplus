#!/usr/bin/env python3
#
# By Ziqiao Kong <mio@lazym.io>

import subprocess
import sys
import shutil
import os
import tempfile
import json
from pathlib import Path

MINUMUM_RUSTC_TO_BUILD = (1, 87, 0)

# https://stackoverflow.com/questions/1871549/how-to-determine-if-python-is-running-inside-a-virtualenv
def in_venv():
    return sys.prefix != sys.base_prefix

def run_cmd(cmd: str, cwd: Path = None, quiet: bool = False, envs: dict = None):
    if not envs:
        envs = {}
    passed_envs = dict(os.environ, **envs)
    if not cwd:
        cwd = Path(__file__).parent
    if quiet:
        print(f"[*] Running quietly: \"{cmd}\" under workding directory {cwd}")
    else:
        print(f"[*] Running: \"{cmd}\" under workding directory {cwd}")
    if quiet:
        try:
            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.PIPE, cwd=cwd, env=passed_envs)
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed with:\n{e.stdout}\n{e.stderr}")
            raise e
        return out
    else:
        subprocess.check_call(cmd, shell=True, cwd=cwd, env=passed_envs)
        return None


def detect_from_env_or_file(target: str):
    if target in os.environ:
        return os.environ[target]
    elif (cwd / target).exists():
        with open(cwd / target, mode="r") as f:
            return f.read().strip()
    else:
        return None

def detect_rustc_version():
    rustc_version = run_cmd("rustc --version", None, quiet=True).decode("utf-8").split(" ")[1]
    major, minor, patch = rustc_version.split(".")
    patch = patch.split("-", 1)[0] # remove "-nightly"
    current = (int(major), int(minor), int(patch))
    return current >= MINUMUM_RUSTC_TO_BUILD

cwd = Path(__file__).parent

libs_path = cwd / "lib"
include_path = cwd / "include"
unicornafl_path = cwd / "unicornafl"

if libs_path.exists():
    print("[!] Cleaning previous artifacts...")
    shutil.rmtree(libs_path)
if include_path.exists():
    print("[!] Cleaning previous headers...")
    shutil.rmtree(include_path)

if not (cwd.parent / "afl-showmap").exists():
    print("[!] Please compile AFL++ first.")
    exit(1)


if not shutil.which("cargo"):
    print("[!] No cargo, please install Rust in advance.")
    print("[!] TLDR: `curl https://sh.rustup.rs -sSf | sh -s -- -y`")
    exit(2)

if not detect_rustc_version():
    print("[!] Your rustc seems too old to build unicornafl and libafl")
    print(f"[!] The minimum rustc version to build is {MINUMUM_RUSTC_TO_BUILD[0]}.{MINUMUM_RUSTC_TO_BUILD[1]}.{MINUMUM_RUSTC_TO_BUILD[2]}")
    exit(3)
        
unicornafl_version = detect_from_env_or_file("UNICORNAFL_VERSION")
if not unicornafl_version:
    print("[!] No valid UNICORNAFL_VERSION found")
    exit(4)

try:
    run_cmd("git status", cwd)
except subprocess.CalledProcessError:
    print(f"[!] Unicornafl is not a submodule, do a separate clone...")
    run_cmd("rm -rf unicornafl && git clone https://github.com/AFLplusplus/unicornafl", cwd)

if not (unicornafl_path / ".git").exists():
    print(f"[!] Submodule not existing, will do a checkout first")
    run_cmd("git submodule update --init --recursive", cwd)

print(f"[*] We will checkout unicornafl {unicornafl_version}")
run_cmd(f"git fetch --all && git checkout {unicornafl_version}", unicornafl_path)

print(f"[*] Now building unicornafl python bindings")
venv = in_venv()
skip_venv = os.environ.get("AFL_UCAFL_NO_VENV") is not None
venv_prefix = sys.prefix
py3 = sys.executable
if not venv and not skip_venv:
    print(f"[!] A python venv is highly recommended! We will create one for you...")
    venv_prefix = cwd / ".venv"
    run_cmd(f"{py3} -m venv {venv_prefix.absolute()}")
    py3 = venv_prefix / "bin" / "python3"
elif not venv and skip_venv:
    print("[!] You opt in installing the unicornafl to your current site packages, which probably won't work.")
    print(f"[!] We will add --user for you and install with intepreter from {sys.executable}")

print(f"[*] We will install unicornafl to venv at {venv_prefix} using {py3}")

if not shutil.which("setuptools"):
    print(f"[!] No setuptools, will install setuptools first")
    if skip_venv:
        run_cmd(f"{py3} -m pip install --user setuptools")
    else:
        run_cmd(f"{py3} -m pip install setuptools")

if not shutil.which("maturin"):
    print(f"[!] No maturin, will install maturin now")
    if skip_venv:
        run_cmd(f"{py3} -m pip install --user maturin")
    else:
        run_cmd(f"{py3} -m pip install maturin")

print(f"[*] Now building unicornafl with maturin")
if skip_venv:
    run_cmd(f"maturin develop --release", unicornafl_path, True)
else:
    run_cmd(f"{Path(venv_prefix) / 'bin' / 'maturin'} develop --release", unicornafl_path, True, {"VIRTUAL_ENV": venv_prefix})
print(f"[*] Python bindings built, now testing...")

with tempfile.TemporaryDirectory() as tmpdir:
    dst_file = Path(tmpdir) / "test-instr0"
    print("[*] Testing a rather simple python harness")
    run_cmd(f"../afl-showmap -U -m none -t 2000 -o {dst_file.absolute()} -- {py3} ./samples/python_simple/simple_test_harness.py ./sample_inputs/sample1.bin", None, True)

    if dst_file.exists():
        print(f"[*] Cool, it works =).")
    else:
        print(f"[!] Unicornafl can not fuzz a simplest case, please submit an issue.")
        exit(5)

print(f"[*] Now building unicornafl C/C++ bindings")
cargo_out = run_cmd(f"cargo build --release --features bindings --message-format=json", unicornafl_path, True)

print("[*] Copying unicornafl libraries and headers")
os.makedirs(libs_path, exist_ok=True)
shutil.copyfile(unicornafl_path / "target" / "release" / "libunicornafl.a", libs_path / "libunicornafl.a")
if sys.platform == "darwin":
    dylib = "libunicornafl.dylib"
    ucdylib = "libunicorn.so"
else:
    dylib = "libunicornafl.so"
    ucdylib = "libunicorn.so"
shutil.copyfile(unicornafl_path / "target" / "release" / dylib, libs_path / dylib)
shutil.copytree(unicornafl_path / "include", include_path)
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
                    try:
                        shutil.copytree(out_dir / "lib", libs_path, dirs_exist_ok=True)
                    except FileNotFoundError:
                        shutil.copytree(out_dir / "lib64", libs_path, dirs_exist_ok=True)
                    shutil.copytree(out_dir / "include", include_path, dirs_exist_ok=True)
                    print(f"[*] Copied from {out_dir.absolute()}")


if skip_venv:
    venv_prefix = "."
else:
    venv_prompt = f" and venv {venv_prefix}. Please do `source {Path(venv_prefix)/'bin'/'activate'}` first."




print(f"""[*] All done! You have compiled unicornafl without any issue.
    You can now start using python bindings by `import unicornafl`. Please note the python bindings have been
    installed to with intepreter {py3}{venv_prompt}
    For C/C++ users, please see {libs_path.absolute()} for libraries and {include_path.absolute()} for headers.
    For Rust users, either add:
        unicornafl = {{ git = "https://github.com/AFLplusplus/unicornafl", rev="{unicornafl_version}" }}
    or
        unicornafl = {{ path = "{(cwd/'unicornafl').absolute()}" }}
    to your Cargo.toml.
    
    Please also have a look at { (cwd / 'unicornafl' / 'docs').absolute() } which contains various hints and usages.

    If you find an issue in unicornafl, please post to https://github.com/AFLplusplus/unicornafl
""")
