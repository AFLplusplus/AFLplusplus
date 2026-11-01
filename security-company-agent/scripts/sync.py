#!/usr/bin/env python3
"""Non-destructive Git synchronization for the SecurityCompanyAgent subproject."""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

APP = "security-company-agent/"
EXPECTED_REMOTE = "budhadityarishidasgupta-lang/AFLplusplus"
ROOT = Path(__file__).resolve().parents[2]
BLOCKED_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)
PRIVATE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".pst", ".ost", ".gguf", ".safetensors")
PRIVATE_NAMES = ("eq_matrix.json", "neuroplasticity_log.json", "campaign_scope.json", ".env")


def git(*args: str, capture: bool = True, check: bool = True) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=ROOT, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        check=False,
    )
    if check and proc.returncode:
        raise RuntimeError(
            f"git {' '.join(args)} failed ({proc.returncode}): "
            f"{(proc.stderr or '').strip()}"
        )
    return (proc.stdout or "").strip()


def check_repo() -> None:
    actual = Path(git("rev-parse", "--show-toplevel")).resolve()
    if actual != ROOT:
        raise RuntimeError(f"Unexpected repository root: {actual}")
    remotes = git("remote", "-v")
    if EXPECTED_REMOTE not in remotes:
        raise RuntimeError("Expected AFLplusplus remote not configured; refusing sync.")


def current_branch() -> str:
    name = git("branch", "--show-current")
    if not name:
        raise RuntimeError("Detached HEAD: switch to a feature branch first.")
    return name


def dirty_paths() -> list[str]:
    data = git("status", "--porcelain", "--untracked-files=all")
    return [line[3:] for line in data.splitlines() if len(line) >= 4]


def assert_no_outside_changes() -> None:
    bad = [p for p in dirty_paths() if not p.startswith(APP)]
    if bad:
        raise RuntimeError("Changes outside SecurityCompanyAgent detected: " + ", ".join(bad[:20]))


def feature_branch() -> str:
    branch = current_branch()
    if not branch.startswith("feature/"):
        raise RuntimeError(f"Write operations are only allowed on feature/* branches; current: {branch}")
    return branch


def status() -> None:
    check_repo()
    print("Repository:", ROOT)
    print("Branch:", current_branch())
    print("HEAD:", git("rev-parse", "--short", "HEAD"))
    print("Changes:\n" + (git("status", "--short") or "(clean)"))
    upstream = git("rev-parse", "--abbrev-ref", "@{upstream}", check=False)
    print("Upstream:", upstream or "(not configured)")
    if upstream:
        print("Ahead/behind:", git("rev-list", "--left-right", "--count", f"HEAD...{upstream}"))


def start() -> None:
    check_repo()
    branch = feature_branch()
    if dirty_paths():
        raise RuntimeError("Worktree not clean; commit or safely preserve local changes before updating.")
    git("fetch", "origin", capture=False)
    remote_ref = f"refs/remotes/origin/{branch}"
    if git("show-ref", "--verify", remote_ref, check=False) == "":
        # git show-ref success is validated by rev-parse instead below.
        pass
    remote_sha = git("rev-parse", "--verify", remote_ref, check=False)
    if not remote_sha:
        raise RuntimeError(f"Remote branch origin/{branch} missing.")
    git("merge", "--ff-only", f"origin/{branch}", capture=False)
    print("Feature branch fast-forwarded or already current.")


def scan_staged() -> None:
    files = git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    # NUL-delimited output is preserved by subprocess as text.
    paths = [x for x in files.split("\x00") if x]
    if not paths:
        raise RuntimeError("Nothing staged for checkpoint.")
    for name in paths:
        if not name.startswith(APP):
            raise RuntimeError(f"Staged file outside app: {name}")
        relative = name[len(APP):]
        leaf = Path(relative).name.lower()
        if leaf in PRIVATE_NAMES or leaf.startswith(".env.") or relative.lower().endswith(PRIVATE_SUFFIXES):
            raise RuntimeError(f"Private runtime/secret file staged: {name}")
        p = ROOT / name
        if p.exists() and p.is_file():
            try:
                txt = p.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            if any(pattern.search(txt) for pattern in BLOCKED_PATTERNS):
                raise RuntimeError(f"Potential hardcoded secret in {name}")
    print(f"Validated {len(paths)} staged application files.")


def checkpoint(message: str) -> None:
    check_repo()
    branch = feature_branch()
    assert_no_outside_changes()
    existing = git("diff", "--cached", "--name-only")
    if existing:
        raise RuntimeError("Pre-staged changes found; unstage/review them before checkpoint.")
    # Compile tracked and new Python files without executing application logic.
    pyfiles = [p for p in (ROOT / APP).rglob("*.py") if ".venv" not in p.parts]
    for f in pyfiles:
        source = f.read_bytes()
        compile(source, str(f), "exec")
    print(f"Syntax-checked {len(pyfiles)} Python files.")
    # Prevent local checkpoint from writing remote without a fetch comparison.
    git("fetch", "origin", capture=False)
    remote = git("rev-parse", "--verify", f"refs/remotes/origin/{branch}", check=False)
    if remote and git("merge-base", "--is-ancestor", remote, "HEAD", check=False) is None:
        pass
    if remote:
        ancestor = subprocess.run(
            ["git", "merge-base", "--is-ancestor", remote, "HEAD"], cwd=ROOT,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if ancestor.returncode:
            raise RuntimeError("Remote feature branch is not an ancestor; run start/reconcile first.")
    git("add", "--", APP, capture=False)
    staged = git("diff", "--cached", "--name-only")
    if not staged:
        print("No application changes to commit.")
        return
    scan_staged()
    print("Staged diff summary:\n" + git("diff", "--cached", "--stat"))
    git("commit", "-m", message, "--", APP, capture=False)
    git("push", "-u", "origin", branch, capture=False)
    print("Pushed checkpoint:", git("rev-parse", "--short", "HEAD"))


def finish() -> None:
    check_repo()
    branch = feature_branch()
    if dirty_paths():
        raise RuntimeError("Uncommitted changes remain; checkpoint first.")
    git("fetch", "origin", capture=False)
    local = git("rev-parse", "HEAD")
    remote = git("rev-parse", "--verify", f"refs/remotes/origin/{branch}", check=False)
    if local != remote:
        raise RuntimeError("Local and remote commits differ; reconcile before finish.")
    print("Synchronized:", local)
    print("Review PR: https://github.com/" + EXPECTED_REMOTE + "/compare/stable..." + branch)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "start", "finish"):
        sub.add_parser(name)
    cp = sub.add_parser("checkpoint")
    cp.add_argument("-m", "--message", required=True)
    args = parser.parse_args()
    try:
        if args.command == "status":
            status()
        elif args.command == "start":
            start()
        elif args.command == "checkpoint":
            checkpoint(args.message)
        elif args.command == "finish":
            finish()
        return 0
    except (RuntimeError, OSError, SyntaxError) as exc:
        print("SYNC BLOCKED:", exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
