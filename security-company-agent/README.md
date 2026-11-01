# SecurityCompanyAgent (isolated workspace)

This project lives under `security-company-agent/` in the AFLplusplus repository, without modifying the upstream AFL++ source tree.

## Windows first-time setup

**Important:** If `C:\SecurityCompanyAgent` contains any existing project files, do not clone into or replace it. First back up the entire directory and reconcile those files manually or with Codex. The clone command below is only for a **new empty directory**.

1. Install Git for Windows and Python 3.11+ if not installed.
2. In PowerShell, to clone into an empty directory:

```powershell
git clone --branch stable https://github.com/budhadityarishidasgupta-lang/AFLplusplus.git C:\SecurityCompanyAgent
Set-Location C:\SecurityCompanyAgent
git fetch origin
git switch --track origin/feature/security-company-agent-bootstrap
```

The latest app files are now at `C:\SecurityCompanyAgent\security-company-agent`.

## Local Git synchronization

From `C:\SecurityCompanyAgent`:

```powershell
py security-company-agent\scripts\sync.py status
py security-company-agent\scripts\sync.py start
py security-company-agent\scripts\sync.py checkpoint -m "chore: add validated infrastructure"
py security-company-agent\scripts\sync.py finish
```

- `status`: read-only inventory of branch, worktree and upstream.
- `start`: fetch remote, fast-forward only when worktree is clean and tracking branch is compatible.
- `checkpoint`: compile Python files, stage **only security-company-agent/**, inspect staged changes for common secret patterns, commit, push current **feature/** branch (never stable).
- `finish`: fetch and verify local/remote feature branch alignment; no automatic merging.

The scripts deliberately refuse to run if the repository is different, the branch is `stable` for writes, files outside this app are modified, or a safe fast-forward is impossible. They never force push, clean, reset, or merge.

## Brain code

This is a Git workflow scaffold, **not** a completed migration of existing local scripts. Existing `multi_agent_system.py`, `enterprise_stealth_range.py`, `conversational_launcher.py` and private state must be inspected locally before integration. No network testing workers are automatically enabled by this scaffold.

## Confidentiality

Do not commit local state, secrets, personal training histories, passwords or target campaign data. Check `git status` before each checkpoint. Git ignores only prevent untracked file additions; remove already tracked sensitive files from Git's index separately if discovered.
