# Sovereign Brain Training Studio (Phase 1)

Prototype V1 now includes one persistent simulated personality, relationship memory,
and pre-decision appraisal. See `PROTOTYPE_V1.md` for module boundaries, limitations,
and the migration path to a self-hosted API, PostgreSQL and a secure web frontend.

## Standalone local model upgrade

The Training Studio remains independent from Hermes and all operational agents.
The local inference adapter defaults to `http://127.0.0.1:11434/v1` and the exact
requested model `qwen3:0.6b`. It uses OpenAI-compatible structured output with
validated JSON; no API key is sent to local Ollama. Connection errors, timeouts,
HTTP failures and malformed output produce safe messages without response bodies.

Choose a user-writable workspace such as
`%USERPROFILE%\Documents\Codex\SovereignBrain`. Leave protected repositories
and Windows permissions unchanged. Before updating an existing workspace, compare
upstream code, back up local changes, and preserve all private training data.

Double-click `Launch Sovereign Brain.cmd` to start the Studio. `launch_studio.py`
uses an available loopback port and records the actual URL in
`local_logs/studio-url.json`. If the bundled official Ollama CLI is present under
`ollama-runtime/`, it starts only that local inference service, never agents.
The separate child-process profile, model store and logs stay within this workspace.
No system environment, existing credentials, services, ACLs or firewall settings
are changed. New Ollama application identity files remain private and Git-ignored.
Cloud inference and prompt logging are disabled in the managed local runtime.

### Resource policy

The `qwen3:0.6b` runtime uses a 2048-token context, at most 768 output tokens, one
concurrent generation and one loaded model. Keep-alive is zero seconds; there is
no model preloading. Every local generation request requires at least 1.5 GiB of
available physical RAM. Unknown RAM fails closed. Other model identifiers retain
the conservative 2.5 GiB guard and 4096-token context.
This is a conservative application policy, not an official model minimum.
No alternative model is silently downloaded. A detected installation is not proof
that inference succeeds. Read the deployment verification report for actual results.

Set `BRAIN_LOCAL_MODEL` to configure the Studio's local Ollama model and managed
runtime policy. `BRAIN_MODEL` configures the standalone API adapter default.
Memory failures and invalid structured model output are separate error types.

### Emotional display and memory

The model returns thirteen simulated emotional indexes (including guilt and jealousy), competing emotions,
evidence versus uncertainty, decision options, a proposed action and a concise
explanation. Indexes are computational representations, not real experiences or
psychological measurements. Legacy dopamine/cortisol/serotonin values and old
training histories remain readable. Each new response records state before and
after, its source, and the IDs of previous corrections included in its request.

Saved trainer corrections are retrieved by transparent word overlap from recent
local turns. Trainers can inspect retrieved corrections and opt out. References
are separately opt-in. This is persistent contextual adaptation, not fine-tuning.
A correction being included in a prompt is not proof that a model followed it.
Offline mode keeps the fixed narrative fixture and labels its deterministic
word-matched emotion visualization explicitly. It is never treated as real inference.

### Scenario quality and state inspection

Responsibility for harming a coworker and jealousy without evidence of dishonesty
receive different advisory candidates, affected-party concerns and consequences.
Responsibility and fairness are contextual concerns, separate from stable traits.
The lexical appraisal is fallible; the model may choose an action outside its candidates.
There is no fallback that replaces a model decision with a preferred action.

The compact inference prompt omits the old numerical state and unreviewed proposed
rules to reduce copying. Relevant corrections and relationship context remain explicit.
Retrieval requires two substantive token matches; shared pronouns are insufficient.
Runtime validation rejects malformed structure, placeholder labels, bare option IDs,
unrelated evidence and exact state copying when appraisal materially differs. Invalid
output is reported without saving a turn, retrying automatically or fabricating emotions.

The transition table distinguishes persisted Before, raw Model proposed, and smoothed
After (35% previous / 65% proposed). Older history is retained unchanged; absent new
indexes appear blank in historical output and receive explicit baseline defaults only
when loading current state. Identity and stable traits are never changed by this migration.
Controlled fake-model regressions validate data flow, not genuine Qwen judgment.

Enterprise gateways remain replaceable through `BRAIN_API_BASE`, `BRAIN_MODEL`
and `BRAIN_API_KEY`. Remote inference requires HTTPS and explicit UI authorization
for session data, retrieved feedback and selected reference excerpts. References
and research do not automatically overwrite behavioral rules.

### Verification

Run `.venv\Scripts\python.exe -m unittest discover -s tests -v` from the
standalone application directory. Transport tests use fake loopback responses;
they are explicitly separate from genuine Ollama inference checks. UI tests use
temporary stores and never alter the trainer's real saved history.

Modules: `model_api.py` (transport), `appraisal.py` (state), `decision.py`
(recommendation contract), `trainer.py` (state updates), `service.py` (training),
and `studio.py` (feedback/references/documents/research). No autonomous execution
interface is provided.

**Standalone application.** Hermes, agent orchestration, network campaigns, and real model-weight fine-tuning are not part of this phase.

## Run on Windows

Open the existing repository at `C:\SecurityCompanyAgent` in VS Code/Codex.

```powershell
py security-company-agent\scripts\sync.py start
py -m pip install -r security-company-agent\requirements-brain.txt
py -m unittest discover -s security-company-agent\tests -v
py -m streamlit run security-company-agent\brain_studio.py --server.address 127.0.0.1
```

Open the loopback URL shown in the VS Code terminal (normally http://localhost:8501).

**First run:** Select **Offline demonstration** from the sidebar. This mode returns a fixed example to test the UI; it is **not LLM reasoning**.

**Actual model:** Set these environment variables locally before starting Streamlit:

- `BRAIN_API_BASE`: base URL **including /v1**, e.g. `https://your-approved-gateway.example/v1`
- `BRAIN_MODEL`: exact approved model identifier
- `BRAIN_API_KEY`: API credential (do not paste into chats or commit to Git)

The model server must implement compatible `/chat/completions` responses. Never use an unapproved external provider for sensitive documents.

**Research (optional):** Set `TAVILY_API_KEY` in your environment. Web search is user-initiated; returned snippets are held for review and included as contextual material only after explicit approval. No autonomous unrestricted browsing or scraping.

## Features

- Scenario training with trainer guidance, simulated emotion state, decision recommendation and human rating
- Upload PDF, DOCX, TXT or MD files, with plaintext extraction and local SQLite storage
- Retrieval by simple text-term overlap; this is MVP retrieval, not semantic vector RAG
- Source-labeled, manually approved web research excerpts (subject to the configured API)
- Persistent state at `brain_core/eq_matrix.json`, rules/history at `brain_core/neuroplasticity_log.json`, and training/documents at `brain_core/studio_data/brain.sqlite3`

Local stores and secrets are Git-ignored. Uploaded content and selected reference excerpts may be transmitted to your configured LLM API during a training request. The app currently does **not** implement encryption at rest, access control for other local users, OCR, semantic search, model-weight updates, or independent validation of source claims.

## Planned Phase 2

Introduce a testable appraisal/decision engine, explicitly separated emotions and choices, rule approval, feedback reflection, safer transactional persistence, scenario benchmarks, and more substantive human-behavior research. Do not attach operational agents before evaluation and authorization control integration.
