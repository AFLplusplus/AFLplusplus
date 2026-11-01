# Sovereign Brain prototype V1

This self-hostable prototype is a recommendation system with one persisted simulated
personality. It is not a foundation model, a conscious entity, or an agent orchestrator.
The temporary prototype model is `qwen3:0.6b` served by local Ollama. No OpenAI SDK,
OpenAI account, or OpenAI-hosted inference is required. The transport uses an open,
OpenAI-compatible HTTP message format, which is distinct from depending on that provider.

## Identity and memory

`brain_core/personality.py` loads one profile at `brain_core/personality.json`.
`identity_id` remains `sovereign-brain-001`. Stable traits are validated and never
modified by training. A separate `personality.identity` marker makes deletion of an
established profile fail closed rather than silently create a replacement. Corrupt,
unsupported or unexpected identities require human recovery. Initial publication is
atomic and does not overwrite a concurrent creator. These private files are ignored
by Git. Back up both profile and marker together. A marker is a persistence guard,
not tamper-proof authentication; deletion of all identity artifacts cannot be detected.

Temporary emotions persist separately in `eq_matrix.json`. Training experiences and
corrections live in SQLite; the legacy JSON history remains supported. An optional
trainer-defined label selects a relationship-specific emotion bucket. Unlabeled
situations do not share an implicit relationship identity. Fixed demonstration output
never updates a live relationship bucket. Existing historical records remain readable.

## Recommendation flow

1. Load and validate the stable identity and traits.
2. Retrieve relevant previous experiences and trainer corrections from local storage.
3. Retrieve emotions for the optional relationship label.
4. Compute a transparent lexical appraisal and weighted decision preferences before
   model inference. Trait and emotion contributions are separately inspectable.
5. Supply the same personality snapshot, temporary state, relationship state,
   experiences, uncertainty policy, and preferences to the model.
6. Validate the structured recommendation and resulting simulated emotion state.
7. Store the experience; accept trainer rating and correction for later retrieval.

The weighting mechanism is an engineering heuristic, not validated psychology. The
model can review and disagree with its proposed preference. Inference output and
human feedback are not proof of understanding. Mock tests establish data flow,
persistence and causal effects on heuristic ranking, not genuine model reasoning.

Human consent and authorization are independent of traits and emotions. The service
offers recommendations only. It exposes no operational execution interface, imports
no security-agent framework, and never turns an emotional score into permission.
Documents are opt-in references; research sources require trainer review. Neither
automatically replaces stable traits or authorizes actions. The model gateway's
remote-data consent check remains separate from personality and appraisal.

## Module boundaries

| Concern | Module |
|---|---|
| Inference transport and structured responses | `brain_core/model_api.py` |
| Persistent identity and stable traits | `brain_core/personality.py` |
| Emotional representations | `brain_core/appraisal.py` |
| Pre-decision appraisal and preferences | `brain_core/cognition.py` |
| Experience and relationship retrieval | `brain_core/memory.py` |
| Recommendation schema | `brain_core/decision.py` |
| Stateful training | `brain_core/trainer.py` |
| Application service | `brain_core/service.py` |
| Documents, corrections, reviewed research, SQLite | `brain_core/studio.py` |
| Browser presentation | `brain_studio.py` |

## Local operation and limits

Use the existing virtual environment and `Launch Sovereign Brain.cmd`. The launcher
binds Streamlit to loopback and records its actual URL under `local_logs/`. Expand
**Persistent personality** in the sidebar to inspect identity and traits. The main
screen accepts a direct question or scenario, optional relationship context, and
trainer guidance. Results include before/after emotion values, options, a decision
explanation, and inspectable pre-decision preferences. Prior experiences remain in
Training history; trainer corrections are visible before reuse.

Ollama stays on `127.0.0.1:11434`, with cloud inference disabled. The application
blocks every local generation request below the model-specific physical RAM guard:
1.5 GiB for `qwen3:0.6b`, 2.5 GiB for other identifiers. Unknown RAM fails closed.
The 0.6B policy uses 2048 context tokens, at most 768 output tokens, one request at
a time, one loaded model and zero-second keep-alive. No background preload occurs.
Set `BRAIN_LOCAL_MODEL` to select the local Studio/runtime model; `BRAIN_MODEL`
selects the configurable API adapter model. A software test pass does not
establish hardware readiness or successful generation. The deployment report must
state whether genuine inference was actually performed. No model is silently swapped.

Local data is not encrypted and the prototype has no multiuser authentication. JSON
and SQLite writes are not one distributed transaction, and training is not yet
serialized across multiple serving processes. Use one application process. Keep
backups; do not deploy publicly in this form. Lexical memory retrieval, relationship
labels and emotional weighting are initial prototypes, not validated assessment tools.

## Migration path (documented only; no public deployment)

1. **Python API backend:** wrap `service.analyze` and `service.give_feedback` with
   authenticated request handlers. Introduce explicit request/response DTOs, bounded
   inputs, cancellation, rate limits, and identity-scoped authorization. Keep the
   cognitive modules independent of the web framework and remove process-global
   file paths through repository interfaces and configuration injection.
2. **PostgreSQL:** implement repositories for personality, versioned traits, temporary
   state, relationship state, experiences, feedback, documents and research approval.
   Use a unique identity constraint, transactions, optimistic version checks, and
   per-identity serialization. Migrate existing records with hashes, row counts and
   backups; never initialize over existing state. Make identity creation an explicit
   provisioning transaction and prevent user requests from creating new identities.
3. **Self-hosted inference:** retain the model interface and point it to an internal
   Ollama or vLLM service. Validate the chosen model's structured-output support,
   capacity, context and latency. Apply service authentication, network isolation,
   bounded concurrency, deadlines and model provenance. Never make inference itself
   an authorization boundary. No dependency on OpenAI services is required.
4. **Secure web frontend:** replace Streamlit presentation with a frontend calling
   the API. Add sessions, CSRF protection, per-identity access checks, TLS, secure
   document handling, data retention controls and explicit consent for any remote
   inference. Do not expose the local prototype or raw model endpoint publicly.
5. **Future authorized orchestration:** define a separate, audited proposal boundary
   for recommendations. Any future execution requires independent deterministic
   scope validation, human approval, resource limits and a controlled worker service.
   Personality, mood and model output must never create or override that approval.

Run all tests with `.venv\Scripts\python.exe -m unittest discover -s tests -v`.
Tests use temporary stores and clearly labelled mock/fake inference. A genuine
two-session test remains a separate hardware-gated acceptance check.
