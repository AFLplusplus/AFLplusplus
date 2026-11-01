# Sovereign Brain Training Studio (Phase 1)

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
