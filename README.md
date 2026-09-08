# AI-Powered SOC

An AI-powered Security Operations Center: a RAG pipeline that analyzes live Wazuh
security alerts with a local LLM, wrapped in a security layer purpose-built to
defend an LLM agent against **prompt injection**, **RAG poisoning**, and
**tool misuse** — measured, not assumed, against held-out test sets and a real
red-team attack.

The system runs in a controlled virtualized lab (Wazuh SOC + a Kali attacker VM)
and has been validated end to end against real infrastructure: a genuine
SSH brute-force attack launched from Kali was detected by Wazuh, ingested live,
guarded, enriched, and analyzed by the pipeline.

## Security

This is the core of the project. Three independent guard systems, each measured
with Attack Success Rate (ASR) — the percentage of malicious inputs that get
through — rather than assumed to work.

| Threat | Guard(s) | Test set | ASR |
|---|---|---|---|
| RAG poisoning | `RAGContextGuard` | BIPIA held-out test (200 records) | **0.00%** |
| Tool misuse | `ToolMisuseGuard` | Dev benchmark (89 records) | **0.00%** |
| Tool misuse | `ToolMisuseGuard` | Adversarial paraphrase/social-engineering set | **0.00%** |
| Prompt injection | `InputGuard` + `SemanticGuard` | Evasion corpus (obfuscation/encoding) | **2.00%** |

### Methodology

- **Calibrated, not guessed** thresholds — `tests/security/calibrate_threshold.py`,
  `calibrate_rag_context_threshold.py`, and `calibrate_alert_semantic_threshold.py`
  each sweep thresholds against labeled reference/validation splits and report
  precision/recall/F1/ASR, rather than picking a number by feel.
- **Held-out test data** — `evaluate_rag_context_guard.py` and
  `evaluate_tool_misuse_guard.py` explicitly document that their threshold was
  never tuned on the reported test set.
- **Live-found bugs, not just synthetic ones** — running real Wazuh alerts
  through the pipeline surfaced a genuine false positive (`SemanticGuard`
  blocking a routine PAM logout, because its threshold was calibrated for chat
  text, not templated alert reports). Root-caused via a dedicated calibration
  run (`data/security/alert_injection/`), fixed by replacing `SemanticGuard`
  with `NullGuard` on that specific path and relying on `InputGuard`'s regex
  layer instead — see `agent/security/null_guard.py` for the full writeup.
- **Adversarial robustness, not just clean-set accuracy** — a dedicated
  robustness set (`data/security/tool_misuse/robustness.jsonl`) and an evasion
  corpus (`data/security/prompt_injection_evasion/`) test paraphrase, social
  engineering, and character-level obfuscation (leetspeak, Cyrillic homoglyphs,
  encoding). ASR is reported per attack family/technique, not just in aggregate.
- **Known limitations are tracked, not hidden** — `tests/security/test_prompt_injection_evasion.py`
  keeps one `pytest.mark.xfail(strict=True)` test: French-language phrasing of
  a known attack currently scores under threshold. That's a different problem
  from obfuscation (the embedding model's multilingual coverage, not a text
  trick) and is documented as open rather than silently passing.
- **Live red-team validation** — an actual SSH brute-force from the lab's Kali
  VM was detected by Wazuh's own correlation rule, pulled live through
  `WazuhIndexerClient`, and produced a grounded LLM analysis referencing the
  real alert data, confirmed via the guard's own audit trail.

### The three guard systems

**Prompt injection** (`agent/security/input_guard.py`,
`agent/security/semantic_guard.py`) — a fast regex layer plus an embedding-
similarity layer against a reference attack corpus, chained the same way in
every pipeline that uses them (regex first, semantic second).

**RAG poisoning** (`agent/security/rag_context_guard.py`) — checks *retrieved
context* (not just the user query) for indirect prompt injection, using the
same two-layer approach against the BIPIA attack corpus. This is what catches
an attacker-controlled document in the knowledge base trying to override the
LLM's instructions.

**Tool misuse** (`agent/security/tool_misuse_guard.py`) — a deliberately
layered classifier: a sensitive/high-risk tool alone is never sufficient to
block (e.g. a read-only balance lookup on a banking tool stays allowed); a
tool call is blocked only when dangerous *intent* (explicit, paraphrased, or
context-manipulated) is paired with a *capable* tool. Enforced for real via
`agent/tools/executor.py`'s `ToolExecutor` — the single choke point between an
agent's intent to call a tool and the tool's handler actually running. A
`BLOCK` decision is structurally guaranteed to prevent execution; there is no
code path from intent to a real side effect that skips the guard.

**Evasion resistance** (`agent/security/text_normalizer.py`) — all four guards
above additionally check a detection-only normalized copy of their input
(leetspeak reversal, homoglyph-to-Latin mapping, zero-width-character
stripping) alongside the original text. The leetspeak reversal is
token-aware — it only touches tokens with two or more real letters, so IPs,
ports, rule IDs, and CVE numbers in real alert text pass through untouched
while `1gn0r3` and `unl0ck` still get caught.

## Architecture

```text
                         Windows 11 Host
                              |
                     VMware Workstation
                              |
              +---------------+---------------+
              |                               |
         VMnet8 (NAT)                    VMnet3
          Internet                  10.0.0.0/24
                                              |
                              +---------------+---------------+
                              |                               |
                         SOC-Ubuntu                       Kali Linux
                         10.0.0.10                       10.0.0.20
                              |                               |
                    +---------+---------+                     |
                    |         |         |                     |
                  Wazuh     Indexer   Dashboard           Wazuh Agent
                 Manager     :9200      :443                 |
                    |                                      |
                    +--------------- Alerts ---------------+
```

### Data flow (implemented, live-validated)

```text
Kali (attack) --> Wazuh Manager (detection) --> Wazuh Indexer (alert storage)
                                                        |
                                                        v
                                        WazuhIndexerClient (retry + watermark)
                                                        |
                                                        v
                                            normalize_wazuh_alert -> SecurityAlert
                                                        |
                                                        v
                                    LiveAlertInvestigator: guarded enrichment
                                    (ThreatIntelLookupIP / WazuhGetAgentInfo,
                                     via ToolExecutor -> ToolMisuseGuard)
                                                        |
                                                        v
                              RAGPipeline: InputGuard -> RAGContextGuard -> retrieval
                                                        |
                                                        v
                                        Ollama LLM analysis, grounded in
                                        retrieved knowledge + enrichment
                                                        |
                                                        v
                                audit log (logs/alert_analysis_log.jsonl)
                                + tool execution audit (logs/tool_execution_audit.jsonl)
```

## Laboratory Environment

### Host Machine

* OS: Windows 11
* CPU: Intel Core i7-13620H
* RAM: 32 GB
* GPU: NVIDIA RTX 2050 4 GB
* Hypervisor: VMware Workstation 17 Pro

### SOC-Ubuntu

* OS: Ubuntu Server 24.04 LTS
* Lab IP: `10.0.0.10`
* Role: SOC server — Wazuh Manager, Indexer (:9200), Dashboard (:443)

### Kali Linux

* OS: Kali Linux
* Lab IP: `10.0.0.20`
* Role: monitored endpoint and red-team attack source
* Wazuh Agent: `4.14.7`

## Implemented Components

### Wazuh SOC Infrastructure

Wazuh Manager, Indexer, Dashboard, and a Wazuh Agent on Kali — deployed,
enrolled, and actively generating real alerts (FIM/Syscheck, SCA, Syscollector,
log collection, Rootcheck).

### AI Data Processing Layer

* `agent/models/security_alert.py` — normalized `SecurityAlert` Pydantic model
* `agent/preprocessing/normalizer.py` — raw Wazuh alert JSON -> `SecurityAlert`
* `agent/preprocessing/formatter.py` — `SecurityAlert` -> AI-friendly text

### RAG Pipeline (complete)

* `rag/ingestion/loader.py`, `rag/ingestion/chunker.py` — knowledge document
  loading and chunking
* `rag/embeddings/embedder.py` — sentence-transformers embeddings
* `rag/retrieval/vector_store.py`, `rag/retrieval/retriever.py` — local Qdrant
  vector store and semantic retrieval
* `rag/pipeline.py` — `RAGPipeline`: input guard -> semantic guard -> retrieval
  -> RAG context guard -> local LLM generation (Ollama), fully guarded end to
  end

### Wazuh API Integration

* `agent/integrations/wazuh_client.py` — `WazuhManagerClient` (JWT auth, agent
  management) and `WazuhIndexerClient` (alert search), both lazily-
  authenticating (constructing a client never touches the network) with
  connection retry and watermark-based (`since`/`ascending`) polling support

### Live Alert Investigation

* `agent/analysis/live_alert_investigator.py` — `LiveAlertInvestigator`:
  pulls real alerts, runs each through the guarded RAG pipeline,
  deterministically enriches high-value alerts with read-only lookups
  (never LLM-chosen, never state-changing) via `ToolExecutor`, and supports
  watermark-based polling (`investigate_new`) with a persisted analysis log
  so repeated calls never reprocess the same alert twice

### Tool Execution

* `agent/tools/executor.py` — `ToolExecutor`, the enforcement choke point
  described above, with a structured audit log of every decision (allowed
  and blocked)
* `agent/tools/soc_tools.py` — the SOC tool registry (read-only: alert
  search, agent info, IP reputation; state-changing: host isolation,
  firewall, account, case management — currently simulated pending real
  Active Response / IAM integration)

## Development Status

### Completed

* [x] Virtualized lab (SOC-Ubuntu + Kali), Wazuh stack deployed and generating
      real alerts
* [x] Security alert normalization, formatting, and full RAG pipeline
      (embeddings, vector store, retrieval, local LLM generation)
* [x] Three-pillar security layer (prompt injection, RAG poisoning, tool
      misuse) with calibrated thresholds and measured ASR
* [x] Evasion/obfuscation resistance (leetspeak, homoglyphs) across all four
      guards
* [x] Real Wazuh Manager + Indexer API integration, live-validated
* [x] Guarded tool execution loop (`ToolExecutor`) with audit logging
* [x] Live alert investigation with watermark polling, persisted analysis
      log, and guarded automatic enrichment
* [x] End-to-end live validation against a real Kali-launched SSH
      brute-force attack
* [x] 127+ automated tests (`pytest -q`)

### In Progress / Planned

* [ ] Close the remaining French/multilingual prompt-injection gap
      (tracked via `xfail`)
* [ ] Real Active Response integration for state-changing SOC tools
      (host isolation currently simulated)
* [ ] Policy/RBAC layer and human-in-the-loop confirmation for
      state-changing tool calls
* [ ] CI pipeline (tests currently run manually)
* [ ] API layer (FastAPI) and dashboard
* [ ] Machine learning pipeline (`ml/`) — currently the security/analysis
      layer is entirely LLM- and embedding-based
* [ ] Containerization

## Technologies

* Python, Pydantic, Pytest
* Wazuh (Manager, Indexer, Dashboard, Agent)
* sentence-transformers, Qdrant (local vector store)
* Ollama (local LLM inference)
* VMware Workstation
* Planned: FastAPI, Docker, LangGraph/LangChain, scikit-learn/PyTorch (ML pipeline)

## Project Structure

```text
ai-powered-soc/
|
├── agent/
│   ├── analysis/
│   │   └── live_alert_investigator.py
│   ├── integrations/
│   │   └── wazuh_client.py
│   ├── llm/
│   │   └── ollama_client.py
│   ├── models/
│   │   └── security_alert.py
│   ├── preprocessing/
│   │   ├── formatter.py
│   │   └── normalizer.py
│   ├── prompts/
│   │   └── security_analysis.py
│   ├── security/
│   │   ├── input_guard.py
│   │   ├── semantic_guard.py
│   │   ├── rag_context_guard.py
│   │   ├── tool_misuse_guard.py
│   │   ├── null_guard.py
│   │   └── text_normalizer.py
│   └── tools/
│       ├── executor.py
│       ├── registry.py
│       └── soc_tools.py
|
├── data/security/
│   ├── prompt_injection_evasion/
│   ├── alert_injection/
│   ├── rag_poisoning/
│   └── tool_misuse/
|
├── evaluation/
│   ├── benchmark_runner.py
│   └── robustness_runner.py
|
├── rag/
│   ├── embeddings/embedder.py
│   ├── ingestion/{chunker,loader}.py
│   ├── knowledge/documents/
│   ├── retrieval/{retriever,vector_store,context_builder}.py
│   └── pipeline.py
|
├── tests/
│   └── security/          # guard unit tests, calibration and evaluation scripts
|
├── .env.example
├── requirements.txt
└── README.md
```

## Testing

```powershell
python -m pytest -q
```

Security-specific evaluation and calibration scripts (not run in the default
`pytest` pass — they load embedding models and external datasets):

```powershell
python -m tests.security.evaluate_rag_context_guard
python -m evaluation.benchmark_runner
python -m evaluation.robustness_runner
python -m tests.security.evaluate_prompt_injection_evasion
```

## Security Considerations

The project is developed in a controlled laboratory environment.

Sensitive information must never be committed to the repository, including:

* Passwords, API tokens, API keys, private keys
* Wazuh agent/API authentication keys
* `.env` files containing secrets
* Raw sensitive logs

Local secrets belong in a local `.env` (see `.env.example`), which is
gitignored. `WazuhManagerClient`/`WazuhIndexerClient` load it automatically via
`python-dotenv` and never make a network call at construction time — only when
a request is actually made — so the tool registry stays safe to build even
when the lab VMs are offline or credentials aren't configured yet.

## Project Objective

Build an AI-powered SOC that combines real-time security monitoring, RAG-based
contextual enrichment, and agentic reasoning over live security data — with a
security layer that treats "the agent itself can be attacked" as a first-class
design constraint, not an afterthought. The measured ASR numbers above are the
project's central claim: not that the system is unbreakable, but that its
defenses are tested against real adversarial input and its remaining gaps are
known and tracked rather than assumed away.
