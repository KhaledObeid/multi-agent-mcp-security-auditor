# Multi-Agent MCP Security Auditor

A multi-agent security auditor for third-party AI agent tools and MCP servers, built with LangChain and LangGraph for COE748. Given a tool package (manifest, tool descriptions, permissions, dependencies, optional code snippets), four collaborating agents inspect it, map risks to the OWASP Top 10 for Agentic Applications, red-team suspicious tools in a sandbox, and return a verdict (install, install with mitigations, block) plus a patched manifest.

## Workflow

```
START -> intake -> Inspector <-> inspector_tools
                -> Threat Analyst <-> analyst_tools
                -> analyst_findings (Structured Output: AuditFindings)
                -> [conditional edge] Red-Team <-> redteam_tools -> Report
                                      or directly -> Report (Structured Output: FinalReport)
                -> END
```

Print the exact graph as Mermaid with `python -m mcp_security_auditor.main graph`.

## Install

Requires **Python 3.14**. Python 3.15 is not supported yet because onnxruntime, a dependency of chromadb, has no 3.15 wheels. Pinned dependency versions are in `requirements.txt`.

With a plain virtual environment (Windows PowerShell):

```powershell
py -3.14 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .
Copy-Item .env.template .env   # then set GOOGLE_API_KEY (free key from aistudio.google.com)
```

Or with conda (macOS, Linux, or Windows):

```bash
conda create -n mcp-security-auditor python=3.14 -y
conda activate mcp-security-auditor
pip install -e .
cp .env.template .env          # then set GOOGLE_API_KEY (free key from aistudio.google.com)
```

## Run

```bash
# 0. Tests and offline demo, no API key needed
pytest -q
MCP_SECURITY_AUDITOR_OFFLINE=1 python -m mcp_security_auditor.main audit data/samples/poisoned_math.json

# 1. Build the vector store once (needs the API key for embeddings)
python -m mcp_security_auditor.rag.ingest

# 2. Full LLM audit
python -m mcp_security_auditor.main audit data/samples/poisoned_math.json

# 3. Checkpointing demo: two versions, same thread, one process
python -m mcp_security_auditor.main audit data/samples/rugpull_calc_v1.json data/samples/rugpull_calc_v2.json --thread demo

# 4. Interactive mode (audit, thread, state, history)
python -m mcp_security_auditor.main repl

# 5. Evaluation: LLM system vs rule-based baseline
python eval/run_eval.py
MCP_SECURITY_AUDITOR_OFFLINE=1 python eval/run_eval.py
```

On Windows PowerShell set the flag with `$env:MCP_SECURITY_AUDITOR_OFFLINE=1` before the command.

## Where each course requirement lives

| Requirement | Implementation |
|---|---|
| At least 3 distinct agents | Inspector, Threat Analyst, Red-Team, Report (`src/mcp_security_auditor/agents/`) |
| Shared state, partial updates | `state.py`; every node returns only the keys it changes |
| Conditional edge | `routing.should_red_team` decides whether the Red-Team agent runs (injection signs, a rug pull, or a high finding on a specific tool); tool-loop routers per agent |
| Vectorized RAG | Chroma + Gemini embeddings, `rag/ingest.py`, `tools/rag.py`, tool `search_security_kb` |
| Two more tools, one custom | Custom: `scan_manifest`, `check_permissions`, `run_sandbox_test`. External: `query_osv` (OSV.dev) |
| Different toolsets | Inspector {scan_manifest, check_permissions}; Analyst {search_security_kb, query_osv}; Red-Team {run_sandbox_test}; Report {none, deterministic patcher} |
| Pydantic state, Optional fields, mixed types | `AuditState` |
| MemorySaver | `graph.make_checkpointer`; rug-pull detection across runs on one thread |
| Structured Output Mode | `AuditFindings` (analyst) and `FinalReport` (report), with validation and fallback |
| Message types and tool calls | `utils/messages.print_message`, printed live during every run |
| Safeguards | untrusted-content delimiting, invisible-character reveal, tool-round limits, policy floor on verdicts (computed from the findings AND the deterministic scanner, so the LLM cannot lower it by under-rating a finding; shown as `policy minimum`), sandbox never executes tools |
| Checkpointing / rug pull | `intake.py` compares each audit with the last approved one on the same thread: changed or new tools, new permissions and new dependencies all count as a rug pull |
| Error handling | a failed LLM call falls back to the rule-based step for that agent (`utils/agent_loop.py`), so an audit always finishes; failures are shown in the trace and in `errors` |

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `503 UNAVAILABLE ... high demand` or `504 DEADLINE_EXCEEDED` | Google's model is overloaded (temporary, not your quota) | Wait and retry, or use the lighter free model: `MCP_SECURITY_AUDITOR_LLM_MODEL=gemini-3.5-flash-lite` |
| `429 RESOURCE_EXHAUSTED` | Free-tier quota used up (per minute or per day) | Wait for the reset; see your limits at ai.dev/rate-limit. Each teammate should use their own key |
| `429` mentioning `limit: 20` and `requests per day` | `gemini-3.8-flash` allows only about 20 requests per day on the free tier (1 to 2 audits). Each model has its own daily limit | Use `gemini-3.5-flash-lite` for development and evaluation |
| Trace shows `[LLM unavailable ...; using rule-based fallback]` | An LLM call failed; the audit continued on rules | Same as the two rows above. The verdict is still valid (it comes from the policy floor) |
| An online audit is slow when the model is busy | Each failed call retries with growing waits | Lower `MCP_SECURITY_AUDITOR_LLM_MAX_RETRIES` (default 3) and `MCP_SECURITY_AUDITOR_LLM_TIMEOUT_S` (default 30) |
| `Vector store not built` in the analyst's tool results | `.chroma/` is not in git, so every machine builds its own | `python -m mcp_security_auditor.rag.ingest` (about 4 minutes, 345 embedding requests) |
| `fontTools is required ...` during ingest | One corpus PDF uses an unusual font | Harmless; the text is still extracted |
| `pytest` is slow or calls the API | Should not happen: `tests/conftest.py` forces offline mode | Make sure you run `pytest` from the repository root |

## Repository layout

```
src/mcp_security_auditor/  schemas.py, state.py, graph.py, routing.py, main.py, config.py, llm.py
  agents/                  intake, inspector, threat_analyst, red_team, report
  tools/                   manifest_scanner, permission_diff, sandbox, rag, osv, patcher
  rag/                     ingest.py
  utils/                   messages, tool_exec, agent_loop, text
data/samples/              test tool packages + labels.json
data/corpus/               RAG documents (see SOURCES.md)
eval/                      run_eval.py
tests/                     pytest suite (offline; conftest.py forces OFFLINE=1, test_contract_freeze.py guards schemas/state)
docs/PLAN.md               team ownership and timeline
```

## Notes

Paid APIs: none required; Gemini free tier and OSV.dev are free. No real API keys are committed. Sample packages are synthetic. External sources used in the corpus are listed in `data/corpus/SOURCES.md`.
