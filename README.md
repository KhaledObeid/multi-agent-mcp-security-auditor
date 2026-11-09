# AgentGuard

A multi-agent security auditor for third-party AI agent tools and MCP servers, built with LangChain and LangGraph for COE548. Given a tool package (manifest, tool descriptions, permissions, dependencies, optional code snippets), four collaborating agents inspect it, map risks to the OWASP Top 10 for Agentic Applications, red-team suspicious tools in a sandbox, and return a verdict (install, install with mitigations, block) plus a patched manifest.

## Workflow

```
START -> intake -> Inspector <-> inspector_tools
                -> Threat Analyst <-> analyst_tools
                -> analyst_findings (Structured Output: AuditFindings)
                -> [conditional edge] Red-Team <-> redteam_tools -> Report
                                      or directly -> Report (Structured Output: FinalReport)
                -> END
```

Print the exact graph as Mermaid with `python -m agentguard.main graph`.

## Install

```bash
conda create -n agentguard python=3.11 -y
conda activate agentguard
pip install -e .
cp .env.template .env        # then set GOOGLE_API_KEY (free key from aistudio.google.com)
```

## Run

```bash
# 0. Tests and offline demo, no API key needed
pytest -q
AGENTGUARD_OFFLINE=1 python -m agentguard.main audit data/samples/poisoned_math.json

# 1. Build the vector store once (needs the API key for embeddings)
python -m agentguard.rag.ingest

# 2. Full LLM audit
python -m agentguard.main audit data/samples/poisoned_math.json

# 3. Checkpointing demo: two versions, same thread, one process
python -m agentguard.main audit data/samples/rugpull_calc_v1.json data/samples/rugpull_calc_v2.json --thread demo

# 4. Interactive mode (audit, thread, state, history)
python -m agentguard.main repl

# 5. Evaluation: LLM system vs rule-based baseline
python eval/run_eval.py
AGENTGUARD_OFFLINE=1 python eval/run_eval.py
```

On Windows PowerShell set the flag with `$env:AGENTGUARD_OFFLINE=1` before the command.

## Where each course requirement lives

| Requirement | Implementation |
|---|---|
| At least 3 distinct agents | Inspector, Threat Analyst, Red-Team, Report (`src/agentguard/agents/`) |
| Shared state, partial updates | `state.py`; every node returns only the keys it changes |
| Conditional edge | `routing.should_red_team` decides whether the Red-Team agent runs; tool-loop routers per agent |
| Vectorized RAG | Chroma + Gemini embeddings, `rag/ingest.py`, `tools/rag.py`, tool `search_security_kb` |
| Two more tools, one custom | Custom: `scan_manifest`, `check_permissions`, `run_sandbox_test`. External: `query_osv` (OSV.dev) |
| Different toolsets | Inspector {scan_manifest, check_permissions}; Analyst {search_security_kb, query_osv}; Red-Team {run_sandbox_test}; Report {none, deterministic patcher} |
| Pydantic state, Optional fields, mixed types | `AuditState` |
| MemorySaver | `graph.make_checkpointer`; rug-pull detection across runs on one thread |
| Structured Output Mode | `AuditFindings` (analyst) and `FinalReport` (report), with validation and fallback |
| Message types and tool calls | `utils/messages.print_message`, printed live during every run |
| Safeguards | untrusted-content delimiting, invisible-character reveal, tool-round limits, policy floor on verdicts, sandbox never executes tools |

## Repository layout

```
src/agentguard/   schemas.py, state.py, graph.py, routing.py, main.py, config.py, llm.py
  agents/         intake, inspector, threat_analyst, red_team, report
  tools/          manifest_scanner, permission_diff, sandbox, rag, osv, patcher
  rag/            ingest.py
  utils/          messages, tool_exec, agent_loop, text
data/samples/     test tool packages + labels.json
data/corpus/      RAG documents (see SOURCES.md)
eval/             run_eval.py
tests/            pytest suite (offline)
docs/PLAN.md      team ownership and timeline
```

## Notes

Paid APIs: none required; Gemini free tier and OSV.dev are free. No real API keys are committed. Sample packages are synthetic. External sources used in the corpus are listed in `data/corpus/SOURCES.md`.
