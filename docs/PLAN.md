# AgentGuard team plan (3 members, about 4 h/week each, due Dec 5, 2026 23:59)

Total budget is roughly 4 weeks x 4 h x 3 people = 48 person-hours, so the plan keeps scope tight and front-loads the risky parts (online LLM behaviour, RAG, OSV) into weeks 1 and 2.

## Why this splits cleanly

1. `schemas.py` and `state.py` are the contract. They are already written. Freeze them at the end of week 1; after that only additive, Optional fields, via a PR titled `contract: ...`.
2. Every agent already runs end to end in OFFLINE mode (`AGENTGUARD_OFFLINE=1`) with scripted turns, so nobody waits for anybody. You replace stubs and prompts inside your own files only.
3. Each person owns whole files. Two people should almost never edit the same file in the same week.
4. `tests/test_graph_offline.py` must stay green on `main`. If it passes, integration is not broken.

## Ownership

| Member | Owns (files) | Course requirements they carry |
|---|---|---|
| A, integrator | `state.py`, `schemas.py`, `graph.py`, `routing.py`, `main.py`, `agents/intake.py`, `agents/report.py`, `tools/patcher.py`, `utils/*`, `tests/test_graph_offline.py`, README | LangGraph, Pydantic state, MemorySaver, conditional edge, message printing, Report SOM, guardrail, demo video |
| B, attack surface | `agents/inspector.py`, `agents/red_team.py`, `tools/manifest_scanner.py`, `tools/permission_diff.py`, `tools/sandbox.py`, `data/samples/*`, `tests/test_scanner.py` | the custom tools, Red-Team agent, test packages |
| C, knowledge | `agents/threat_analyst.py`, `rag/ingest.py`, `tools/rag.py`, `tools/osv.py`, `data/corpus/*`, `eval/run_eval.py` | vectorized RAG, OSV tool, AuditFindings SOM, quantitative evaluation |

Everybody writes code (the guidelines require it) and everybody writes the report sections for what they built.

## Timeline

| Week | Member A | Member B | Member C |
|---|---|---|---|
| 1 (Nov 5 to 11) | Push repo to GitHub, protect `main`, everyone runs offline demo. Run one ONLINE audit with a real Gemini key and fix integration issues. Freeze contracts. | Fix the permission-diff bug noted in the file. Add 3 scanner rules with tests. | Download corpus (SOURCES.md), build Chroma, test `search_kb` on 5 queries. Confirm OSV returns CVEs for `vuln_deps_pdf`. |
| 2 (Nov 12 to 18) | Report prompt and SOM, tune `policy_verdict`, polish REPL output for the demo (state diffs, history). | Inspector and Red-Team prompts. Sandbox canaries. Run each attack 5 times and log obedience rate. | Analyst prompts, findings SOM quality, OWASP metadata tags, retrieval hit-rate check. |
| 3 (Nov 19 to 25) | Error handling pass, clean-clone reproducibility test of README, Mermaid diagram. Feature freeze Nov 25. | Grow samples to about 20 with labels (mix of benign, poisoned, invisible, overbroad, vulnerable deps, rug pulls). Optional: "defended" sandbox run on patched manifest. | Eval: LLM vs offline baseline on all samples, accuracy, block recall, false-block rate. Save tables. |
| 4 (Nov 26 to Dec 2) | Report sections 1, 2, 3, 7, 11. Record 4-minute video. | Report sections 4 (their nodes), 5 (their tools), 8. | Report sections 5 (RAG, OSV), 6, 10. |
| Buffer (Dec 3 to 5) | Everyone: section 9 (prompting, own agents) and 12 (contributions), final read, ZIP, submit. | | |

A 20-minute weekly sync counts inside the 4 hours. Agenda: what merged, what is blocked, does `pytest` pass on `main`.

## Git workflow

Branches are `a/<topic>`, `b/<topic>`, `c/<topic>`. Small PRs, one reviewer from the team, `pytest -q` passes before merge. Never commit `.env`.

## Gemini free-tier budget

One online audit costs roughly 8 to 15 LLM calls (agent turns, two SOM calls, sandbox calls). Develop in OFFLINE mode, test one sample online, and run the full online eval only once or twice. If you hit rate limits, set `AGENTGUARD_LLM_MODEL` to a lighter model or add a short sleep between eval samples.

## Demo video script (max 4 minutes)

1. `audit benign_weather.json`: show message types, tool calls, ToolMessages, and the path that SKIPS the red team.
2. `audit poisoned_math.json`: same thread; show the conditional edge firing, sandbox results, AuditFindings SOM, block verdict and patched manifest.
3. `thread demo`, `audit rugpull_calc_v1.json`, then `audit rugpull_calc_v2.json`: checkpoint continuity detects the rug pull.
4. `history`: show checkpoints and state progression.
