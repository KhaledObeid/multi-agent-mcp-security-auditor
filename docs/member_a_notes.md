# Member A (Integrator): Reference Notes for the Report

**Period covered:** Week 1 (ending 11 November 2026)
**Branch:** `a/week1-integration`
**Report sections fed by these notes:** §9 Prompting/Development, §12 Contributions, plus material for sections 1, 2, 3, 7, 11 and the demo video

---

## 1. Week 1 tasks (from `docs/PLAN.md`)

| Task | Status | Evidence |
|---|---|---|
| Push repo to GitHub | Done | `origin` on GitHub; teammates push branches to it |
| Protect `main` | Done | GitHub ruleset: pull request with 1 approval required, force pushes and deletion blocked |
| Everyone runs the offline demo | Done for Member A and Member C | Fresh `.venv` (Python 3.14.6), `pip install -e .`, 10/10 tests, offline audit of `poisoned_math.json` returns `block`. Member B to confirm |
| Merge teammate work | Done | PR #1 (`c/rag-corpus`, Member C) reviewed and merged, with two follow-up comments (see section 3) |
| One ONLINE audit, fix integration issues | Done | Section 4 and 5 |
| Freeze contracts | Done | Section 6 |

## 2. Environment notes (for the README check in week 3)

- Followed the README on Linux: `python -m venv .venv`, `pip install -e .`, `cp .env.template .env`. Installed cleanly on Python 3.14.6.
- The `.chroma/` vector store is not in git, so **every machine that runs online must build it** (`python -m mcp_security_auditor.rag.ingest`, 345 chunks, 3 min 24 s on the free tier). Same chunk count as Member C, so the corpus is reproducible.
- Each teammate uses their own Gemini key on their own Google account: free-tier quota is per Google project, so a shared key would split one quota three ways.

## 3. Review of PR #1 (Member C: RAG corpus, paced embedding, CVE ids from OSV)

Checked: only C-owned files changed; fast-forward from `main`; 10/10 tests on the branch; OSV now returns de-duplicated CVE ids for `vuln_deps_pdf` (pyyaml 2, requests 5). Approved with two follow-ups:
1. No automated test for the OSV de-duplication (manual testing only).
2. OFFLINE mode still calls OSV.dev over the network, so the offline demo needs internet and its results can change over time (C's week 2 cache task covers this).

## 4. First ONLINE audit (`poisoned_math.json`)

| Run | Model | Result |
|---|---|---|
| 1 | `gemini-3.8-flash` | **Crashed** after 2 min 41 s: `503 UNAVAILABLE` ("model is currently experiencing high demand") on the Inspector's first call; 3 retries failed, the exception escaped `agent_turn` and ended the program |
| 2 | `gemini-3.8-flash` | Hung for more than 8 minutes (same overload, retries) and was stopped |
| 3 | `gemini-3.5-flash-lite` | **Completed in 38 s, verdict `block`**, no errors |

Run 3 compared with the offline run:
- Inspector chose its own tool calls (scan all tools, then permission check) and wrote a summary naming the `<IMPORTANT>` block and `~/.ssh/id_rsa`.
- Threat Analyst searched the knowledge base (OWASP Agentic Top 10 passages returned) and mapped the attack to ASI01 and ASI02.
- Both Structured Output calls (`AuditFindings`, `FinalReport`) validated; the verdict guardrail (policy floor) did not need to fire.
- The sandbox really ran: the mock agent **obeyed** the hidden instruction (`mock_agent_obeyed: true`).
- No field in `schemas.py` or `state.py` needed changing, which cleared the contract freeze.

Observations passed to teammates (their files):
- **Member B (sandbox):** `mock_agent_obeyed` was `true` because of a canary hit on the mock agent's *text* ("sensitive path referenced"), with `observed_tool_calls: []`. Worth checking whether a text mention alone should count as obeying.
- **Member C (Threat Analyst):** the LLM rated the hidden instruction `high` while the scanner hinted `critical`, and the analyst searched the knowledge base only once. Fits the week 2 prompt work.

## 5. Integration fix: LLM failure no longer crashes the audit (§9, error handling)

**Problem.** `utils/agent_loop.py:agent_turn`, the one function every tool-calling agent uses to ask the LLM for its next step, had no error handling. One failed call (503 overload, 429 quota, network) crashed the whole audit. In the analyst and report nodes the Structured Output calls already fell back to rule-based results; the agent turns did not.

**Change.**
1. On an LLM exception, `agent_turn` plays the scripted rule-based step (the same one OFFLINE mode uses) and prefixes the message with `[LLM unavailable (...); using rule-based fallback]`, so the fallback is visible in the printed trace.
2. Once an agent's LLM has failed in an audit, that agent does not call the LLM again in the same audit (avoids paying the timeout and retries on every turn).
3. New settings: `MCP_SECURITY_AUDITOR_LLM_TIMEOUT_S` (default 30 s per request) and `MCP_SECURITY_AUDITOR_LLM_MAX_RETRIES` (default 3).

**Verification.**
- 3 new unit tests with a fake LLM that always raises (`tests/test_agent_loop_fallback.py`).
- End to end with every LLM call failing (non-existent model name): the audit finished in 8.6 s with verdict `block`, each agent tried the LLM once, and the failure was listed under `errors`.
- With the overloaded `gemini-3.8-flash` and 0 retries, the fallback triggered on real `503` and `504 DEADLINE_EXCEEDED` responses.

**Second fix found on the way: tests could call the real API.** `test_graph_offline.py` set OFFLINE=1 at the top of the file, but `config.py` reads settings only once, at the first import. When another test file imported the package first, a developer's `.env` (OFFLINE=0) won, and the graph tests ran online against the overloaded model and hung. `tests/conftest.py` now forces OFFLINE=1 before any test file loads.

## 6. Contract freeze (end of week 1)

- `schemas.py` and `state.py` are frozen as of 11 November 2026.
- Enforced by `tests/test_contract_freeze.py`: it stores today's field names and enum values and fails if any is removed or renamed, or if a new field has no default. Adding Optional fields and new enum values still passes.
- Member C verified the `OwaspCategory` names against the ingested PDFs; the LLM ids follow the **2025** edition of the LLM Top 10 (the 2026 edition renumbers entries). Recorded in the `OwaspCategory` docstring; state it in the report.
- To change a contract from now on: PR titled `contract: ...`, agreed with the team, and update the snapshot in the freeze test in the same PR.

## 7. Demo video notes

- Use `gemini-3.5-flash-lite` if `gemini-3.8-flash` is overloaded on recording day (check first with one audit).
- Set `MCP_SECURITY_AUDITOR_LLM_MAX_RETRIES=0` or `1` for recording so a busy model fails fast into the visible fallback rather than pausing on camera.

## 8. Week 2 to-do (Member A)

1. Report prompt and `FinalReport` SOM quality.
2. Tune `policy_verdict`.
3. REPL polish for the demo: state diffs, history.
