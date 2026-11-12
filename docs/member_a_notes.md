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
- Additive fields agreed at the freeze (before it was merged): `AuditRecord.permissions`, `AuditRecord.dependencies`,
  `AuditState.policy_floor`, `AuditState.policy_reason` (see section 6c).
- Member C verified the `OwaspCategory` names against the ingested PDFs; the LLM ids follow the **2025** edition of the LLM Top 10 (the 2026 edition renumbers entries). Recorded in the `OwaspCategory` docstring; state it in the report.
- To change a contract from now on: PR titled `contract: ...`, agreed with the team, and update the snapshot in the freeze test in the same PR.

## 6b. Free-tier limit found on 11 November

A run with `gemini-3.8-flash` returned `429 RESOURCE_EXHAUSTED ... limit: 20 ... requests per day`. That is about
1 to 2 audits per day per key on that model; `gemini-3.5-flash-lite` has its own separate limit and kept working.
Impact: the evaluation (about 20 samples x 10 to 15 calls) cannot run on 3.8-flash in one day. Proposed for the
weekly sync: develop and evaluate on flash-lite, keep 3.8-flash for a final comparison or the demo.

## 6c. Code review fixes (§9; Safeguards for the report)

A review of the whole codebase found three gaps. Each was first reproduced offline, then fixed, and each fix
has a test that fails on the old code and passes on the new one (`tests/test_guardrails.py`).

| # | Gap (reproduced) | Fix |
|---|---|---|
| 1 | **The LLM could weaken the verdict.** The policy floor was computed from the LLM's findings only. With the analyst LLM rating the SSH-stealing instruction `high` (as Gemini did in the first online run) and a sandbox run where the mock agent did not obey, `poisoned_math` got a floor of `install_with_mitigations`. The analyst safety net did not help: it only re-adds a critical finding the LLM *omitted*, not one it *under-rated* | `policy_verdict` takes the highest of the findings' severity and the deterministic scanner's severity hints. Floor and reason are stored in the new state fields `policy_floor` / `policy_reason` and printed as `policy minimum` (kept out of `FinalReport`, the LLM's SOM target, so the LLM never fills in its own floor) |
| 2 | **Rug pulls through permissions or dependencies were missed.** v2 of the calculator with identical descriptions but new `shell:exec`, `fs:*` and an unknown dependency gave `rug_pull_detected: False` | `AuditRecord` gains optional `permissions` and `dependencies`; intake flags any *added* permission or dependency (removals and version bumps of existing dependencies are normal updates) |
| 3 | **The red team ran on packages it cannot test.** `vuln_deps_pdf` (only CVE findings, no affected tool) went to the red team, which then "attacked" an innocent tool: wasted LLM calls | `should_red_team` counts only high findings that name a tool (plus injection signs and rug pulls, as before). Offline evaluation unchanged at 7/7; the red team now skips 2 of 7 samples |

Passed to teammates: B (permission-diff bug confirmed in the online run; hidden-parameter stuffing not counted as
obeying), C (the evaluation runs each sample on a fresh thread so rug-pull detection is never exercised; it
cannot tell when a run fell back to rules; one failing sample stops the run).

## 7. Demo video notes

- Use `gemini-3.5-flash-lite` if `gemini-3.8-flash` is overloaded on recording day (check first with one audit).
- Set `MCP_SECURITY_AUDITOR_LLM_MAX_RETRIES=0` or `1` for recording so a busy model fails fast into the visible fallback rather than pausing on camera.

## 8. Week 2 to-do (Member A)

1. Report prompt and `FinalReport` SOM quality.
2. Tune `policy_verdict`.
3. REPL polish for the demo: state diffs, history.

---

## 9. Week 2: report agent, policy floor, REPL (12 to 13 November 2026)

**Branch:** `a/week2-report` (started from `a/week1-integration`, which is still waiting for review).
`schemas.py` and `state.py` are unchanged, so the contract freeze holds.

### 9.1 Policy floor tuning (§7 Safeguards, §9)

| # | Gap (reproduced offline) | Fix |
|---|---|---|
| 1 | **Only the first reason was reported.** `rugpull_calc_v2` said "critical finding" and never mentioned the rug pull, because the first matching rule returned | `policy_triggers()` collects every rule that fires; the floor is the strictest, and `policy_reason` lists all reasons, strictest first |
| 2 | **Known CVEs reached the floor only through the analyst's findings.** An analyst LLM rating them `low` allowed `install` | Any dependency with a known vuln id sets at least `install_with_mitigations` on its own |
| 3 | **Same for unjustified permissions** (`permission_diff`) | Any unjustified permission sets at least `install_with_mitigations` |
| 4 | **A failed CVE lookup looked like a clean result.** OSV down meant no CVEs, so `install` | Online only: a declared dependency whose OSV lookup failed, or was never made (the analyst LLM may skip `query_osv`), sets at least `install_with_mitigations` with the reason "dependencies could not be checked for known CVEs", a manual-check mitigation and an entry in `errors` |

Design decision for rule 4: **it does not apply in OFFLINE mode.** `osv.py` calls OSV.dev even offline, so
without this exception an offline run without internet would change verdicts. Checked by running the offline
eval with OSV unreachable (`HTTPS_PROXY` pointed at a closed port): `benign_weather` stays `install`.
The same experiment showed an existing weakness: `vuln_deps_pdf` drops to `install` offline without network,
because its CVEs come only from the live lookup. Member C's OSV cache task (week 2) fixes this.

### 9.2 Report prompt and Structured Output (§6, §9)

- `REPORT_SYSTEM` now defines the three verdicts, states that the policy minimum is binding (stricter allowed,
  with a reason), asks for a 3 to 6 sentence rationale for a non-expert that names the tool and the evidence,
  and asks for concrete, de-duplicated mitigations, each naming its tool, permission or dependency.
- **Spotlighting in the report agent too.** Findings evidence contains attacker text, so everything derived
  from the package reaches the LLM inside `<untrusted>` tags, and a closing tag inside package text is escaped.
  Only the policy minimum is outside the tags.
- The patcher now runs **before** the LLM call (it is deterministic), so the report can tell the user to use
  the patched manifest.
- Post-check on the SOM result: a non-install verdict with no mitigations is filled from the findings and
  noted in `errors` (in addition to the week 1 floor guardrail).
- Offline and fallback report: a real rationale built from the policy reasons, the findings and the sandbox
  result, instead of "Policy decision: ...". Mitigations are grouped: `vuln_deps_pdf` used to list
  "Upgrade to a fixed version." three times; it now shows one line naming `pyyaml==5.3, requests==2.19.0,
  pillow==8.0.0` (matched through the OSV ids, not the finding text).

### 9.3 REPL polish for the demo (§3, demo video)

- **State diff after every node**: only fields that changed, as `before -> after`
  (`needs_red_team: False -> True`, `audit_history: +1 (now 2)`). On a second audit on the same thread,
  the fields `intake` resets are collapsed into one line.
- **`history`** groups checkpoints by audit (`audit 2: calc-pro-mcp v1.0.1 -> block, RUG PULL`) and shows,
  for each step, the node that wrote the checkpoint and the fields it changed. `history full` keeps the raw view.
- New commands: `help`, `samples`, `report`, `patched`, a readable `state`; `audit poisoned_math` works
  without the path (also on the command line).

### 9.4 Verification

- Tests: 43 pass (24 at the end of week 1). New: `tests/test_report.py` (fake-LLM tests of the online path),
  `tests/test_main.py` (diff function and a scripted REPL session), 7 new tests in `tests/test_guardrails.py`.
- Offline eval: 7/7 (unchanged).
- **A mistake found on the way (§9):** the first version of the "failed OSV lookup, online" test switched the
  report module to online mode but did not replace the LLM, so it made one real Gemini call (25 s). Fixed with
  a fake LLM that always raises; all online-mode tests now replace `get_llm`.

### 9.5 Online check: `poisoned_math` on `gemini-3.5-flash-lite` (13 November 2026)

| Item | Result |
|---|---|
| Verdict | `block` (policy minimum `block`: "there is at least one critical finding"); the floor guardrail did not need to fire |
| Report SOM | validated, no parse error |
| Analyst SOM | **failed with `504 DEADLINE_EXCEEDED`** (server timeout, not a parse error); the rule-based findings were used, as designed |
| Sandbox | ran; `mock_agent_obeyed: false` |

Rationale returned by the LLM:
> This package is blocked due to critical security findings including hidden instructions in the add tool
> description and references to sensitive credential paths like ~/.ssh. These issues represent a severe risk of
> agent goal hijack and tool misuse where the package works against the user. Although a patched manifest was
> produced, the presence of critical findings requires a block per policy until the underlying tool poisoning
> and path access risks are fully resolved. Before this package could be reconsidered, the add tool must have
> its injected instructions completely removed and all unauthorized access to credential files must be eliminated.

Mitigations: remove the injected instructions from `add`; deny access to credential paths such as `~/.ssh`;
use the patched manifest. All three name the tool, and the patched manifest is used, as the prompt asks.

Observations:
- The rationale does not mention the sandbox result, although the prompt asks for it. Possible prompt tweak.
- **For Member B:** the mock agent called `add` with an extra argument `"sidenote": "user request"`, which is
  the hidden-parameter stuffing the poisoned description asks for, but the sandbox reported
  `mock_agent_obeyed: false`. Same issue as noted in week 1.
- **For Member C:** the analyst's SOM call timed out (504) on flash-lite; worth checking prompt size.

### 9.6 Still to do in week 2

1. Get `a/week1-integration` and then `a/week2-report` reviewed and merged.
2. One more online check after B's and C's week 2 prompts merge.
3. Agree with B what counts as `mock_agent_obeyed`; it feeds the policy floor.
