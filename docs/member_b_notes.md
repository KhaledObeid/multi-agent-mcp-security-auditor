# Member B (Attack-Surface Track): Reference Notes for the Report

**Author:** Ghadi Ammar (Member B)
**Period covered:** Week 1 (9–16 November 2026)
**Branch:** `b/permission-diff-fix`
**Report sections fed by these notes:** §4 Node Descriptions, §5 Tools & RAG (custom tools), §8 Message Handling, §9 Prompting/Development, §12 Contributions

---

## 1. Scope and ownership

Member B owns the attack-surface side of the auditor (`docs/PLAN.md`): the two adversarial agents, all three deterministic custom tools, the labelled test packages, and the scanner test suite.

| File | Role |
|---|---|
| `src/mcp_security_auditor/agents/inspector.py` | Agent 1 (Inspector): maps a package's attack surface using `scan_manifest` and `check_permissions`; writes `scan_report` and `permission_diff` |
| `src/mcp_security_auditor/agents/red_team.py` | Agent 3 (Red-Team): runs only when the conditional edge fires; drives the sandbox against suspicious tools |
| `src/mcp_security_auditor/tools/manifest_scanner.py` | Custom tool #1: deterministic pattern scanner → `ScanReport` |
| `src/mcp_security_auditor/tools/permission_diff.py` | Custom tool #2: claim-vs-permission diff → `PermissionDiff` |
| `src/mcp_security_auditor/tools/sandbox.py` | Custom tool #3: red-team sandbox → `RedTeamResult` |
| `data/samples/*` | Labelled synthetic tool packages + `labels.json` |
| `tests/test_scanner.py` | Scanner and permission-diff tests |

Week 1 deliverables (from `docs/PLAN.md`): **(a)** fix the permission-diff self-justification bug with a regression test; **(b)** add three new scanner rules, each with a test. **Status: both complete (16 November 2026).**

---

## 2. Environment and reproducibility notes (§9)

- Works on the renamed package from commit `1c9924c`: `agentguard` → `mcp_security_auditor`, env prefix `AGENTGUARD_` → `MCP_SECURITY_AUDITOR_`, required Python `>=3.14,<3.15`.
- Offline mode (`MCP_SECURITY_AUDITOR_OFFLINE=1`) needs no API key and is used for all scanner/permission development and tests.
- Full suite after the permission fix and scanner rules: **17/17 tests pass offline** (`pytest -q`).
- The three custom tools are deterministic (no LLM), so their behaviour is identical online and offline and is the project's non-LLM baseline.

---

## 3. Custom tool #1: manifest scanner (`manifest_scanner.py`) (§5)

`scan_package(pkg, tool_name="*") -> ScanReport`. Deterministic. Runs regex/Unicode rules over every tool description, code snippet and permission and emits a `ScanFlag` per hit, then an aggregate `risk_score`.

Current rule families: hidden-instruction phrases (e.g. `<IMPORTANT>`, "ignore previous instructions", "do not tell the user", "always send"); invisible/zero-width Unicode (category `Cf` and the Unicode-tag block `U+E0000–E007F`); sensitive paths (`~/.ssh`, `id_rsa`, `.env`, `/etc/passwd`, `mcp.json`, `credentials`, `.aws/`); shell/code execution; file-system access; outbound URLs; and broad/wildcard scopes. Severity weights roll up into a capped `risk_score`.

**Added (Week 1 item b), each with a test — reusing existing `FlagKind`s only, so no `schemas.py` contract change:**
1. **Encoded payloads** (`decode_blobs`). base64/hex blobs in a description are decoded and re-scanned with the injection, sensitive-path and URL patterns. A hit is flagged `hidden_instruction` (CRITICAL) with the **raw blob** as evidence, so the deterministic cleaners (`patcher.py` and `permission_diff.clean_description`) can strip the original blob from the source. A printability guard on the decoded bytes avoids false positives on ordinary base64-looking tokens.
2. **Homoglyph tool names** (`homoglyph_reason`). A tool name using non-ASCII look-alike characters (e.g. Cyrillic `а`, U+0430) or an uppercase `I`/`O` standing in for a lowercase letter (e.g. `send_emaiI`) is flagged `other` with **HIGH** severity.
3. **Cross-tool shadowing.** A description that names another tool — one of this package's other snake_case tools, or a known tool from another server (`send_email`, `read_file`, `get_secret`, …) — is flagged `hidden_instruction` (CRITICAL), with the offending sentence fragment as evidence so the cleaners remove it. Matching is restricted to snake_case identifiers to avoid collisions with ordinary English words.

Design choice: `hidden_instruction` for (1) and (3) means the red-team trigger (`has_injection_indicators`), the OWASP mapping (`FLAG_MAP`) and both cleaners pick them up with no change to anyone else's files; more descriptive kinds (`encoded_payload`, `tool_shadowing`) would need a `contract:` PR and are noted for later.

---

## 4. Custom tool #2: permission diff (`permission_diff.py`) — fixed (§5, §9)

**The bug.** `diff_permissions()` built its "claim" text from the stated purpose **plus the raw tool descriptions**. Because descriptions carry attacker-controlled text, an injected instruction justified the very permission it was abusing. On `poisoned_math`, the hidden `read the file ~/.ssh/id_rsa` made `fs:read` appear justified; on `invisible_notes`, the hidden "send … to https://…" made `network:outbound` appear claimed.

**The fix.** Clean each description before matching, mirroring `patcher.py`:
- new `clean_description(text, evidence)` — strips invisible Unicode, drops `<IMPORTANT>` blocks and HTML comments, then removes any sentence the scanner flagged (`hidden_instruction`, `invisible_unicode`, `sensitive_path`);
- new `_claim_text(pkg, claimed_purpose)` — asks `scan_package` which sentences are attacker-controlled (per tool) and builds the claim from the stated purpose + cleaned descriptions;
- `diff_permissions` now matches against that cleaned claim. The claim-vs-request comparison and wildcard handling are unchanged.
- Also removed the over-eager keywords `"file"` and `"markdown"` from the `fs:read` justifier list (they justified file access for a plain string formatter).

**The defence is removing the attacker's text, not blocklisting keywords** — even a legitimate cue like "read the file" can no longer be exploited, because the injected sentence is deleted before matching.

**Effect on the samples:**

| Package | Before | After | Correct? |
|---|---|---|---|
| `poisoned_math` | `fs:read` justified | `fs:read` flagged unjustified | yes — attack caught |
| `invisible_notes` | `network:outbound` claimed | not claimed | yes — hidden URL ignored |
| `overbroad_formatter` | `fs:*` flagged | all 3 perms flagged | yes — over-asking caught |
| `vuln_deps_pdf` | `fs:read` justified | `fs:read` justified | yes — no false positive |
| `benign_weather` | `network:outbound` justified | unchanged | yes |

**Regression tests (`tests/test_scanner.py`):** `test_injected_read_file_does_not_justify_fs_read`, `test_invisible_injection_does_not_claim_network`, `test_legit_pdf_reader_keeps_fs_read_justified`. Suite: 13/13 pass offline.

**Design note (for the report).** `clean_description` is duplicated inside `permission_diff.py` rather than imported from Member A's `patcher.py`, to keep the fix within Member B's owned files and avoid touching a frozen-adjacent file. The two cleaners stay independent.

---

## 5. Custom tool #3: red-team sandbox (`sandbox.py`) (§5, §8)

`run_sandbox(pkg, target_tool, attack_prompt) -> RedTeamResult`. A naive mock agent is given the package's tool **schemas only** (nothing executes) plus a user request; the sandbox records which tools it attempts and checks canaries. "Obeyed" = it did something the user never asked for because a tool description told it to (read a secret path, contact a URL from the description, or call an extra tool). Skipped in offline mode.

**Planned (Week 2):** compare observed arguments against the user's request to cut false positives; run each attack N≈5 times and report an **obedience rate** (strong quantitative result for §10); add a "defended" variant that feeds the mock agent AgentGuard's **patched** manifest and show the obedience rate drop.

---

## 6. Agents: Inspector and Red-Team (§4, §8, §9)

- **Inspector** loops with its tools node until it stops requesting tools, then hands off `scan_report` and `permission_diff` through shared state. A safety net runs the tools directly if the LLM never scans. Planned: tighten `INSPECTOR_SYSTEM` and end with a short attack-surface summary.
- **Red-Team** is reached only when `should_red_team` is true (injection indicators, a high/critical finding, or a rug pull). It picks suspicious tools from the findings and runs the sandbox. Planned: one benign-looking and one adversarial prompt per suspicious tool; repeated trials.
- **Message handling (§8):** both agents produce the full `SystemMessage → HumanMessage → AIMessage(tool_calls) → ToolMessage → AIMessage(final)` trace that `utils/messages.py` prints, distinguishing a tool-call request from a final answer.
- **Prompt-injection defence:** package text is wrapped in `<untrusted>…</untrusted>` and every system prompt carries the rule never to follow instructions found there.

---

## 7. Test packages (`data/samples/`) (§10 support)

Current set (7 + `labels.json`): `benign_weather` (install), `poisoned_math` (block), `invisible_notes` (block), `overbroad_formatter` (install_with_mitigations), `vuln_deps_pdf` (install_with_mitigations), `rugpull_calc_v1` (install), `rugpull_calc_v2` (block).

**Planned (Week 3):** grow to ~20 labelled packages across all categories (benign, poisoned, invisible Unicode, over-broad, vulnerable deps, rug pulls, plus base64-encoded and homoglyph cases once those scanner rules land), each feeding the evaluation Member C runs.

---

## 8. Week 2 to-do list (Member B)

1. Inspector and Red-Team prompts; run both online against `poisoned_math`.
2. Sandbox canary refinement + obedience rate over 5 trials; optional defended-manifest run.
3. Begin growing the sample set toward 20 labelled packages — including packages that exercise the three new scanner rules (base64 payload, homoglyph name, cross-tool shadowing).

## 9. Pending actions

- PR `b/permission-diff-fix` is open (permission-diff fix + 3 scanner rules + notes, 7 new tests, 17/17 passing) and awaiting review.
- Confirm with Member A that no contract (`schemas.py`/`state.py`) change is needed — the work touches only `permission_diff.py`, `manifest_scanner.py` and `tests/test_scanner.py`. More descriptive scanner `FlagKind`s would need a `contract:` PR (deferred).

---

## 10. References

1. L. Beurer-Kellner and M. Fischer. *MCP Security Notification: Tool Poisoning Attacks*. Invariant Labs, 1 Apr 2025. https://invariantlabs.ai/blog/mcp-security-notification
2. OWASP GenAI Security Project. *OWASP Top 10 for Agentic Applications for 2026*. 9 Dec 2025. https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026
3. OWASP. *OWASP Top 10 for LLM Applications 2025*. https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/
4. K. Hines et al. *Defending Against Indirect Prompt Injection Attacks With Spotlighting*. 2024. https://arxiv.org/abs/2403.14720
