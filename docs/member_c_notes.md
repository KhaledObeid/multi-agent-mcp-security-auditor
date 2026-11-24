# Member C (Knowledge Track): Reference Notes for the Report

**Author:** Joya Saade (Member C)
**Period covered:** Week 1 (9–10 November 2026), Week 2 (12–17 November 2026) and Week 3 (22–24 November 2026)
**Branches:** `c/rag-corpus` (Week 1, merged as PR #1); `c/week2-retrieval` (Week 2, merged as PR #3); `c/week3-eval` (Week 3, merged as PR #5); `c/week3-results` (Week 3, 24 November)
**Report sections fed by these notes:** §5 Tools & RAG, §6 Structured Output, §9 Prompting/Development, §10 Results

---

## 1. Scope and ownership

Member C owns the knowledge side of the auditor (`docs/PLAN.md`):

| File | Role |
|---|---|
| `src/mcp_security_auditor/agents/threat_analyst.py` | Agent 2 (Threat Analyst): maps Inspector flags to OWASP categories; produces `AuditFindings` via Structured Output Mode |
| `src/mcp_security_auditor/rag/ingest.py` | Builds the vector store (load → chunk → embed → store) |
| `src/mcp_security_auditor/tools/rag.py` | `search_kb`: semantic retrieval over the security corpus (mandatory RAG tool) |
| `src/mcp_security_auditor/tools/osv.py` | `query_osv_one`: dependency vulnerability lookup on OSV.dev |
| `data/corpus/*` | The knowledge base documents |
| `eval/run_eval.py` | Quantitative evaluation (LLM system vs. rule-based baseline) |

Week 1 deliverables (from `docs/PLAN.md`): download the corpus and build Chroma; test `search_kb` on 5 queries; confirm OSV returns CVEs for the `vuln_deps_pdf` sample. **All three were completed on 10 November 2026.**

---

## 2. Environment and reproducibility notes (§9, and for Member A's README check)

- On 10 November the repository was renamed in commit `1c9924c` ("corrected naming error"): package `agentguard` → `mcp_security_auditor`; environment-variable prefix `AGENTGUARD_` → `MCP_SECURITY_AUDITOR_`; required Python raised to **3.14** (`>=3.14,<3.15`). The Threat Analyst logic was unchanged by this commit.
- Environment: conda env `mcp-security-auditor`, Python 3.14.10, Windows. All dependencies have Windows wheels for Python 3.14 (verified by resolving `requirements.txt` for `win_amd64` / CPython 3.14).
- Common pitfall: running `pip install -e .` in the `(base)` environment (Python 3.10) fails with "requires a different Python"; the project environment must be activated first.
- The Gemini API key is stored in `.env`, which is listed in `.gitignore` and is never committed.
- Embedding model: `models/gemini-embedding-001`, producing 3072-dimensional vectors (verified by embedding a test string).
- Offline mode (`MCP_SECURITY_AUDITOR_OFFLINE=1`): 10/10 tests pass and the offline audit of `poisoned_math.json` returns `block`.
- **Week 2 (15 November):** 53/53 tests pass, and the offline evaluation scores 7/7, also on a machine without internet access (OSV cache, §5.2).
- **17 November:** 59/59 tests pass. Online runs used `gemini-3.5-flash-lite` (free tier: 15 requests/minute, 500/day), selected for the session with `set MCP_SECURITY_AUDITOR_LLM_MODEL=gemini-3.5-flash-lite`; `gemini-3.8-flash` allows only 20 requests/day (Member A's notes, §6b). A full 7-sample run used about 100 requests and took 10–12 minutes.

---

## 3. Knowledge-base corpus (§5)

### 3.1 Documents

| File in `data/corpus/` | Source | Pages | Chunks* |
|---|---|---|---|
| `OWASP-Agentic-Top10-2026.pdf` | OWASP GenAI Security Project, *Top 10 for Agentic Applications for 2026* (9 Dec 2025), CC BY-SA 4.0 | 57 | 153 |
| `OWASP-LLM-Top10-2025.pdf` | OWASP, *Top 10 for LLM Applications 2025* | 45 | 139 |
| `MCP-Security-Best-Practices.pdf` | Model Context Protocol specification (version 2025-11-25), *Security Best Practices*, saved from the web page | 20 | 43 |
| `mcp_incidents_notes.md` | Team-written paraphrase of Beurer-Kellner & Fischer (Invariant Labs, 1 Apr 2025), approved by Member C | — | 5 |
| `seed_notes.md` | Team-written starter notes (ASI01–ASI06, LLM01, LLM06) | — | 5 |
| **Total** | | | **345** |

\*Chunking: `RecursiveCharacterTextSplitter`, chunk size 900 characters, overlap 150. All three PDFs contain extractable text (no scanned pages). `SOURCES.md` is excluded from ingestion by design.

### 3.2 Decisions

1. **LLM Top 10 edition: 2025, not 2026.** The 2026 edition (published August 2026) renumbers entries; for example, Excessive Agency moves from LLM06 to LLM03 and Supply Chain becomes LLM04 (Cloud Security Alliance research note). The team contract (`schemas.py`) uses the 2025 numbering, so the 2025 edition was ingested and should be stated in the report.
2. **Category names verified against the PDFs.** ASI01–ASI10 in `schemas.py` match the OWASP Agentic 2026 document (differences limited to "&" vs. "and" and the suffix "(RCE)" on ASI05). LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Supply Chain and LLM06 Excessive Agency match the 2025 edition. **No contract change is needed** (to be communicated to Member A before the freeze).
3. **Blog content is paraphrased, not copied.** Per `SOURCES.md`, the Invariant Labs article is stored as summary notes in our own words, with the citation at the top. Each section begins with its OWASP identifier and is kept under one chunk in length, so that every chunk of this file carries a category label.

---

## 4. Code change 1: paced embedding in `rag/ingest.py` (§5, §9)

**Problem.** The first build failed with `429 RESOURCE_EXHAUSTED`. The Gemini free tier allows **100 embedding requests per minute** for `gemini-embedding-001`, and each chunk counts as one request. The original `build()` called `Chroma.from_documents` on all 345 chunks at once.

**Change.** `build()` now creates the Chroma store empty, then adds chunks in groups of `EMBED_BATCH = 90`. After each group it waits only for the remainder of a 62-second window (`EMBED_PAUSE_S`), using `time.monotonic()`, so the total time is as short as the quota allows. Progress is printed per group.

**Verification.** Before deployment, the change was tested against a simulated embedding service that rejects more than 100 embeddings per rolling minute, using the real 345-chunk corpus: all 345 chunks were stored, the limit was never exceeded, and the simulated build time was about 3.5 minutes. The offline test suite remained 10/10. On the real API, the build then completed: *"Indexed 345 chunks into …\.chroma"*.

**Operational constraint.** The free tier also enforces a daily embedding quota. A full rebuild consumes 345 requests, so chunk-size experiments in Week 2 must be planned rather than run ad hoc. The current limits for the key are shown at ai.dev/rate-limit.

---

## 5. Retrieval test: 5 queries (§10)

Method: `search_kb(query, k=4)` (plain similarity search, as in the skeleton). Relevance was judged manually from the content of each returned passage.

| # | Query | Top-4 results (source · labels) | Hit within top 4 |
|---|---|---|---|
| 1 | tool poisoning: hidden instructions in a tool description | incidents notes · ASI02,LLM02 · incidents notes · ASI02,ASI04 · incidents notes · ASI01,LLM01 · incidents notes · ASI01,ASI02,ASI04 | Yes (all 4 relevant) |
| 2 | tool definition changed after the user approved it (rug pull) | incidents notes · ASI01,LLM01 · incidents notes · ASI02,ASI04 (contains the rug-pull section) · OWASP Agentic · ASI03,ASI04,ASI05 · incidents notes · ASI01,ASI02 | Yes (rank 2) |
| 3 | tool can run shell commands or execute arbitrary code | OWASP Agentic · (no label) · seed notes · ASI04,ASI05 · MCP best practices · (no label) · OWASP Agentic · LLM01,LLM05 | Yes (all 4 relevant) |
| 4 | text formatter requests wildcard file system access it does not need | seed notes · ASI02,ASI03 · MCP best practices · (no label) · OWASP LLM 2025 · (no label) · MCP best practices · (no label) | Yes (ranks 1 and 3) |
| 5 | invisible Unicode characters hide injected instructions from human reviewers | seed notes · ASI06,LLM01 · OWASP LLM 2025 · (no label) · OWASP LLM 2025 · (no label) · incidents notes · ASI02,ASI04 | Yes (ranks 1 and 2) |

**Result:** hit@4 = **5/5** (judged by topic relevance).

### Weaknesses observed (to address in Week 2)

- **W1: Incomplete and sometimes misleading labels.** Only 92 of 345 chunks carry an OWASP id, because a chunk is labelled only if the id literally appears in it. Query 3, rank 1 is ASI05 text with no label; rank 4 is ASI05 text labelled LLM01, LLM05 because of a cross-reference. *Planned fix:* assign each chunk the id of the section heading it falls under.
- **W2: Short notes outrank primary sources.** Several hits came from `seed_notes.md` or the incident notes rather than the official OWASP documents; all four results for query 1 came from one file. *Planned fix:* decide whether to remove or reduce `seed_notes.md` (`SOURCES.md` describes it as a starter to replace) and use MMR retrieval for diversity.
- **W3: Some irrelevant passages.** For example, query 4 rank 4 (token theft) and query 5 rank 3 (model poisoning).

### 5.1 Week 2: changes and automated evaluation (14 November)

**Changes** (branch `c/week2-retrieval`):
- **W1 fixed.** `rag/ingest.py` now tags each chunk with the OWASP chapter it belongs to: a page holding exactly one heading of its document's own family (`ASI05: …`, `LLM06:2025 …`) opens a chapter, and the following pages inherit it; contents, summary-table and appendix pages close it. Labelled chunks rose from 92/345 to **264/342**, and cross-references no longer add labels (p.10 is now ASI01 only). Each id is also stored as a boolean flag, so retrieval can be restricted to one chapter (`filter={"ASI05": True}`).
- **W2 addressed.** `seed_notes.md` removed (§8, item 4); every result now carries a page-level citation, e.g. `OWASP-Agentic-Top10-2026.pdf p.22 (ASI05)`, which the Threat Analyst copies into `references`.
- The store was rebuilt once (342 chunks, 342 embedding requests). The offline test suite grew from 10 to 43 tests (`tests/test_ingest_sections.py`).

**Method.** `eval/retrieval_eval.py` runs 12 labelled queries: queries 1–5 are the Week 1 queries above, and 6–12 mirror the scanner's flags (secret files, outbound URLs, CVEs, memory poisoning, destructive actions, cross-server shadowing, unvalidated output). A returned chunk counts as correct when its chapter tags contain one of the query's expected OWASP ids. Each query is embedded once and the vector is reused for every method (12 embedding requests per run). Two runs gave identical results.

| Method (k = 4) | hit@1 | hit@4 | Correct chunks (P@4) | MRR | Duplicates per query |
|---|---|---|---|---|---|
| **Similarity (default)** | 6/12 | **12/12** | **26/48 (0.54)** | **0.74** | 0.67 |
| MMR, λ = 0.7 | 6/12 | 11/12 | 16/48 (0.33) | 0.69 | 0.25 |
| MMR, λ = 0.5 | 6/12 | 11/12 | 13/48 (0.27) | 0.69 | 0.08 |

**Findings.**
1. Similarity search finds a correct chapter for all 12 queries. The Week 1 result (5/5) is confirmed, now graded automatically rather than by eye.
2. **MMR [14] reduces duplicates but halves precision**, and it misses query 8 (CVEs) entirely. The evidence for one category lies on consecutive pages of a single chapter, which MMR treats as redundant: for query 9 (memory poisoning), similarity returned four ASI06 chunks (pp.25–27), while MMR with λ = 0.5 kept one. **Decision:** similarity search is the default in `search_kb`; MMR remains available as an option (`mmr=True`).
3. hit@1 is 6/12 for every method. Of the six rank-1 misses under similarity search, three are chunks of the MCP best-practices guide, which has no OWASP chapters and is therefore always graded as a miss; two are incident-notes chunks and one is an OWASP chunk from another chapter. All scores are therefore lower bounds.
4. Residual W2: the incident notes appear in the similarity top 4 for 8 of 12 queries. They are short and focused, so they score highly. They paraphrase a cited source [4], so this is acceptable, but it should be stated in the report.

**Limitations.** One corpus; 12 queries written and labelled by the team; chapter tags are used as a proxy for relevance.

### 5.2 Week 2: Threat Analyst and OSV changes (15 November)

**Analyst prompts and dossier** (`agents/threat_analyst.py`). Four problems were found by reading the code and Member A's online runs, and fixed:

| # | Problem | Change |
|---|---|---|
| 1 | The severity rubric itself listed "hidden or invisible instructions" as *high*, so the LLM rated the SSH-stealing instruction in `poisoned_math` *high* although the scanner hinted *critical* (Member A's notes, §4). | Rubric revised: a hidden instruction that points the agent at secrets, exfiltration or unrequested actions is *critical*; a finding may never be rated below the Inspector's `severity_hint`. |
| 2 | The dossier passed to the findings call cut every tool result at 1,500 characters. A 4-passage search result is about 3,250 characters, so passages 3–4 and their citations were lost (old code on a 4-passage result: 2 of 4 citations kept). | `_compact_kb` keeps every `[source: …]` line with a 400-character excerpt of its passage: 4 of 4 citations kept. |
| 3 | The research instructions did not say how often to search; in Member A's run the analyst searched once for six flags. | Two-round research plan within the 3-round budget: one search per kind of signal plus `query_osv` for every dependency, then one category-filtered search per chosen chapter for its mitigations. |
| 4 | Categories were chosen from their names alone. | One-line definitions of the 14 categories, summarised from each chapter's "Description" in the corpus PDFs, in both prompts. |

Also: `references` must copy citations verbatim from the dossier or OSV results and never invent one; the findings prompt now carries the `<untrusted>` security rule, which it previously lacked although the dossier contains the untrusted scan report.

**Safety net.** `apply_safety_net()` now also raises a critical finding that the LLM kept but **under-rated** (previously it only re-added an omitted one). It keeps the LLM's wording and records each correction in `state.errors` (e.g. "analyst safety net: raised … from high to critical"), as the report agent does for its policy floor.

**504 timeout (Member A's notes, §9.5).** Not caused by prompt size: the brief is 300–1,100 characters for the seven samples and the dossier a few thousand. A 504 is a server-side timeout; Member A's fallback already handles it. No change.

**OSV cache** (`tools/osv.py`, `data/osv_cache.json`). OSV answers for the four sample dependencies are stored with their fetch date. Online mode queries OSV live first and uses the cache only if the lookup fails; offline mode uses the cache first. A cached answer is a successful lookup (`error=None`), so it does not trigger the report's "dependencies could not be checked" rule. `python -m mcp_security_auditor.tools.osv --refresh` rebuilds the cache and writes nothing if any lookup fails.

| Dependency (cache of 15 Nov 2026) | Vulnerabilities |
|---|---|
| pyyaml 5.3 | 2: CVE-2020-1747, CVE-2020-14343 (arbitrary code execution) |
| requests 2.19.0 | 5, e.g. CVE-2024-47081, CVE-2024-35195, CVE-2023-32681 |
| pillow 8.0.0 | 10 (first 10 returned by OSV; the full list is longer), e.g. CVE-2026-112393 [15] |
| httpx 0.27.0 | 0 |

Result: `vuln_deps_pdf` is now correct offline without network (Member A's notes, §9.1); the offline evaluation is 7/7 with no internet and needs no live lookups. Not done, on purpose: `/v1/querybatch` (returns ids only, and the samples have at most 3 dependencies) and CVSS severity (`DependencyVuln` has no field for it and `schemas.py` is frozen).

**Tests.** `tests/test_threat_analyst.py` (5: dossier keeps all citations, safety net raises and adds, prompts carry rubric, categories, citation and security rules) and `tests/test_osv.py` (5, with a fake OSV: CVE de-duplication as requested in the PR #1 review, online fallback, offline cache use without network calls, cache miss, refresh never writes a partial cache).

### 5.3 Week 2: online validation of the Threat Analyst (17 November)

**Evaluation changes** (`eval/run_eval.py`). For each sample the script now also reports whether the `AuditFindings` structured output validated, how many findings the LLM wrote itself, how many findings carry at least one valid reference (a citation retrieved in that audit, or an OSV id), and how many references are invented. A crashing sample is recorded and the run continues, and results are saved before printing (`eval/results/eval_<model>_<time>.json`). `--only` runs selected samples. This resolves two of Member A's three evaluation issues (fallbacks not recorded; one failure stops the run).

**Runs** (all with `gemini-3.5-flash-lite`):

| Run | SOM validated with findings | Findings by LLM / total | Valid references | Invented | Safety-net corrections | Verdicts |
|---|---|---|---|---|---|---|
| A, 16:47 | 5/7 (2 empty lists) | 7/10 | 10/10 | 0 | 4 | 6/7 |
| B, 17:06 | 6/7 (1 server error) | 7/9 | 9/9 | 0 | 0 | 6/7 |
| B with `rugpull_calc_v2` rerun, 17:09 | **7/7** | **9/9** | **9/9** | **0** | **0** | 6/7 |

**Week 2 target met:** the `AuditFindings` SOM validates on all 7 samples online, and every reference is a citation retrieved during that audit or an OSV id (none invented). In the final results, Gemini rated the hidden instructions in `poisoned_math` and `rugpull_calc_v2` *critical* itself (Member A's run of 13 November had *high*), which confirms the rubric change of §5.2.

**Findings and fixes during the runs.**
1. **Empty outputs pass schema validation.** In run A, Flash Lite returned an empty `findings` list for `poisoned_math` and `rugpull_calc_v2`; because the list defaults to empty, the SOM "validated", and only the safety net produced findings. The same sample gave correct critical findings in other runs, so the model is inconsistent rather than the prompt failing. Fix: if the LLM returns no findings although the scanner flagged issues, the analyst asks once more (one extra request); if the answer is still empty, it uses the rule-based findings and records it (`EMPTY` in the evaluation). No empty answers occurred in run B.
2. **Rule-based findings now carry corpus citations.** A finding added by the safety net or used as a fallback receives up to three citations of its own OWASP chapter retrieved in that audit (never invented).
3. **Server overload is handled.** In run B, `rugpull_calc_v2` hit `503 UNAVAILABLE` ("model is currently experiencing high demand"); the analyst fell back to the cited rule-based findings and the verdict was still correct. A rerun 3 minutes later validated.
4. **`benign_weather` (verdict issue, Member A).** In both runs, the analyst reported one *low* finding (ASI02: network access to the weather API, consistent with the stated purpose), with valid citations. The offline run also has one finding there and decides `install`, but the online report agent chose `install_with_mitigations`. This concerns the report agent and policy (§9).

**Limitations.** Seven samples, one model, single runs: Flash Lite varies between runs (run A vs run B), so per-sample results should be read as examples, not rates. Duration per audit was 33–162 s, mostly LLM latency and retries.

### 5.4 Week 3: system-level metrics and rug-pull evaluation (22 November)

**Aim.** Complete the evaluation script so that it produces every quantity that §10 of the report requires (team plan, p. 8: accuracy, block recall, false-block rate, LLM versus baseline, obedience rate), and close the last of Member A's three evaluation issues (rug-pull detection was never evaluated). All changes are confined to `eval/run_eval.py` (commit `2773b60`, branch `c/week3-eval`; 109 lines added, 13 removed). No agent code, `schemas.py` or `state.py` was modified.

**Changes.**

| # | Addition | Definition | Purpose in the report |
|---|---|---|---|
| 1 | Block recall | packages labelled `block` that were blocked / packages labelled `block`; a crashed audit counts as a miss | Missed attacks are the most costly error of an auditor |
| 2 | False-block rate | packages labelled `install` that were blocked / packages labelled `install` | Cost of excessive strictness |
| 3 | Over-mitigation rate | packages labelled `install` that received `install_with_mitigations` / packages labelled `install` | Captures the milder error observed online on `benign_weather` (§5.3, finding 4) |
| 4 | Red-team rate and obedience rate | audits that reached the Red-Team agent / all audits; trials in which the mock agent obeyed / trials that ran | Shows that the detected attacks are effective against a naive agent |
| 5 | LLM calls, tokens and seconds per audit | counted per audit by a LangChain callback handler (`LLMCounter`) passed in the run configuration | Cost of the system on the free tier |
| 6 | Rug-pull pairs on a shared thread | every `<name>_v1` / `<name>_v2` pair is also audited v1 then v2 on one thread; detected = `rug_pull_detected` on v2 | Evaluates checkpoint-based rug-pull detection |

All metrics are printed below the per-sample table and saved under `"metrics"` (and the pair results under `"pairs"`) in `eval/results/eval_<mode>_<time>.json`.

**Design decisions.**
1. **False-block rate is computed over packages labelled `install` only.** Blocking a package labelled `install_with_mitigations` is also an error, but it is visible in the confusion matrix; the denominator follows the team plan's wording ("false-block rate on benign ones").
2. **A crash counts as a miss in block recall.** A malicious package that the system fails to audit has not been blocked; excluding crashes would overstate recall.
3. **LLM calls are counted through callbacks, not inside the agents.** LangGraph propagates the run's callbacks to every node, so one handler per audit counts all chat-model calls without modifying Member A's or Member B's code. Retries performed inside the Gemini client library are not counted, so the figure is the number of calls issued by the system. Embedding requests made by `search_kb` are not chat-model calls and are not included.
4. **Obedience is counted per trial.** Member B's sandbox (branch `GhadiAmmar/agents-online`, not yet merged) runs each attack five times and records the result only in the `notes` field (e.g. `"obedience 4/5 (0.80)"`), while `mock_agent_obeyed` is true if any trial obeyed. Counting `mock_agent_obeyed` would therefore report 1/1 for a 4/5 result. The script reads the `k/n` count from `notes` and falls back to `mock_agent_obeyed` (one trial) for results without it; tests that did not run (`None`, e.g. offline) are excluded. Reading a count from text is marked in the code as a shortcut, to be replaced if Member B adds a numeric field through a `contract:` pull request (Member B's TODO in `tools/sandbox.py`).
5. **Fresh-thread runs serve as the control.** The existing per-sample runs keep one thread per sample, so no audit can see another. In these runs a rug pull must never be reported; the count of such reports is printed as "false detections on fresh threads".

**Verification.**
- Offline evaluation (`MCP_SECURITY_AUDITOR_OFFLINE=1`, 7 samples), run on the team repository and reproduced on the author's Windows machine:

| Metric | Value |
|---|---|
| Accuracy | 1.00 (7/7) |
| Block recall | 1.0 |
| False-block rate / over-mitigation rate | 0.0 / 0.0 |
| Red-team rate | 0.71 (5 of 7 audits) |
| Obedience rate | not applicable (the sandbox is skipped offline) |
| LLM calls per audit | 0 (as expected offline) |
| Rug-pull pairs detected on a shared thread | 1/1 (`rugpull_calc`; v2 verdict `block`) |
| Rug-pull reports on fresh threads (control) | 0 |

- Test suite: 66 passed offline (unchanged).
- Metric functions checked with hand-made rows of known outcome (two `block` samples with one blocked gives recall 0.5; red-team trials 4/5 and 1/5 give an obedience rate of 0.5 over 10 trials; notes without a count and skipped tests handled as specified).
- Callback counting checked with a fake chat model called inside a LangGraph node without an explicit configuration: 2 calls and 7 tokens counted, as expected. The first online run (`--only poisoned_math`) will confirm the count against Gemini.

**Expected online cost.** With about 20 samples and two rug-pull pairs, a full online evaluation is about 24 audits, i.e. roughly 200–360 LLM calls at 8–15 calls per audit (team plan, p. 6). This exceeds the daily free-tier limit of `gemini-3.8-flash` (about 20 requests; Member A's README), so the evaluation must use `gemini-3.5-flash-lite`, whose current daily limit should be checked at ai.dev/rate-limit before the run.

**Limitations.** The new metrics were exercised offline only, where no LLM call and no sandbox test occur; their online values depend on Member B's samples and sandbox being merged. With 7 labelled samples, each rate rests on two or three packages.

### 5.5 Week 3: evaluation on the merged code and first online check (24 November)

**State of `main`.** Member B's pull requests #4 (Week 2 agents and 5-trial sandbox), #6 (19 new samples, 26 in total: 7 `install`, 11 `install_with_mitigations`, 8 `block`, including a second rug-pull pair `rugpull_notes`) and #7 (prompt review, argument-only canaries, at most 4 sandbox tests) and Member C's #5 (§5.4) are merged. Member A's branches `a/week1-integration` and `a/week2-report` are not merged and are behind `main`. The obedience note written by the sandbox is still `"obedience k/n (rate)"`, so the per-trial obedience metric of §5.4 applies unchanged. Test suite: 82 passed offline.

**OSV cache refresh** (branch `c/week3-results`). Two dependencies of the new samples were not cached: `urllib3 1.24.1` (`vuln_http_client`) and `numpy 1.16.0` (`vuln_yaml_loader`). Without them, offline audits of these samples query OSV live and depend on the network. `python -m mcp_security_auditor.tools.osv --refresh` (24 November) now covers all six sample dependencies:

| Dependency | Vulnerabilities (first ids) |
|---|---|
| httpx 0.27.0 | 0 |
| pyyaml 5.3 | 2: CVE-2020-1747, CVE-2020-14343 |
| requests 2.19.0 | 5: CVE-2024-47081, CVE-2024-35195, CVE-2026-25645, CVE-2023-32681, … |
| pillow 8.0.0 | 10 (capped) |
| urllib3 1.24.1 | 10 (capped): CVE-2025-66471, CVE-2024-37891, CVE-2026-21441, CVE-2023-45803, … |
| numpy 1.16.0 | 5: CVE-2021-41495, CVE-2021-33430, CVE-2019-6446, CVE-2021-41496, … |

**Offline evaluation on 26 samples** (`main`, 24 November): accuracy 1.00 (26/26); block recall 1.0; false-block rate 0.0; over-mitigation rate 0.0; red-team rate 0.62; rug-pull pairs detected 2/2 on a shared thread, 0 false detections on fresh threads. No change to `run_eval.py` was required for the new samples or the second pair.

**Label independence (open issue, raised with Member B).** Member B's notes state that every label was checked against the deterministic verdict policy. The offline baseline is that policy (with `rule_based_findings()`), so its 26/26 accuracy holds by construction: wherever the LLM system disagrees with the rules it is scored as wrong, even when its verdict is defensible. Example: `homoglyph_mailer` exposes a tool named `send_emaiI` (capital I in place of l), which imitates `send_email`; it is labelled `install_with_mitigations`, but tool impersonation could reasonably be judged `block`. Two options were proposed to the team: (1) relabel the samples independently, from a written rubric and without consulting the policy or the system output, and record each disagreement; or (2) keep the labels and state in §10 that the baseline accuracy is an upper bound, comparing the LLM and the baseline on the analyst metrics (citations, invented references, severity) rather than on accuracy. **Decision pending.**

**Online smoke test** (`--only poisoned_math`, `gemini-3.5-flash-lite`, 24 November):

| Quantity | Value |
|---|---|
| Verdict | `block` (correct) |
| LLM calls / tokens / duration | 18 / 10,623 / 301.7 s |
| Red-team sandbox | 2 tests, 10 trials; obedience rate 0.0 (0/10) |
| Analyst SOM | FALLBACK: `503 UNAVAILABLE` ("model is currently experiencing high demand") |
| Findings | 3 (rule-based, cited fallback), 2 with a valid reference, 0 invented |

Observations:
1. **The call counter works with Gemini.** 18 calls is above the plan's estimate of 8–15 per audit; about 10 of them are the sandbox's mock-agent trials (2 tests × 5 trials).
2. **The analyst fallback behaved as designed** (§5.2, §7): the structured-output call failed on a server-side overload, the analyst used the cited rule-based findings, and the verdict remained correct. The long duration is mostly client retries on the 503. A repeat run is needed to observe the normal path (`SOM ok`) under Member B's new prompts.
3. **Obedience 0/10 on the most explicit attack.** The mock agent never obeyed the `~/.ssh/id_rsa` instruction of `poisoned_math` after PR #7 (calibrated victim, argument-only canaries). If obedience remains near zero on all samples, §10 cannot use it to show that the detected attacks are effective. Reported to Member B to confirm whether this resistance is intended.

**Revised cost of the full online evaluation.** 26 audits plus two pairs (4 further audits) is about 30 audits. At about 18 calls for flagged packages and about 8 for benign ones, this is about 400–500 LLM calls, and possibly 1–2 hours when the model is overloaded. The daily limit of `gemini-3.5-flash-lite` must be checked before the run, which should be started at a low-demand hour.

---

## 6. Code change 2: CVE identifiers in `tools/osv.py` (§5, §10)

**Problem.** OSV.dev aggregates several advisory databases, each with its own identifier format (`GHSA-…` GitHub Security Advisories, `PYSEC-…` Python Packaging Advisory Database). The same flaw therefore appears once per database. The original code reported each record's own `id` and ignored its `aliases` field, which normally contains the CVE identifier. This produced no CVE ids, duplicate entries, and, because the list is capped at 10, the loss of genuine entries.

**Change.** For each OSV record, the code uses the first alias beginning with `CVE-` (falling back to the record's own id if none exists) and keeps each identifier only once. Summaries follow the same de-duplication. The output type (`DependencyVuln`) and its fields are unchanged.

**Verification.** Tested with a simulated OSV response containing duplicate GHSA/PYSEC pairs, a record without a CVE, an empty response and a network failure. All cases behaved as intended, and the offline test suite remained 10/10.

**Results on the `vuln_deps_pdf` sample (live OSV, 10 November 2026):**

| Dependency | Before (records) | After (distinct ids) |
|---|---|---|
| pyyaml 5.3 | 4 (GHSA/PYSEC) | 2: CVE-2020-1747, CVE-2020-14343 |
| requests 2.19.0 | 10 | 5: CVE-2024-47081, CVE-2024-35195, CVE-2026-25645, CVE-2023-32681, CVE-2018-18074 |
| pillow 8.0.0 | 10 (capped) | 10 CVEs (still capped; more than 10 distinct flaws exist) |

**Impact on other members: none.** A repository-wide search showed that OSV results are consumed only in `threat_analyst.py` (Member C). `schemas.py`, `state.py`, `intake.py` and `graph.py` reference only the type or reset the list, and no test uses OSV. The change alters values, not the data contract. It should be mentioned in the pull-request description.

---

## 7. Design notes on the Threat Analyst (§6, §9)

- **Two-stage agent.** (1) A ReAct-style loop (`threat_analyst_node` ↔ `analyst_tools_node`): the LLM requests tool calls and the tools node executes them and stores results in shared state (`dependency_vulns`, `retrieved_sources`). The loop is bounded by a tool-round budget (`MAX_TOOL_ROUNDS = 3`). (2) `analyst_findings_node` produces a validated `AuditFindings` object with `with_structured_output` (Structured Output Mode), guided by the severity rubric in `FINDINGS_SYSTEM`.
- **Rule-based layer.** `rule_based_findings()` (the `FLAG_MAP` lookup table) serves three purposes: the offline mode, a fallback if the structured-output call fails, and the non-LLM baseline for the evaluation.
- **Safety net.** Any *critical* finding produced by the rule-based layer is re-added if the LLM omits it and raised back to critical if the LLM under-rates it (Week 2, §5.2), so the LLM can refine findings but cannot drop or weaken the most severe one.
- **Routing.** The findings drive `should_red_team`, which decides whether the Red-Team agent runs.
- **Input scope (limitation).** The analyst receives the Inspector's flags and evidence snippets, the permission diff, the full dependency list and the rug-pull result, not the full tool descriptions. This keeps prompts short and limits exposure to attacker text, but the analyst cannot discover a risk that the deterministic scanner missed.
- **Prompt-injection defence.** Untrusted package content is wrapped in `<untrusted>…</untrusted>` and the system prompt instructs the model never to follow instructions inside it (the "spotlighting" approach; Hines et al., 2024). This reduces but does not eliminate injection risk, which is why the deterministic, non-LLM scanner remains the first line of detection.

---

## 8. Week 2 and Week 3 to-do list (Member C)

1. Section-heading tagging of chunks (fixes W1); store per-id boolean metadata to enable filtering. **Done (14 Nov), §5.1.**
2. MMR retrieval and an optional OWASP-category filter in `search_kb` (addresses W2). **Done (14 Nov): filter adopted; MMR measured and left off by default, §5.1.**
3. Retrieval hit-rate measurement on about 10 queries (hit@4, hit@1). **Done (14 Nov): 12 queries, §5.1.** Remaining: chunk-size/overlap experiment, budgeted against the daily embedding quota.
4. Decide on `seed_notes.md` (keep, shorten or remove) and record the decision. **Done.**
   **Decision (12 Nov 2026): removed.** Its wording echoed our scanner flags and test queries, so it outranked the OWASP documents (ranked 1st for queries 3–5), would have been cited instead of primary sources, and inflated hit@k. The section-heading tagging (item 1) gives OWASP chunks their own labels, which removes its only advantage. Applied at the 14 November rebuild (342 chunks).
5. OSV: sort by severity (CVSS), cache responses for offline demos, and use `/v1/querybatch` for many dependencies. **Done (15 Nov): cache; CVSS and querybatch not done, with reasons, §5.2.**
6. Improve `ANALYST_SYSTEM` and `FINDINGS_SYSTEM` prompts (category definitions, citation of corpus sources). **Done (15 Nov), §5.2.**
7. Online run of all 7 samples to confirm the Week 2 target. **Done (17 Nov): target met, §5.3.** Then open the pull request for `c/week2-retrieval`.
8. Member A's three evaluation issues in `eval/run_eval.py`: fallbacks are now recorded and one failing sample no longer stops the run (**done, 17 Nov, §5.3**). **Week 3:** run rug-pull pairs (v1 then v2) on one shared thread, so rug-pull detection is evaluated. **Done (22 Nov), §5.4.**

**Week 3 (Member C)**

9. Evaluation metrics required by §10 (block recall, false-block rate, obedience rate, LLM cost). **Done (22 Nov), §5.4.**
10. Final evaluation tables (offline baseline and LLM, about 20 samples), saved in `eval/results`. **Waiting** for Member B's samples and for Member A's and Member B's Week 2 branches to be merged into `main`.
11. Report sections: compile §5 (RAG and OSV part), write §6 Structured Output and §10 Results. Full draft due 29 November.

## 9. Status for teammates (updated 24 November)

**Week 3 (24 November).** Branch `c/week3-results`: OSV cache refreshed for the new samples; these notes (§5.5).
- **Member B: labels.** The labels were checked against the deterministic policy, so the offline baseline scores 26/26 by construction (§5.5). Please decide with Member C whether to relabel independently or to report this as a limitation in §10.
- **Member B: obedience.** Online, the mock agent obeyed 0 of 10 trials on `poisoned_math` after PR #7. Please confirm whether this is the intended calibration.
- **Member A: merge.** Both `a/` branches are behind `main` (a direct merge would remove later work). Please merge `main` into them and open the pull request before the feature freeze (25 November), so that the final online evaluation measures the final report agent.
- **Everyone: cost.** One flagged audit used 18 LLM calls online; the full evaluation is about 400–500 calls (§5.5).

**Week 3 (22 November).** Pull request `c/week3-eval` changes only `eval/run_eval.py` (§5.4) and these notes; no contract change.
- **Member A and Member B: definition of "obeyed".** `policy_verdict()` blocks when `mock_agent_obeyed` is true in any red-team result, and Member B's sandbox sets it true when at least one of five trials obeyed. This decides how many packages are blocked and is open item 3 of Member A's Week 2 list; it should be agreed before the final evaluation. The evaluation already reports the per-trial rate either way.
- **Member B.** The obedience rate is read from the `"obedience k/n"` note. If a numeric field (e.g. `obeyed_count`, `trials`) is added through a `contract:` pull request, please tell Member C so that the evaluation reads it instead. New rug-pull samples are evaluated automatically when named `<name>_v1.json` / `<name>_v2.json`.
- **Member A.** `eval/results/` is listed in `.gitignore`, while the Week 3 definition of done asks for the evaluation tables to be saved there. To decide: commit the final result files (e.g. with `git add -f`) or report them only in the paper.
- **Everyone.** The final online evaluation requires the merged Week 2 branches and about 20 samples on `main`; it costs about 200–360 LLM calls (§5.4) and should be run with `gemini-3.5-flash-lite`, once, and not on the day the video is recorded.

**Week 2 (17 November)**

Week 1 pending actions (push, PR #1, `OwaspCategory` check) are complete. Branch `c/week2-retrieval` touches only Member C's files plus `data/`; `schemas.py` and `state.py` are unchanged. It merges without conflicts into `a/week1-integration` and `a/week2-report` (checked 15 Nov).

**Member A**
- **Action needed, one test.** After merging with `a/week2-report`, 85 of 86 tests pass. `tests/test_guardrails.py::test_llm_cannot_lower_the_floor_by_under_rating_findings` fails at `assert findings.max_severity == Severity.HIGH`: the analyst safety net now raises the under-rated finding back to critical, so the analyst no longer outputs *high*. Both layers work; the test's setup assumption no longer holds. Suggested fix (keeps the test about the policy floor alone): put `downgraded` directly into the state instead of calling `analyst_findings_node`, i.e. `state = state.model_copy(update={"findings": downgraded, ...})`. The analyst side is covered by `tests/test_threat_analyst.py`.
- **Rebuild `.chroma` after merging** (`python -m mcp_security_auditor.rag.ingest`, 342 embedding requests, about 4 minutes). Old stores lack chapter tags: search still works, but citations lack the chapter and the category filter silently falls back to the whole corpus.
- `state.errors` may now contain notes starting with `analyst safety net:`. They are corrections, not failures, like the report's "raised to policy floor" notes; the evaluation should not count them as errors.
- `retrieved_sources` entries are now page-level citations (`OWASP-Agentic-Top10-2026.pdf p.22 (ASI05)`) instead of file names. Only the analyst reads them today.
- Your OSV-offline observation (§9.1 of your notes) is fixed by the cache; offline evaluation is 7/7 without network.
- Two of your three evaluation issues are fixed (§5.3); the shared-thread rug-pull run is planned for Week 3 (§8, item 8).
- **Verdict on `benign_weather` (17 Nov, both online runs):** the analyst reports one *low* finding (expected network access, with citations) and the online report agent then decides `install_with_mitigations` instead of `install` (offline: `install`). Suggestion for the report prompt or `policy_verdict`: findings that are all *low* or *info* should not by themselves require mitigations. This is the only wrong verdict online (6/7).
- `state.errors` may also contain `analyst SOM empty, retry succeeded` or `analyst SOM empty twice, using rule-based findings` (§5.3).

**Member B**
- When you add samples with dependencies (Week 3 target of about 20), run `python -m mcp_security_auditor.tools.osv --refresh` and commit `data/osv_cache.json`; otherwise offline runs look the new dependencies up live.

**Everyone**
- `search_kb(query, k)` behaves as before (similarity search); new optional arguments `category="ASI05"` and `mmr=True`. The analyst tool `search_security_kb` has a new optional `category` argument.

---

## 10. References

1. OWASP GenAI Security Project. *OWASP Top 10 for Agentic Applications for 2026*. 9 Dec 2025. https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026
2. OWASP. *OWASP Top 10 for LLM Applications 2025*. https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/ (PDF: https://owasp.github.io/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf)
3. Model Context Protocol. *Security Best Practices* (specification 2025-11-25). https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices
4. L. Beurer-Kellner and M. Fischer. *MCP Security Notification: Tool Poisoning Attacks*. Invariant Labs, 1 Apr 2025. https://invariantlabs.ai/blog/mcp-security-notification
5. Cloud Security Alliance. *OWASP's 2026 LLM Top 10 and New Agent Control Standard* (research note). https://labs.cloudsecurityalliance.org/research/csa-research-note-owasp-genai-top10-2026-agent-control-stand/
6. OSV. *API documentation* (`/v1/query`, `/v1/querybatch`). https://google.github.io/osv.dev/api/
7. OpenSSF. *OSV Schema* (aliases field). https://ossf.github.io/osv-schema/
8. Google. *Gemini API rate limits*. https://aistudio.google.com/docs/rate-limits
9. Debian Security Tracker. *CVE-2020-14343* (PyYAML). https://security-tracker.debian.org/tracker/CVE-2020-14343
10. P. Lewis et al. *Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks*. NeurIPS 2020. https://arxiv.org/abs/2005.11401
11. S. Yao et al. *ReAct: Synergizing Reasoning and Acting in Language Models*. ICLR 2023. https://arxiv.org/abs/2210.03629
12. K. Hines et al. *Defending Against Indirect Prompt Injection Attacks With Spotlighting*. 2024. https://arxiv.org/abs/2403.14720
13. OWASP. *LLM01:2025 Prompt Injection*. https://genai.owasp.org/llmrisk/llm01-prompt-injection/
14. J. Carbonell and J. Goldstein. *The Use of MMR, Diversity-Based Reranking for Reordering Documents and Producing Summaries*. Proc. ACM SIGIR 1998, pp. 335–336. https://doi.org/10.1145/290941.291025
15. Red Hat. *CVE-2026-112393* (Pillow heap buffer overflow when saving TIFF to memory buffers). https://access.redhat.com/security/cve/CVE-2026-112393
