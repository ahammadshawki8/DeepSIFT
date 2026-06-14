# DeepSIFT — Judging Criteria Evidence Map

This document maps the **Find Evil!** Stage-2 judging criteria (equally weighted) to the
exact place each is implemented and how to verify it. Everything here is runnable — no claim
is asserted that you cannot confirm from the repository.

---

## 1. Autonomous execution quality
*Does the agent reason about next steps, handle failures, and self-correct in real time — without theater?*

- **Hypothesis-driven loop:** `agents/reasoning_agent.py`. The LLM forms explicit hypotheses,
  picks the tool that would confirm/disprove each, marks them confirmed/disproved/inconclusive
  with a confidence, and **self-corrects** when a tool errors or a result contradicts a hypothesis.
- **Evidence-adaptive triage:** works on **memory-only, disk-only, or both**. A disk-only case is a
  first-class autonomous run (`investigate.py --evidence-mount /mnt/evidence`) — triage starts with
  event logs / shellbags / UserAssist / LNK / Jump Lists / USB / shimcache / browser / MFT.
- **Not theater:** the deterministic `demo.py` pipeline exists *only* for reproducible benchmarks;
  the autonomy is the LLM loop, and the full reasoning + every tool call is written to
  `analysis/agent_transcript.json`.
- **Verify:** `pytest tests/test_reasoning_agent.py` (covers self-correction + disk-only bootstrap +
  iteration cap).

## 2. IR accuracy — findings trace to real artifacts/logs/repeatable steps
- **Structured parsing before the LLM:** raw Volatility/EZ-Tools/Plaso output is converted to typed
  JSON by `mcp_server/parsers/*` before the model sees a byte.
- **Grounding verifier:** `mcp_server/parsers/grounding_verifier.py` checks every observable claim
  token against the raw exported evidence; `findings.json.grounding.grounding_score` reports the %.
- **Measured, head-to-head:** ROCBA 4/4 and FOR500 "Abducted Zebrafish" 4/4 vs Protocol SIFT, **0
  hallucinations, 100% grounding** — scored by `benchmark/scorer.py` against
  `benchmark/ground_truth/*`. We publish *numbers*, not adjectives.
- **Independently reproducible — verify the evidence yourself.** Ground-truth files are transparently
  derived from the organizer case scenario (each carries a `_provenance` block citing its basis).
  Crucially, every finding is **cryptographically reproducible**: `python3 verify_findings.py`
  re-checks each claim against the cited raw tool output and recomputes the audit hash chain, so a
  judge confirms the result from first principles rather than taking any reported number on faith.
  Grounding is the objective, tamper-evident proof behind the score.
- **Verify:** `python3 verify_findings.py` (independent) · `python3 benchmark/compare.py --protocol-sift <psift.json> --deepsift analysis/findings.json --ground-truth benchmark/ground_truth/<case>_ground_truth.json`

## 3. Depth of analysis
- **148 typed forensic tools** across memory, disk, registry, browser, cloud, email, document,
  network, anti-forensics, carving, threat-intel, correlation (+ a preflight self-check).
- **Cross-tool correlation + adversarial review + contradiction detection:** `mcp_server/tools/correlation.py`.
- **Verify:** `python3 preflight.py` lists every group; `mcp_server/server.py` registers them all.

## 4. Architectural guardrails (vs prompt-based)
- **Architectural, enforced in code at every exec choke point:** `mcp_server/audit.py: guard_command`
  blocks shells + destructive/exfil binaries + shell redirection/chaining and rejects shell-string
  commands (argv only, never `shell=True`). `guard_output_path` blocks any write under `/cases/`,
  `/mnt/`, `/media/`. These raise exceptions — they are not suggestions to the model.
- **No `run_shell` tool exists.** The MCP tool surface is the only interface.
- **Cross-case isolation + dirty-hive correctness** baked into the EZ-Tools path (see README →
  Production Hardening).
- **Verify:** `pytest tests/test_guardrails.py`.

## 5. Audit trails
- **Tamper-evident:** every tool call is a SHA-256 **hash-chained** entry in
  `analysis/forensic_audit.log` — modify/insert/delete breaks the chain (`verify_audit_chain()`).
- **Tamper-resistant:** set `DEEPSIFT_AUDIT_KEY` (held off the evidence host) to **HMAC-sign** the
  chain; an attacker who rewrites the whole log cannot forge valid signatures without the key.
- **Examiner sign-off:** `mcp_server/custody.py` HMAC-signs a findings manifest for human approval.
- **Verify:** `pytest tests/test_custody.py`; open the **Examiner Portal** to see the live verdict.

## 6. Usability — could another practitioner run, understand, and build on it?
- **Examiner Portal:** `python3 examiner_portal.py` — a read-only review UI (verdict, findings,
  grounding, full chain of custody) with **zero pip installs** (Python stdlib only).
- **Preflight:** `python3 preflight.py` tells you exactly what is operational and what to install.
- **Three run modes** (Claude Code + MCP / `investigate.py` / `demo.py`) and `AGENTS.md` for agents.

## 7. Honest testing of safety/reliability/hallucination/governance
- **67 tests, 1 skipped** (`pytest -q`): parsers, guardrails, custody (incl. HMAC forgery), grounding
  integrity, reasoning loop, preflight, examiner portal.
- **Honest degradation:** missing external binaries report `unavailable` (preflight), they don't crash.
- **Honest accuracy:** grounding is *measured per claim*; hallucination is *counted against ground
  truth*, not asserted.

## 8. Documentation / reproducibility
- `README.md` (architecture diagram + production hardening + validated results), `CLAUDE.md`
  (operator/agent guide), `AGENTS.md` (agent orientation), `docs/` (architecture, dataset), and
  `benchmark/ground_truth/` (the scoring rubric per case). Datasets and what was found are documented
  for reproducibility.

---

### Architectural pattern & security boundaries (required deliverable)
- **Pattern:** typed-MCP-middleware + agentic reasoning loop. The LLM never receives raw tool output
  and can never issue a raw shell command.
- **Security boundary 1 (command):** `guard_command` at every subprocess choke point.
- **Security boundary 2 (filesystem):** `guard_output_path` — evidence roots are read-only.
- **Security boundary 3 (integrity):** hash-chained + HMAC-signable audit log.
- **Architectural vs prompt-based:** all three boundaries are Python that raises exceptions — none
  rely on the model "agreeing" to a rule in a prompt.
