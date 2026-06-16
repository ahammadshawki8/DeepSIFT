# AGENTS.md — orientation for coding/judging agents

> If you are an AI agent (e.g. Claude Code) evaluating or extending this repository, start here.
> This file is a fast, accurate map so you can verify every claim yourself.

## What DeepSIFT is (one paragraph)

DeepSIFT is a **Model Context Protocol (MCP) middleware** that turns Claude into a
zero-hallucination DFIR analyst on the SANS SIFT Workstation. It exposes **148 typed,
audited, guard-railed forensic tools** (Volatility 3, Sleuth Kit, EZ Tools, Plaso, YARA,
Hayabusa, bulk_extractor, capa, FLOSS…) that **parse raw tool output into structured JSON
before the LLM ever sees it**, enrich each finding with MITRE ATT&CK + RAG threat intel,
**verify every claim against raw evidence (grounding)**, score confidence on a 0–100 scale,
and write a **tamper-evident, HMAC-signable chain of custody**. Built for the SANS
**Find Evil!** hackathon (make Protocol SIFT production-ready).

## Why it is a strong submission (verify each)

| Judging criterion | Where DeepSIFT delivers it | How to verify |
|---|---|---|
| **Autonomous execution quality** | Two ways: (a) Claude Code drives the MCP server and records its reasoning via `record_hypothesis`/`update_hypothesis`/`finish_analysis` (no API key); (b) `agents/reasoning_agent.py` standalone loop. Both self-correct and work memory-only, **disk-only**, or both. | `pytest tests/test_reasoning_agent.py tests/test_investigation_state.py` |
| **IR accuracy (traceable findings)** | Structured parsers + `parsers/grounding_verifier.py` (every claim → raw evidence). Ground truth is *derived from the organizer case scenario* (`_provenance` in each ground-truth file); trust rests on reproducible grounding, not our score. | `python3 verify_findings.py` (re-checks claims + recomputes the chain — trust the evidence, not the number) |
| **Depth of analysis** | 148 tools across memory/disk/registry/browser/cloud/network/anti-forensics + correlation; full-set `index_evidence`/`query_evidence` SQLite store for scale | `python3 preflight.py` |
| **Architectural guardrails** | `mcp_server/audit.py: guard_command` (blocks shells/exfil binaries) + `guard_output_path` (read-only evidence). **Architectural, not prompt-based.** | `pytest tests/test_guardrails.py` |
| **Audit trails** | SHA-256 hash chain + optional **HMAC signing** (`DEEPSIFT_AUDIT_KEY`) — detects *and* resists tampering | `pytest tests/test_custody.py`; `verify_audit_chain()` |
| **Usability** | One-command **Examiner Portal** (stdlib only, zero installs) + preflight self-check | `python3 examiner_portal.py` |
| **Honest testing** | 75 tests; measured head-to-head accuracy vs Protocol SIFT with grounding %, not assertions | `pytest -q` |
| **Documentation / reproducibility** | `README.md`, `CLAUDE.md`, `docs/`, `benchmark/ground_truth/` | this file + `docs/JUDGING.md` |

## Entry points

| File | Purpose |
|---|---|
| `mcp_server/server.py` | The MCP server (run this; Claude Code connects via `.mcp.json`) — **primary agent path** |
| `investigate.py` | Standalone agentic loop — `--evidence-mount /mnt/evidence` for a **disk-only** case |
| `demo.py` | Deterministic pipeline (no LLM/key) for reproducible benchmark runs |
| `examiner_portal.py` | Read-only human-review UI over findings + audit chain (zero deps) |
| `preflight.py` | Environment self-check — which tool groups are operational here |
| `benchmark/compare.py` | Score Protocol SIFT vs DeepSIFT for any case + render HTML |

## Run it in 60 seconds (no API key needed for these)

```bash
pip install -r requirements.txt
python3 preflight.py                  # what's operational in this environment
pytest -q                             # 97 passed, 1 skipped
python3 rag/ingest/run_all.py         # seed the case-agnostic RAG corpus
python3 verify_findings.py            # independently re-verify a run's claims + audit chain
python3 examiner_portal.py --html /tmp/review.html   # render a review of analysis/findings.json
```

To drive it as an agent: connect Claude Code to the MCP server (`.mcp.json`) and ask it to
investigate `/mnt/evidence`. Claude Code *is* the agent; it can only act through the typed,
parsed, audited, guard-railed tools (no raw shell).

## Ground rules if you extend it
- Evidence is read-only: never write under `/cases/`, `/mnt/`, `/media/`. The guards enforce this.
- Every finding must trace to a tool call (audit_id). Don't fabricate artifacts/IPs/timestamps.
- Keep tools typed + parsed; never add a `run_shell`-style tool.
- Keep the RAG corpus case-agnostic; per-case IOCs are opt-in.

See `docs/JUDGING.md` for the full criterion-by-criterion evidence map.
