# DeepSIFT — Accuracy Report

> **Honesty over perfection.** This report states where DeepSIFT is *confirmed*, where it is
> *inferring*, the false positives its parsers emitted (and how they were caught), the artifacts
> it missed, and the limits of our testing. Every headline number here is **independently
> recomputable** from committed evidence — see [§6 Verify it yourself](#6-verify-it-yourself).
> Nothing in this report rests on the agent's self-reported success; only raw tool output and
> ground truth count.

---

## 1. Methodology

- **Scoring:** `benchmark/scorer.py` scores a `findings.json` against a structured
  ground-truth answer key (`benchmark/ground_truth/*.json`), counting **must-identify found,
  missed artifacts, false positives, and hallucinations**, and produces an accuracy score and a
  hallucination rate. Indicators use content-based co-occurrence groups (artifact strings must
  appear *together in one entry*), so a passing prose mention does not score — the agent must have
  produced the artifact, not described it.
- **Grounding (anti-hallucination gate):** `mcp_server/parsers/grounding_verifier.py` re-checks
  every observable claim (process names, IPs, domains, filenames) **verbatim against the raw
  bytes** of the cited tool's output. `finish_analysis` is **hard-blocked** if zero claims can be
  traced. MITRE technique IDs are DeepSIFT's own derivation, so they are validated for
  well-formedness and counted *separately* — not grounded against CLI bytes (that would be a
  category error).
- **Chain of custody:** every tool call is appended to a SHA-256 **hash chain**
  (`mcp_server/audit.py`); `verify_audit_chain()` recomputes it and detects any
  modify/insert/delete/reorder.
- **Independent re-derivation:** `verify_findings.py` re-runs grounding + chain verification from
  the on-disk artifacts and exits non-zero on any failure. A judge runs it on a fresh clone; it
  trusts none of our numbers.
- **Evidence:** the organizer-provided **ROCBA** (FOR508, memory + disk) and **Vanko / "The
  Abducted Zebrafish"** (FOR500, disk-only) cases. See [`docs/dataset.md`](dataset.md).

---

## 2. Results

| Case | Evidence | Must-identify found | Missed | Hallucinations* | Grounding | Confidence |
|------|----------|--------------------|--------|-----------------|-----------|------------|
| **ROCBA** (FOR508) | memory + disk | **4 / 4** | 0 | 0 | 100% (27/27 observable claims) | MODERATE (66.4/100)† |
| **Vanko** (FOR500) | disk-only | **4 / 4** | 0 | 0 | 100% (13/13 observable claims) | MODERATE (56.1/100)† |

Protocol SIFT baseline on the same scorer: ROCBA **0 / 4**, Vanko **3 / 4** (see
`benchmark/baselines/`). The ROCBA baseline was memory-only; all four ground-truth criteria
are disk artifacts, so Protocol SIFT scored 0. DeepSIFT uniquely recovered Vanko's zebrafish /
cell-regeneration / DNA-splice subject matter via jump-list + shellbag correlation.

† **Confidence score** is the 4-axis quantified score (Tool Reliability 40 + Corroboration 25 + IOC Specificity 25 + MITRE Accuracy 10 − grounding penalty): MODERATE is the honest tier for memory images captured days post-incident (ROCBA) or disk-only cases (Vanko) where some inferences can't be independently corroborated. The 100% grounding and 4/4 must-identify scores are separately verified.

\* **"Hallucinations: 0" and "False Positives: 0" are measured against the ground-truth
must-identify list** — i.e. DeepSIFT reported no *unsupported* finding that contradicts the answer
key. That is **not** the same as "the parsers never over-flag." They do, and we surface every such
case below. The distinction between a *confirmed* finding and a *flagged-but-reasoned-away* one is
the whole point of §3–§4.

---

## 3. Confirmed vs. inferred (we label every claim)

DeepSIFT separates **observation** (what the raw tool output shows) from **interpretation** (what
it means), and attaches a confidence tier to each inference.

**ROCBA — HIGH (confirmed, traces verbatim to raw output):**
- Inbound RDP unauthorized access to SRL-FORGE; the SDelete download and SharePoint exfil facts.
- SRL project files copied to a removable **F:** drive on 2020-11-13 (LNK targets).

**ROCBA — MEDIUM (inference, explicitly flagged, *not* presented as fact):**
- That the 2020-11-14 `fredr` RDP sessions were *attacker-driven* rather than the legitimate user.
  **Why only medium:** the parser's 4778/4779 records do **not** carry the source IP; tying the
  session to `213.202.233.104` / `81.30.144.115` would require
  TerminalServices-RemoteConnectionManager (1149) / RDPClient logs we did not have. We say so in
  the report rather than overclaiming.

**Vanko — HIGH:** shellbag/LNK/USB/UserAssist evidence of Level 5–8 classified access, local
staging under "vacation photos", 7-Zip + VeraCrypt encryption, and exfil to USB / iCloud.
**Vanko — MEDIUM:** exact *intent* labeling of individual file opens vs. the overall exfil chain.

---

## 4. False positives our parsers emitted — and how they were caught

These are real over-flags. None reached the final must-identify findings (corroboration suppressed
them), but an honest report names them:

1. **`malfind` RWX false positives.** `find_injected_code` flags standard CLR/JIT executable
   regions in benign processes: **MsMpEng.exe** (Defender), **SearchApp.exe**, **smartscreen.exe**,
   **RuntimeBroker.exe**, **LockApp.exe**, **dllhost.exe**. We do not remediate these — the
   per-tool forensic-knowledge envelope flags malfind's well-documented FP rate, and the confidence
   scorer weights `find_injected_code` at only **0.72** for exactly this reason.
2. **`URL_SHORTENER` mislabel — a parser bug we caught.** The browser parser tagged
   `*.sharepoint.com` URLs as a URL shortener. **That is wrong** (SharePoint is not a shortener);
   the operative flag is `CLOUD_EXFIL_DOMAIN`. Documented rather than hidden.
3. **`APSDaemon.exe → 17.57.144.165:5223` flagged, then assessed BENIGN.** That address is Apple
   Push Notification service on an Apple-owned range — a false positive we explicitly stand down.
4. **`MRC.exe` (`D:\Tools\MRC.exe`) initially looked suspicious by path**, but runs alongside
   KAPE / FTK Imager and was assessed as the **responder's IR collection tool, not attacker
   malware** — noted for completeness, not counted as a finding.

---

## 5. Misses and known limitations

- **`get_partition_table` returned no parsed partitions** on the Vanko mounted volume (analysis ran
  against the mounted filesystem, not the raw `.E01`); we relied on file-system artifacts instead.
- **RDP source-IP attribution gap** (above): a class of evidence (1149/RDPClient) we could not
  correlate on ROCBA, so the attacker↔session link is an inference, not a fact.
- **Coverage of accuracy testing is two cases.** DeepSIFT exposes 148 tools; only the subset used
  in ROCBA/Vanko is independently accuracy-validated here. The rest are real wrappers, but their
  per-tool false-positive rates are not separately measured.
- **Non-determinism.** The agentic path is LLM-driven and can vary run-to-run. We mitigate with the
  grounding hard-gate (an unverifiable claim cannot be submitted) and the audit chain, but we do
  **not** claim deterministic findings. Re-running on the same input is expected to converge on the
  same *grounded* facts, not necessarily identical prose.

---

## 5a. Self-correction (demonstrated, from the logs — not the video)

Two committed artifacts show genuine mid-investigation pivots:

**`docs/sample/rocba_agentic_findings.json`** — memory-first run (Claude Code + DeepSIFT MCP):
- **H1 — "Memory-resident malware / injected code present" → DISPROVED (conf 0.85).** After
  `get_process_list`, the agent recognized 103 flags were Teams/svchost *volume* anomalies with
  **no injected PE**, and that the capture was **2020-11-16, three days post-incident**.
- It **pivoted to disk**, where `parse_lnk_files` confirmed 7 SRL-project files on removable **F:**
  (**H2 confirmed, 0.95**) and `parse_chrome_history` confirmed the SDelete search (**H3 confirmed, 0.80**).

**`docs/sample/rocba_findings.json`** — disk + memory run; structured hypothesis ledger:
- **H4 — "Memory image is post-incident; attacker process is no longer present" → DISPROVED (conf 0.80)**
  with evidence audit_ids `['dsift-2026-06-20-0f0a0bff', 'dsift-2026-06-20-45661afb', ...]`. This
  records the same diagnostic pivot with structured traceability to specific tool calls.

That is the senior-analyst behavior the event asks for: form a hypothesis, test it, recognize when
results don't add up, change approach. The agent also handles genuine tool failures (e.g. Volatility
argument errors and `PECmd` absent) by retrying / degrading gracefully rather than aborting.

---

## 6. Verify it yourself

No trust required — recompute everything from committed evidence on a fresh clone:

```bash
# Re-check every claim against raw tool output + recompute the audit hash chain
python3 verify_findings.py --findings docs/sample/rocba_findings.json --analysis-dir docs/sample/rocba_analysis
# Expected: grounding 100% (27/27 observable claims), chain INTACT, OVERALL ✔ VERIFIED

python3 verify_findings.py --findings docs/sample/vanko_findings.json --analysis-dir docs/sample/vanko_analysis
# Expected: grounding 100% (13/13 observable claims), chain INTACT, OVERALL ✔ VERIFIED
```

- **Three-claim trace:** open `docs/sample/rocba_findings.json`, pick any finding, read its
  `audit_id`, find that entry in `docs/sample/rocba_analysis/forensic_audit.log` — it gives the
  exact tool command + SHA-256 + the raw output file path. The claim's tokens appear verbatim in
  that raw file. Same pattern works for `docs/sample/vanko_findings.json` / `vanko_analysis/`.
- **Score reproduction:** `python3 -m benchmark.scorer` against `benchmark/ground_truth/`.
- **Self-correction:** [`docs/sample/rocba_agentic_findings.json`](sample/rocba_agentic_findings.json)
  → the `hypotheses` array (H1 `disproved`).
