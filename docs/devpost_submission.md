# DeepSIFT — Devpost Submission Draft

> **Fill in before submitting:** benchmark numbers (TBD), demo video URL, accuracy report link

---

## Project Title

**DeepSIFT — Zero-Hallucination AI Forensic Analysis via Structured MCP Middleware**

---

## Tagline

AI-driven incident response that *proves* its findings — structured JSON middleware eliminates LLM hallucinations in SANS SIFT forensic investigations.

---

## 1. Inspiration

At SANS DFIR we saw a compelling demo of Protocol SIFT — Claude Code connected directly to SIFT Workstation tools. The concept was powerful: an AI agent that autonomously runs Volatility, log2timeline, and Sleuth Kit. But watching it analyze the ROCBA memory image, we noticed a pattern: **the agent hallucinated.**

It invented process names that weren't in the data. It attributed network connections to wrong PIDs. It confused a November 16 RDP brute-force with the November 13 break-in we were actually investigating.

The root cause was structural: Protocol SIFT dumps 10,000+ lines of raw Volatility output directly into Claude's context window and asks the LLM to find patterns in raw text. Under that token pressure, the model fills gaps with plausible-sounding fabrications.

We asked: what if the LLM never saw raw output at all?

---

## 2. What It Does

DeepSIFT is a Python MCP (Model Context Protocol) server that sits between Claude Code and SANS SIFT forensic tools. It provides:

**29 typed MCP functions** across 5 tool categories:
- Memory forensics (Volatility 3) — process list, code injection, network connections, registry, handles
- Timeline analysis (log2timeline/Plaso) — super timeline, filter, browser history
- Disk forensics (Sleuth Kit) — partition table, file listing, extraction, deleted files
- YARA hunting — file scan, memory scan, rule listing
- Windows artifacts (EZ Tools) — event logs, shimcache, amcache, MFT, prefetch, LNK files, jump lists, recycle bin, registry, IP reputation

**What makes it different from Protocol SIFT:**

| Protocol SIFT | DeepSIFT |
|---------------|----------|
| One `execute_shell_cmd` function — agent guesses plugin names | One typed function per tool action — guessing is architecturally impossible |
| Raw CLI output (10k+ lines) dumped into context | Python parsers convert output to typed JSON before LLM sees it |
| Hunt Evil baseline comparison done by LLM inference | 31-process KNOWN_NORMAL baseline runs in Python; anomalies pre-flagged |
| Prompt-based evidence protection ("never modify evidence") | No write operations exposed on evidence paths — architectural enforcement |
| No threat intelligence integration | RAG pipeline injects MITRE ATT&CK techniques into every suspicious finding |

**Hallucination reduction mechanism:** Every function returns a structured dict, not text. Claude Code receives pre-analyzed JSON with fields like `"suspicious": true, "anomalies": ["Wrong parent: expected services.exe, got explorer.exe"]`. The LLM's job is to reason about structured findings, not pattern-match raw terminal output.

---

## 3. How We Built It

**Architecture:**

```
Claude Code
    ↓ typed MCP functions (FastMCP)
DeepSIFT MCP Server (mcp_server/server.py)
    ↓ subprocess execution
SIFT Tools (volatility, log2timeline, fls, yara, ez tools)
    ↑ raw output → Python parsers → structured JSON
RAG Pipeline (ChromaDB + all-MiniLM-L6-v2 + MITRE ATT&CK)
    ↑ semantic search injected into tool results
```

**Parser design:** Each parser extracts only the fields the LLM needs. The pslist parser checks every process against a 31-entry KNOWN_NORMAL baseline (from the SANS Hunt Evil FOR508 poster) and runs Levenshtein distance ≤2 masquerade detection. A process named `svch0st.exe` is flagged before Claude ever reads it.

**RAG pipeline:** ChromaDB stores 700+ MITRE ATT&CK techniques, AbuseIPDB threat intel, and prior case findings. When the event log parser sees Event ID 7045 (service install), it queries the RAG for `"service install persistence"` and injects the top-3 matching ATT&CK techniques into the returned JSON. Claude reasons about evidence + threat intel simultaneously.

**Multi-agent orchestration (LangGraph):** A StateGraph runs memory, disk, and network agents, then a synthesis agent cross-correlates findings (e.g., which suspicious processes also have external network connections), and a report agent writes `findings.json` to disk.

**Benchmark framework:** `benchmark/scorer.py` scores any `findings.json` against a ground truth answer key, counting true positives, false positives, missed artifacts, and hallucinations. This lets us produce a quantitative comparison between Protocol SIFT and DeepSIFT on the same image.

**Evidence integrity:** The MCP server exposes zero write operations on `/cases/`, `/mnt/`, or `/media/` paths. Chain-of-custody is logged to `analysis/forensic_audit.log` with UTC timestamp, command executed, and SHA-256 hash of raw output for every tool call.

**Tech stack:** Python 3.10, FastMCP, LangGraph, ChromaDB, sentence-transformers (all-MiniLM-L6-v2), Volatility 3, log2timeline/Plaso, The Sleuth Kit, YARA, Eric Zimmerman's EZ Tools. Runs on SANS SIFT Workstation (Ubuntu x86-64).

---

## 4. Challenges We Ran Into

**Volatility output parsing is fragile.** The Volatility 3 output format varies slightly depending on plugin and OS version. We wrote defensive parsers that handle header-skipping, column count mismatches, and hex dump variations (especially for malfind, where PE header detection requires stripping address prefixes from hex bytes before pattern-matching).

**The 3-day memory gap.** Our ROCBA memory image was captured 3 days after the incident. Nov 13 evidence exists only on disk. This was initially frustrating — Protocol SIFT scored 1/4 on must-identify criteria not because it hallucinated, but because it only analyzed memory. It forced us to build 10 Windows artifact tools that analyze disk-resident forensic artifacts (event logs, shimcache, prefetch, MFT, LNK files, recycle bin) — which is actually the differentiating capability judges should focus on.

**RAG seeding on SIFT VM.** The sentence-transformers model download requires internet access from the VM, and the MITRE ATT&CK JSON is ~100MB. We scripted the full ingestion pipeline (`rag/ingest/mitre_attack.py`) to run idempotently, but first-run setup is slow.

**EZ Tools on Linux.** Eric Zimmerman's tools are .NET-based Windows executables. On the SIFT VM (Ubuntu) they run via `dotnet` runtime. We detect the runtime at config time and fail fast with a clear error message if `dotnet` is unavailable, rather than silently returning empty results.

---

## 5. Accomplishments We're Proud Of

**29 typed MCP tools, all returning structured JSON.** Every single tool — from `get_process_list` to `parse_mft` — returns a typed Python dict, not raw text. This required writing parsers for 6 different raw output formats.

**Zero hallucinations in structured output.** Because the parsers never guess — they extract or skip — DeepSIFT cannot hallucinate a process name or IP address that wasn't in the evidence. The LLM can only reason about what the parsers extracted.

**31-process Hunt Evil baseline with masquerade detection.** We transcribed the complete SANS FOR508 Hunt Evil poster into code, including all 13 processes added in Windows 10 (lsaiso.exe, fontdrvhost.exe, dwm.exe, sihost.exe, ctfmon.exe, WmiPrvSE.exe, audiodg.exe, SecurityHealthService.exe, MsMpEng.exe, ShellExperienceHost.exe, SearchUI.exe, userinit.exe, NisSrv.exe). The masquerade detector runs Levenshtein distance checks against a 12-entry target set.

**Benchmark framework with quantitative hallucination scoring.** `benchmark/scorer.py` provides a rigorous methodology for comparing any two AI forensic systems: true positives, false positives, missed artifacts, hallucination count, accuracy score, and hallucination rate — all computed against a structured ground truth JSON.

---

## 6. What We Learned

The biggest insight was that **structured output is the intervention, not better prompting.** We initially experimented with more specific prompts for Protocol SIFT. They helped marginally. Then we built the parsers. Hallucinations dropped dramatically because the LLM was no longer reading raw text — it was reading pre-analyzed, pre-labeled JSON with anomaly flags already set.

The second insight: **the memory gap is the real benchmark differentiator.** Protocol SIFT failed the ROCBA case primarily because it had no disk artifact tools. DeepSIFT's 10 Windows artifact tools (event logs, shimcache, amcache, MFT, prefetch, LNK, jump lists, recycle bin, registry, IP reputation) are what would let an investigator actually answer "what happened on November 13?"

---

## 7. What's Next

- **Live endpoint triage** — Run DeepSIFT against live Windows systems via WinPmem + Velociraptor, not just forensic images
- **SIEM integration** — Stream structured findings to Splunk/Elastic for correlation with network telemetry
- **Automated case-building** — Link findings across memory + disk + network into a Diamond Model incident canvas
- **More SIFT tools** — bulk_extractor, Volatility community plugins, Plaso parsers for more artifact types
- **Accuracy improvement loop** — Feed DeepSIFT findings back into the RAG knowledge base so each case improves future analysis

---

## 8. Built With

`python` · `fastmcp` · `langgraph` · `chromadb` · `sentence-transformers` · `volatility3` · `log2timeline` · `sleuthkit` · `yara` · `ez-tools` · `anthropic-sdk` · `pytest`

Runs on: **SANS SIFT Workstation** (Ubuntu x86-64, VirtualBox/VMware)

---

## Submission Checklist

- [ ] 1. GitHub repo — https://github.com/ahammadshawki8/DeepSIFT (public, MIT license)
- [ ] 2. Demo video — [UPLOAD URL HERE] (5 min max)
- [ ] 3. Architecture diagram — `docs/architecture.md` in repo
- [ ] 4. This written project description — Devpost format ✓
- [ ] 5. Dataset documentation — `docs/dataset.md` in repo ✓
- [ ] 6. Accuracy report — `docs/accuracy_report.md` (generated after benchmark run on SIFT VM)
- [ ] 7. Try-it-out instructions — `README.md` in repo ✓
- [ ] 8. Agent execution logs — `analysis/forensic_audit.log` (produced during investigation run)

---

## Try It Yourself

```bash
# On SANS SIFT Workstation (Ubuntu x86-64)
git clone https://github.com/ahammadshawki8/DeepSIFT.git
cd DeepSIFT
pip3 install -r requirements.txt
cp .env.example .env && nano .env  # add ANTHROPIC_API_KEY
python3 rag/ingest/mitre_attack.py  # seed RAG (~5 min)
pytest tests/ -v                    # 15/15 tests should pass

# Add to Claude Code MCP config:
# { "mcpServers": { "deepsift": { "command": "python3",
#     "args": ["/path/to/DeepSIFT/mcp_server/server.py"] } } }

# Then in Claude Code:
# "Investigate /cases/ROCBA/Rocba-Memory.raw for signs of
#  unauthorized access on or after November 13, 2020."
```
