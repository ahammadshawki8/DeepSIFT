# DeepSIFT — CLAUDE.md

This file is read by Claude Code when running on the SANS SIFT Workstation VM.
It configures Claude's behavior for forensic investigations using DeepSIFT.

---

## Project Overview

DeepSIFT is a Python MCP middleware layer between Claude Code and SANS SIFT forensic tools.
It reduces hallucinations by parsing raw tool output into structured JSON before it reaches
the LLM, exposing typed functions instead of generic shell commands, and injecting RAG
threat intelligence context into every analysis step.

**Hackathon:** Find Evil! (SANS DFIR, Devpost) — Deadline: June 15, 2026

---

## Architecture

```
Claude Code (you)
    ↓ calls typed MCP functions only
DeepSIFT MCP Server (mcp_server/server.py)
    ↓ executes and parses raw output
SIFT Tools (volatility, log2timeline, sleuthkit, yara, ez tools)
    ↑ structured JSON returned — never raw text
RAG Pipeline (ChromaDB + MITRE ATT&CK + threat intel)
    ↑ injected into tool results before you see them
```

---

## How to Start an Investigation

### 1. Start the MCP server (in a separate terminal)
```bash
cd /path/to/deepsift
python3 mcp_server/server.py
```

### 2. Connect Claude Code to the MCP server
Add to your `~/.config/claude/claude.json` or project `.claude/settings.json`:
```json
{
  "mcpServers": {
    "deepsift": {
      "command": "python3",
      "args": ["/path/to/deepsift/mcp_server/server.py"]
    }
  }
}
```

### 3. Ask Claude to investigate
```
Investigate /cases/ROCBA/Rocba-Memory.raw for signs of unauthorized access
on or after November 13, 2020. Use DeepSIFT tools only.
```

---

## Investigation Workflow (FOLLOW THIS ORDER)

### Memory Image Investigation
1. `get_process_list(image_path)` — Always start here
2. `find_injected_code(image_path)` — If suspicious processes found
3. `get_network_connections(image_path)` — Identify C2 / exfiltration
4. `get_command_history(image_path)` — Find attacker commands
5. `get_loaded_dlls(image_path, pid)` — For specific suspicious PIDs
6. `lookup_ip_reputation(ip)` — For each external IP found
7. `get_registry_hives(image_path)` → `get_registry_key(...)` — Persistence
8. `finish_analysis(...)` — Call when sufficient evidence gathered

### Disk Image Investigation
1. `get_partition_table(image_path)` — Get partition offsets
2. `get_file_listing(image_path, offset)` — Browse file system
3. `search_deleted_files(image_path, offset)` — Anti-forensics check
4. `create_super_timeline(image_path, name)` → `filter_timeline(...)` — Timeline

### YARA Hunting
1. `list_yara_rule_sets()` — See available rules
2. `scan_memory_with_yara(image_path, rule_set)` — Scan memory
3. `scan_file_with_yara(file_path, rule_set)` — Scan extracted files

---

## Hard Rules (Enforced Architecturally)

1. **Use ONLY DeepSIFT MCP tools** — never call `execute_shell_cmd`, `run_command`,
   or any raw shell execution tool. The MCP server is the only interface to SIFT tools.

2. **Evidence is read-only** — never call tools that write to `/cases/`, `/mnt/`, or
   `/media/` paths. If a tool errors because it tries to write evidence, stop immediately.

3. **Maximum 10 tool calls** — if you reach 10 calls without calling `finish_analysis`,
   call it immediately with `confidence: "low"` and your best partial findings.

4. **Never fabricate** — if a tool returns no results, report "no results found".
   Do not invent process names, IP addresses, file names, or timestamps.

5. **All findings must trace to a tool call** — every claim in your report must name
   which tool returned it. "Found in `get_process_list` output" is required.

---

## Evidence Integrity

Every tool call is automatically logged to `./analysis/forensic_audit.log` with:
- Timestamp (UTC)
- Command executed
- SHA-256 hash of raw output
- Path to raw output saved in `./exports/`

Do not delete, modify, or ignore this audit log.

---

## Self-Correction Protocol

| Situation | Action |
|-----------|--------|
| Tool returns error | Retry once with corrected parameters. If error persists, skip and note in report. |
| Finding seems inconsistent | Run a second tool to verify before including in report. |
| Confidence is low | Run 1-2 additional verification steps, then call `finish_analysis` with `confidence: "low"`. |
| Max iterations reached | Call `finish_analysis` immediately with partial findings. |

---

## MITRE ATT&CK Mapping

When you identify suspicious activity, map it to ATT&CK techniques:

| Finding | Technique |
|---------|-----------|
| Process injection (malfind PE header) | T1055 — Process Injection |
| Suspicious cmdline encoding | T1059.001 — PowerShell |
| Registry persistence | T1547.001 — Registry Run Keys |
| C2 network connection | T1071 — Application Layer Protocol |
| Credential dumping (lsass access) | T1003.001 — LSASS Memory |
| Timestomping / deleted files | T1070 — Indicator Removal |

---

## Project Status

### Completed
- [x] MCP server core (mcp_server/server.py)
- [x] Volatility 3 tool wrappers (8 tools)
- [x] log2timeline/psort wrappers (3 tools)
- [x] Sleuth Kit wrappers (4 tools)
- [x] YARA hunting wrappers (3 tools)
- [x] Windows artifact tools — EZ Tools, IP reputation (5 tools)
- [x] pslist_parser with SANS Hunt Evil baseline + masquerade detection
- [x] netscan_parser with external IP flagging
- [x] malfind_parser with injection type classification
- [x] timeline_parser with suspicious keyword detection
- [x] RAG knowledge base (ChromaDB + sentence-transformers)
- [x] MITRE ATT&CK ingestion pipeline
- [x] Threat intel and case history ingestion
- [x] Benchmark runner and scorer
- [x] LangGraph multi-agent orchestrator (memory + disk + network agents)
- [x] Parser unit tests

### In Progress / TODO
- [ ] Run Protocol SIFT baseline on ROCBA image → document hallucinations
- [ ] Test MCP server on SIFT VM with real Volatility output
- [ ] Ingest MITRE ATT&CK into ChromaDB (`python3 rag/ingest/mitre_attack.py`)
- [ ] Run DeepSIFT against ROCBA image
- [ ] Generate benchmark comparison report
- [ ] Create architecture diagram (docs/architecture.md)
- [ ] Record demo video
- [ ] Write Devpost submission

---

## File Structure

```
DeepSIFT/
├── mcp_server/          ← MCP server + tool wrappers + parsers
│   ├── server.py        ← Entry point: python3 mcp_server/server.py
│   ├── config.py        ← Tool paths and environment config
│   ├── audit.py         ← Chain-of-custody logging
│   ├── tools/           ← One module per tool category
│   └── parsers/         ← Raw output parsers (the middleware magic)
├── rag/                 ← ChromaDB + threat intel
│   ├── knowledge_base.py
│   ├── query.py
│   └── ingest/          ← MITRE ATT&CK, IOCs, case history
├── benchmark/           ← Scoring vs Protocol SIFT baseline
├── agents/              ← LangGraph multi-agent orchestrator
├── tests/               ← pytest unit tests for parsers
├── analysis/            ← findings.json + forensic_audit.log (runtime)
├── exports/             ← raw tool outputs (runtime)
└── yara_rules/          ← .yar rule files
```

---

## Environment Setup (SIFT VM)

```bash
# Install Python dependencies
pip3 install -r requirements.txt

# Copy and configure environment
cp .env.example .env
nano .env  # Add API keys, verify tool paths

# Initialize RAG knowledge base
python3 rag/ingest/mitre_attack.py

# Run tests
pytest tests/

# Start MCP server
python3 mcp_server/server.py
```

---

## Key Paths on SIFT Workstation

```
Volatility 3:     python3 -m volatility3
log2timeline:     log2timeline.py
psort:            psort.py
fls/mmls/icat:    /usr/bin/
EZ Tools:         /opt/zimmermantools/
Cases:            /cases/<CASE_NAME>/
```
