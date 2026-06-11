# DeepSIFT

**AI-Driven Forensic Analysis with Zero Hallucinations**

DeepSIFT is a Python MCP (Model Context Protocol) middleware server that wraps SANS SIFT Workstation forensic tools, dramatically reducing LLM hallucinations in autonomous AI-driven incident response.

Built for the **[Find Evil! Hackathon](https://devpost.com/software/find-evil)** hosted by SANS DFIR.

---

## The Problem

[Protocol SIFT](https://github.com/teamdfir/protocol-sift) connects Claude Code to SIFT Workstation but hallucinates more than acceptable:

| Protocol SIFT Problem | DeepSIFT Solution |
|----------------------|-------------------|
| Raw Volatility output (10k+ lines) dumped into context | Python parsers convert output to structured JSON first |
| Generic `execute_shell_cmd` — agent guesses plugin names | Typed MCP functions — one function per tool action |
| Prompt-only safety ("never modify evidence") | Architectural enforcement — zero write ops on evidence paths |
| No threat intelligence context | RAG pipeline injects MITRE ATT&CK + IOCs into every finding |

---

## Architecture

```
Claude Code (autonomous execution engine)
        ↓ calls typed MCP functions
DeepSIFT MCP Server  ←── RAG Pipeline (ChromaDB + MITRE ATT&CK)
        ↓ executes and parses raw output
SIFT Tools (volatility, log2timeline, sleuthkit, yara, ez tools)
        ↑ structured JSON returned — raw text never reaches LLM
```

---

## Available MCP Tools

### Memory Forensics (Volatility 3)
| Tool | Description |
|------|-------------|
| `get_process_list` | Process list with Hunt Evil baseline (31 procs), masquerade detection, MITRE tags |
| `scan_hidden_processes` | **DKOM rootkit detection** — pslist vs psscan diff → T1014 |
| `find_injected_code` | Malfind with injection type classification (shellcode/PE/hollowing) + MITRE tags |
| `get_running_services` | svcscan with suspicious binary path detection → T1543.003 |
| `get_network_connections` | Netscan with external IP flagging + MITRE tags per connection |
| `get_command_history` | Cmdline with suspicious pattern detection + MITRE tags |
| `get_loaded_dlls` | DLL list with path-based suspicion scoring |
| `get_registry_hives` | Registry hive list from memory |
| `get_registry_key` | Read specific registry key values |
| `get_handles` | Open handles (files, mutexes, pipes) |
| `finish_analysis` | Save final structured findings with MITRE technique summary |

### Timeline (log2timeline / Plaso)
| Tool | Description |
|------|-------------|
| `create_super_timeline` | Create Plaso storage from disk image |
| `filter_timeline` | Extract events for a time window |
| `get_browser_history` | WEBHIST events only |

### Disk Forensics (Sleuth Kit)
| Tool | Description |
|------|-------------|
| `get_partition_table` | Partition layout via mmls |
| `get_file_listing` | File system tree via fls |
| `extract_file` | Extract file by inode via icat |
| `search_deleted_files` | Deleted/unallocated files |

### YARA Hunting
| Tool | Description |
|------|-------------|
| `scan_file_with_yara` | Scan file with rule set |
| `scan_memory_with_yara` | Scan memory image via yarascan |
| `list_yara_rule_sets` | Show available rules |

### Windows Artifacts (EZ Tools)
| Tool | Description |
|------|-------------|
| `parse_event_logs` | EVTX parsing — logon (4624/4625/4672), service (7045), tasks (4698), PowerShell (4104), WMI (5861), RDP (4778) |
| `parse_shimcache` | AppCompatCache — executable existence proof from SYSTEM hive |
| `parse_amcache` | Amcache.hve — SHA1 hash + first-run time per executable |
| `parse_mft` | $MFT — full file system with timestamp anomaly detection |
| `parse_prefetch` | Prefetch — program execution history (last 8 run times) |
| `parse_lnk_files` | LNK shortcut files — recently accessed file paths |
| `parse_jump_lists` | Jump Lists — application-specific recent file activity |
| `parse_recycle_bin` | $Recycle.Bin — deleted file recovery with deletion timestamps |
| `parse_registry_hive` | Offline registry hive parsing with keyword search |
| `lookup_ip_reputation` | AbuseIPDB + VirusTotal threat intelligence |

---

## Prerequisites

- **[SANS SIFT Workstation](https://sans.org/tools/sift-workstation)** (Ubuntu x86-64)
- Python 3.10+
- Volatility 3 (`python3 -m volatility3`)
- log2timeline / Plaso (`log2timeline.py`, `psort.py`)
- The Sleuth Kit (`fls`, `mmls`, `icat`)
- YARA
- EZ Tools at `/opt/zimmermantools/` (optional — Windows artifact tools)

---

## Installation

```bash
# Clone the repo
git clone https://github.com/ahammadshawki8/DeepSIFT.git
cd DeepSIFT

# Install Python dependencies
pip3 install -r requirements.txt

# Configure environment
cp .env.example .env
nano .env  # Add your API keys and verify tool paths

# Initialize RAG knowledge base (downloads ~100MB MITRE ATT&CK JSON)
python3 rag/ingest/mitre_attack.py

# Run tests to verify parsers work
pytest tests/ -v
```

---

## Quick Start — Investigate a Memory Image

### Option A: One-Command Demo Script

```bash
# Memory-only investigation (3 steps: seed RAG → run → generate report)
python3 demo.py --image /cases/ROCBA/Rocba-Memory.raw

# Full investigation with disk artifact analysis
python3 demo.py \
  --image /cases/ROCBA/Rocba-Memory.raw \
  --evidence-mount /mnt/evidence

# With Protocol SIFT baseline comparison (generates HTML accuracy report)
python3 demo.py \
  --image /cases/ROCBA/Rocba-Memory.raw \
  --baseline /cases/ROCBA-BASELINE/analysis/findings.json
```

### Option C: Use with Claude Code (Claude Code MCP)

1. Add to your Claude Code MCP configuration:

```json
{
  "mcpServers": {
    "deepsift": {
      "command": "python3",
      "args": ["/path/to/DeepSIFT/mcp_server/server.py"]
    }
  }
}
```

2. Start an investigation:
```
Investigate /cases/ROCBA/Rocba-Memory.raw for signs of unauthorized access
on or after November 13, 2020.
```

Claude will automatically call `get_process_list` → `find_injected_code` → 
`get_network_connections` → `finish_analysis` and produce a structured report.

### Option D: Multi-Agent Orchestrator (LangGraph)

```bash
python3 agents/orchestrator.py --image /cases/ROCBA/Rocba-Memory.raw --case-dir /cases/ROCBA
```

---

## Run Benchmark

Compare DeepSIFT against Protocol SIFT baseline:

```bash
python3 benchmark/runner.py \
  --baseline /cases/ROCBA-BASELINE \
  --ours /cases/ROCBA-DEEPSIFT \
  --ground-truth benchmark/ground_truth/rocba_ground_truth.json \
  --output docs/accuracy_report.md
```

---

## Configuration

Copy `.env.example` to `.env`:

```env
ANTHROPIC_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here      # optional — enables IP reputation
ABUSEIPDB_API_KEY=your_key_here       # optional — enables IP reputation

# Override tool paths if different from SIFT defaults
VOLATILITY_CMD=python3 -m volatility3
LOG2TIMELINE_CMD=log2timeline.py
EZ_TOOLS_DIR=/opt/zimmermantools

# Case directories
CASE_DIR=/cases
EXPORTS_DIR=./exports
ANALYSIS_DIR=./analysis
```

---

## Chain of Custody

Every tool execution is logged to `analysis/forensic_audit.log`:

```json
{
  "timestamp": "2026-06-10T12:34:56.789Z",
  "tool": "get_process_list",
  "command": "python3 -m volatility3 -f /cases/ROCBA/Rocba-Memory.raw windows.pslist",
  "raw_output_sha256": "abc123...",
  "raw_output_file": "./exports/get_process_list_2026-06-10T12-34-56.txt"
}
```

Raw outputs are preserved in `exports/` for audit trail purposes.

---

## License

MIT License — see [LICENSE](LICENSE)

---

## Acknowledgments

- [SANS DFIR](https://sans.org/dfir) — SIFT Workstation and FOR508 Hunt Evil poster
- [MITRE ATT&CK](https://attack.mitre.org/) — threat intelligence framework
- [Protocol SIFT](https://github.com/teamdfir/protocol-sift) — baseline this project improves upon
- [Volatility Foundation](https://volatilityfoundation.org/) — Volatility 3
