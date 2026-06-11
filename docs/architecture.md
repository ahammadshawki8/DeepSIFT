# DeepSIFT — Architecture

## System Overview

DeepSIFT is a Python middleware server that sits between Claude Code and the SANS SIFT
Workstation forensic toolchain. Its core function is to prevent hallucinations by ensuring
raw tool output never reaches the LLM — structured JSON goes in, structured JSON comes out.

---

## Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Claude Code (Investigator)                       │
│  calls typed MCP functions — cannot call raw shell, cannot guess params  │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │ MCP protocol (stdio / SSE)
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     DeepSIFT MCP Server (server.py)                      │
│                                                                          │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐  │
│  │  Volatility  │  │ log2timeline │  │ Sleuth Kit   │  │  EZ Tools   │  │
│  │  9 tools     │  │  3 tools     │  │  4 tools     │  │  10 tools   │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘  │
│         │                 │                  │                 │         │
│         └─────────────────┴──────────────────┴─────────────────┘        │
│                                    │                                     │
│                           ┌────────▼──────────┐                         │
│                           │   Raw Output       │                         │
│                           │   Parsers          │                         │
│                           │                    │                         │
│                           │  pslist_parser.py  │ ← 31 KNOWN_NORMAL procs │
│                           │  netscan_parser.py │ ← external IP flagging  │
│                           │  malfind_parser.py │ ← injection type classif│
│                           │  timeline_parser.py│ ← suspicious keywords   │
│                           └────────┬──────────┘                         │
│                                    │ structured JSON                     │
│                           ┌────────▼──────────┐                         │
│                           │   RAG Enrichment   │                         │
│                           │   (query.py)       │                         │
│                           └────────┬──────────┘                         │
│                                    │ JSON + threat intel context         │
└────────────────────────────────────┼────────────────────────────────────┘
                                     │
                    returned to Claude Code as structured JSON
                    (raw text never reaches the LLM)
```

---

## RAG Pipeline

```
┌─────────────────────────────────────────────────────────┐
│                  RAG Knowledge Base                      │
│                                                          │
│  ChromaDB (PersistentClient)                            │
│  Embedding model: all-MiniLM-L6-v2                      │
│                                                          │
│  ┌───────────────────────────────────────────────────┐  │
│  │ Collection: forensic_knowledge                    │  │
│  │                                                   │  │
│  │ Source 1: MITRE ATT&CK (all 700+ techniques)      │  │
│  │   → indexed by TID, tactic, platform              │  │
│  │                                                   │  │
│  │ Source 2: Threat Intel                            │  │
│  │   → IOC CSVs, AbuseIPDB blacklists, APT groups   │  │
│  │                                                   │  │
│  │ Source 3: Case History                            │  │
│  │   → previous findings.json files from past cases │  │
│  └───────────────────────────────────────────────────┘  │
│                                                          │
│  Query flow:                                             │
│  1. Tool finds suspicious process / IP / technique       │
│  2. rag.query("suspicious finding text") called          │
│  3. Top-3 semantically relevant ATT&CK techniques        │
│     injected into JSON result before Claude sees it      │
└─────────────────────────────────────────────────────────┘
```

---

## Multi-Agent LangGraph Orchestrator

```
                    ┌───────────────────┐
                    │  ForensicState    │
                    │  (shared graph    │
                    │   state)          │
                    └────────┬──────────┘
                             │
              ┌──────────────▼──────────────┐
              │        memory_agent          │
              │  get_process_list           │
              │  find_injected_code         │
              │  get_network_connections    │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │         disk_agent           │
              │  create_super_timeline      │
              │  parse_event_logs           │
              │  parse_prefetch             │
              │  parse_mft                  │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │        network_agent         │
              │  get_network_connections    │
              │  lookup_ip_reputation       │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │       synthesis_agent        │
              │  Cross-correlates findings  │
              │  Maps PIDs → connections    │
              │  Injects RAG threat intel   │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │        report_agent          │
              │  Writes findings.json       │
              │  Writes audit log           │
              └─────────────────────────────┘
```

---

## Evidence Integrity Trust Boundaries

```
╔══════════════════════════════════════════════════════════════╗
║  TRUST BOUNDARY — Evidence is read-only beyond this line     ║
╚══════════════════════════════════════════════════════════════╝

  ALLOWED (read)            FORBIDDEN (never exposed via MCP)
  ─────────────────         ──────────────────────────────────
  /cases/<name>/*.raw       dd, rm, mv on /cases/
  /cases/<name>/*.E01       write to /mnt/ or /media/
  /mnt/evidence/*           modify original forensic image
  /media/forensic/*         delete or truncate log files

  All tool calls are logged to analysis/forensic_audit.log
  Raw output is hashed (SHA-256) and saved to exports/
  Chain of custody is enforced by the MCP server, not prompts
```

---

## Tool Count Summary

| Category | Tools | Key Capability |
|----------|-------|----------------|
| Memory Forensics (Volatility 3) | 9 | Process list, code injection, network, registry, handles |
| Timeline (log2timeline) | 3 | Super timeline, filter, browser history |
| Disk Forensics (Sleuth Kit) | 4 | Partition table, file listing, extract, deleted files |
| YARA Hunting | 3 | File scan, memory scan, list rule sets |
| Windows Artifacts (EZ Tools) | 10 | Event logs, shimcache, amcache, MFT, prefetch, LNK, jump lists, recycle bin, registry, IP reputation |
| **Total** | **29** | |

---

## Data Flow: Why Hallucinations Drop

```
Protocol SIFT (baseline)         DeepSIFT (ours)
─────────────────────────        ──────────────────────────────
volatility pslist                volatility pslist
  → 200 lines of raw text          → parse_pslist()
  → dumped into context              → 31-process KNOWN_NORMAL check
  → LLM reads raw text               → masquerade detection (Levenshtein ≤2)
  → LLM guesses anomalies            → structured JSON with anomaly flags
                                   → RAG injects relevant ATT&CK techniques
                                   → LLM reads JSON with pre-computed flags

Result: LLM sees raw output      Result: LLM sees:
and must pattern-match           {
200 lines of tab-separated         "name": "svchost.exe",
text under token pressure.         "pid": 1234,
                                   "suspicious": true,
Hallucination rate: HIGH           "anomalies": ["Wrong parent: expected
                                     services.exe, got explorer.exe"],
                                   "mitre_context": "T1055 — Process
                                     Injection ..."
                                 }

                                 Hallucination rate: LOW
```

---

## Key Files

| File | Purpose |
|------|---------|
| `mcp_server/server.py` | FastMCP entry point — registers all 29 tools |
| `mcp_server/config.py` | Tool paths and environment variables |
| `mcp_server/audit.py` | Chain-of-custody logging (SHA-256 per call) |
| `mcp_server/parsers/pslist_parser.py` | KNOWN_NORMAL baseline (31 procs), masquerade detection |
| `mcp_server/parsers/netscan_parser.py` | External IP flagging, RFC-1918 detection |
| `mcp_server/parsers/malfind_parser.py` | Injection type classification (PE header, shellcode, etc.) |
| `mcp_server/parsers/timeline_parser.py` | Suspicious keyword detection in Plaso output |
| `mcp_server/tools/windows_artifacts.py` | 10 EZ Tools wrappers with suspicious path detection |
| `rag/knowledge_base.py` | ChromaDB + sentence-transformers setup |
| `rag/ingest/mitre_attack.py` | Downloads and indexes MITRE ATT&CK into ChromaDB |
| `rag/query.py` | Semantic search interface used by tool wrappers |
| `agents/orchestrator.py` | LangGraph StateGraph orchestrator |
| `benchmark/runner.py` | Runs Protocol SIFT baseline + DeepSIFT, scores both |
| `benchmark/scorer.py` | Scores findings vs ground truth, detects hallucinations |
| `benchmark/ground_truth/rocba_ground_truth.json` | ROCBA case answer key + Protocol SIFT baseline score |
