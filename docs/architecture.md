# DeepSIFT — Architecture

## System Overview

DeepSIFT is a Python middleware server that sits between Claude Code and the SANS SIFT
Workstation forensic toolchain. Its core function is to prevent hallucinations by ensuring
raw tool output never reaches the LLM — structured JSON goes in, structured JSON comes out.

Every tool call flows through three layers:
1. **Middleware parser** — converts raw CLI output to a typed Python dict
2. **RAG enrichment** — injects per-finding threat intel from ChromaDB + MITRE ATT&CK
3. **Forensic knowledge envelope** — adds per-tool caveats, advisories, and corroboration hints

---

## Component Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Claude Code (Investigator)                       │
│  calls 148 typed MCP functions — cannot call raw shell, cannot guess     │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │ MCP protocol (stdio / SSE)
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     DeepSIFT MCP Server (server.py)                      │
│                       148 tools · 23 modules                             │
│                                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐  │
│  │  Volatility  │  │ log2timeline │  │ Sleuth Kit   │  │  EZ Tools   │  │
│  │  34 tools    │  │  3 tools     │  │  4 tools     │  │  16 tools   │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐  │
│  │  Browser /   │  │  Document    │  │  Linux /     │  │  Network    │  │
│  │  Email /     │  │  Analysis    │  │  Syslog      │  │  Extended   │  │
│  │  Cloud       │  │  5 tools     │  │  10 tools    │  │  7 tools    │  │
│  │  19 tools    │  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘  │
│  └──────┬───────┘         │                  │                 │         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐  │
│  │  Anti-       │  │  File        │  │  Registry    │  │  Disk /     │  │
│  │  Forensics   │  │  Carving     │  │  Extended    │  │  Threat     │  │
│  │  7 tools     │  │  8 tools     │  │  10 tools    │  │  Intel      │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │  11 tools  │  │
│         │                 │                  │          └──────┬──────┘  │
│         └─────────────────┴──────────────────┴─────────────────┘        │
│                                    │                                     │
│                           ┌────────▼──────────┐                         │
│                           │  Middleware        │                         │
│                           │  Parsers (15)      │                         │
│                           │                    │                         │
│                           │  pslist_parser     │ ← 31 Hunt Evil procs    │
│                           │  netscan_parser    │ ← external IP flagging  │
│                           │  malfind_parser    │ ← injection type classif│
│                           │  timeline_parser   │ ← suspicious keywords   │
│                           │  browser_parser    │ ← cloud exfil domains   │
│                           │  cloud_parser      │ ← exfil risk scoring    │
│                           │  document_parser   │ ← PDF/VBA/RTF/DDE risk  │
│                           │  network_log_parser│ ← web shell/SQLi/DNS    │
│                           │  linux_parser      │ ← attack cmd patterns   │
│                           │  mitre_auto_map    │ ← 80+ rules, 19 groups  │
│                           │  rag_enrichment    │ ← shared enrichment API │
│                           └────────┬──────────┘                         │
│                                    │ structured JSON + MITRE tags        │
│                           ┌────────▼──────────┐                         │
│                           │   RAG Enrichment   │                         │
│                           │  per-finding query │                         │
│                           │  ChromaDB + MITRE  │                         │
│                           └────────┬──────────┘                         │
│                                    │ JSON + threat intel                 │
│                           ┌────────▼──────────┐                         │
│                           │  Forensic Knowledge│                         │
│                           │  Envelope          │                         │
│                           │  148 per-tool      │                         │
│                           │  caveats/advisories│                         │
│                           └────────┬──────────┘                         │
│                                    │ audit_id + SHA-256                  │
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
│  │ Source 1: MITRE ATT&CK (700+ techniques)          │  │
│  │   → indexed by TID, tactic, platform              │  │
│  │                                                   │  │
│  │ Source 2: Threat Intel (IOCs, AbuseIPDB, APTs)    │  │
│  │   → hostile IPs, malicious hashes, C2 domains     │  │
│  │                                                   │  │
│  │ Source 3: Case-Specific IOCs                      │  │
│  │   → ROCBA hostile IPs, MRC.exe, cloud exfil       │  │
│  │                                                   │  │
│  │ Source 4: Case History                            │  │
│  │   → prior findings.json from completed cases      │  │
│  └───────────────────────────────────────────────────┘  │
│                                                          │
│  Query flow (per suspicious finding):                    │
│  1. Tool finds suspicious process / IP / file / event    │
│  2. rag_enrichment.enrich_findings() called             │
│  3. query_fn(item) builds contextual query string        │
│  4. Top-2 semantically relevant docs injected into item  │
│  5. build_rag_summary() adds topic context to response   │
└─────────────────────────────────────────────────────────┘
```

---

## Multi-Agent LangGraph Orchestrator

```
                    ┌───────────────────┐
                    │  ForensicState    │
                    │  image_path       │
                    │  disk_image_path  │
                    │  evidence_mount   │
                    │  browser_dir      │
                    │  email_dir        │
                    └────────┬──────────┘
                             │
              ┌──────────────▼──────────────┐
              │        memory_agent          │
              │  get_process_list           │
              │  find_injected_code         │
              │  get_network_connections    │
              │  get_command_history        │
              │  scan_hidden_processes      │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │         disk_agent           │
              │  parse_event_logs           │
              │  parse_prefetch             │
              │  parse_shimcache            │
              │  parse_mft                  │
              │  parse_lnk_files            │
              │  parse_srum                 │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │        network_agent         │
              │  get_network_connections    │
              │  lookup_ip_reputation       │
              │  parse_zeek_logs            │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │       browser_agent          │
              │  parse_chrome_history       │
              │  parse_firefox_history      │
              │  parse_dropbox_logs         │
              │  parse_onedrive_logs        │
              └──────────────┬──────────────┘
                             │
              ┌──────────────▼──────────────┐
              │       synthesis_agent        │
              │  Cross-correlates findings  │
              │  Maps PIDs → connections    │
              │  Aggregates MITRE TIDs      │
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

## Middleware Parser Architecture

```
Raw CLI output
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  Category-specific parser module                     │
│                                                      │
│  browser_parser.py  → classify_url()                │
│                       classify_chrome_rows()         │
│                       classify_downloads()           │
│                                                      │
│  cloud_parser.py    → classify_sync_event()         │
│                       build_cloud_summary()          │
│                                                      │
│  document_parser.py → classify_pdf()                │
│                       classify_vba_macro()           │
│                       classify_rtf_clsid()           │
│                                                      │
│  network_log_parser → classify_web_log_entry()      │
│                       classify_dns_query()           │
│                       detect_port_scan()             │
│                                                      │
│  linux_parser.py    → classify_linux_process()      │
│                       classify_bash_command()        │
│                       classify_syslog_entries()      │
│                                                      │
│  mitre_auto_map.py  → map_finding_to_techniques()   │
│                       80+ rules · 19 categories     │
└────────────────────────────┬────────────────────────┘
                             │ typed dict with threat_flags
                             ▼
┌─────────────────────────────────────────────────────┐
│  rag_enrichment.py                                   │
│                                                      │
│  enrich_findings(rag, items, query_fn)              │
│    → per-item RAG query, max 20 enriched            │
│    → adds threat_intel + mitre_techniques           │
│                                                      │
│  build_rag_summary(rag, topic)                      │
│    → response-level context string                  │
└────────────────────────────┬────────────────────────┘
                             │ enriched dict
                             ▼
┌─────────────────────────────────────────────────────┐
│  forensic_knowledge.py · wrap_response()             │
│                                                      │
│  Injects per-tool:                                  │
│    caveats:       Known FP sources, limitations     │
│    advisories:    What NOT to conclude alone        │
│    corroboration: Specific follow-up tool calls     │
│    audit_id:      dsift-YYYY-MM-DD-XXXXXXXX         │
└─────────────────────────────────────────────────────┘
                             │ JSON string
                             ▼
                    Claude Code context
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
  Raw output is SHA-256 hashed and saved to exports/
  Chain of custody is enforced by the MCP server, not prompts
  guard_output_path() raises PermissionError at OS level
```

---

## Tool Count Summary

| Category | Module | Tools | Key Capability |
|----------|--------|-------|----------------|
| Memory Forensics Core | volatility.py | 12 | pslist, malfind, netscan, cmdline, registry, verify, finish |
| Memory Forensics Extended | volatility_extended.py | 10 | privileges, mutexes, VAD, LDR, SSDT, callbacks, filescan |
| Memory Forensics Advanced | volatility_advanced.py | 12 | modules, IRP hooks, hashdump, lsadump, clipboard, dump |
| Timeline | log2timeline.py | 3 | super timeline, filter, browser history |
| Disk Forensics | sleuthkit.py | 4 | partition, file listing, extract, deleted |
| Extended Disk | disk_extended.py | 6 | fsstat, ewfinfo, mactime, blkcat, slack, integrity |
| Windows Artifacts | windows_artifacts.py | 16 | event logs, shimcache, amcache, prefetch, MFT, LNK, SRUM |
| Extended Registry | registry_extended.py | 10 | shellbags, BAM/DAM, MRU, wordwheel, SAM, timeline |
| YARA Hunting | yara_tools.py | 3 | file scan, memory scan, list rule sets |
| Hayabusa / Sigma | hayabusa.py | 2 | 3,700+ Sigma rules, rule profile listing |
| Browser Artifacts | browser_artifacts.py | 8 | Chrome, Firefox, Edge, extensions, passwords, cache |
| Email Artifacts | email_artifacts.py | 5 | PST/OST, Thunderbird, EML, header forensics |
| Cloud Storage | cloud_artifacts.py | 6 | Dropbox, OneDrive, Google Drive, Slack, Teams, iCloud |
| Document Analysis | document_analysis.py | 5 | PDF, OLE/VBA, RTF, ZIP, DDE |
| Linux Forensics | linux_forensics.py | 10 | processes, bash history, syslog, crontab, modules |
| Network Extended | network_extended.py | 7 | Zeek, IIS, Apache, firewall, netflow, RDP bitmap |
| Static Analysis | file_analysis.py / file_carving.py | 11 | PE, strings, packer, capa, FLOSS, exiftool, bulk_extractor |
| Threat Intelligence | threat_intel_extended.py | 5 | VT hash/domain, MITRE search, IOC DB, ssdeep |
| Network Analysis | network_analysis.py | 3 | PCAP, DNS, ARP |
| Anti-Forensics | anti_forensics.py | 7 | timestomp, log wipe, ADS, VSS, prefetch anomalies |
| Correlation | correlation.py | 3 | correlate, adversarial review, contradictions |
| **Total** | **23 modules** | **148** | |

---

## Data Flow: Why Hallucinations Drop

```
Protocol SIFT (baseline)         DeepSIFT (ours)
─────────────────────────        ──────────────────────────────
volatility pslist                get_process_list()
  → 200 lines of raw text          → pslist_parser.py
  → dumped into context              → 31-process KNOWN_NORMAL check
  → LLM reads raw text               → masquerade detection (Levenshtein ≤2)
  → LLM guesses anomalies            → MITRE auto-map per finding
                                   → rag_enrichment.enrich_findings()
                                   → forensic_knowledge.wrap_response()

Result: LLM sees raw output      Result: LLM sees:
and must pattern-match           {
200 lines of tab-separated         "name": "svchost.exe",
text under token pressure.         "pid": 1234,
                                   "suspicious": true,
Hallucination rate: HIGH           "anomalies": ["Wrong parent"],
                                   "mitre_techniques": [{"id": "T1055"}],
                                   "threat_intel": "Relevant ATT&CK...",
                                   "caveats": ["pslist misses DKOM procs"],
                                   "corroboration": ["run scan_hidden_processes"]
                                 }

                                 Hallucination rate: LOW
```

---

## Key Files

| File | Purpose |
|------|---------|
| `mcp_server/server.py` | FastMCP entry point — registers all 148 tools |
| `mcp_server/config.py` | Tool paths and environment variables |
| `mcp_server/audit.py` | Chain-of-custody logging (SHA-256 per call) |
| `mcp_server/parsers/pslist_parser.py` | KNOWN_NORMAL baseline (31 procs), masquerade detection |
| `mcp_server/parsers/netscan_parser.py` | External IP flagging, RFC-1918 detection |
| `mcp_server/parsers/malfind_parser.py` | Injection type classification (PE header, shellcode, etc.) |
| `mcp_server/parsers/mitre_auto_map.py` | Rule-based MITRE ATT&CK mapping (80+ rules, 19 categories) |
| `mcp_server/parsers/rag_enrichment.py` | Shared RAG enrichment: enrich_findings(), build_rag_summary() |
| `mcp_server/parsers/browser_parser.py` | Browser URL / download threat classification |
| `mcp_server/parsers/cloud_parser.py` | Cloud sync exfiltration risk scoring |
| `mcp_server/parsers/document_parser.py` | PDF/OLE/RTF/DDE/ZIP malicious document classification |
| `mcp_server/parsers/network_log_parser.py` | Web shell, SQLi, DNS tunneling, port scan detection |
| `mcp_server/parsers/linux_parser.py` | Linux process/command/syslog attack pattern classification |
| `mcp_server/parsers/grounding_verifier.py` | Post-hoc verbatim token grounding check |
| `mcp_server/parsers/confidence_scorer.py` | 4-axis quantified confidence scoring (0-100) |
| `mcp_server/parsers/forensic_knowledge.py` | Per-tool caveats/advisories/corroboration (148 entries) |
| `rag/knowledge_base.py` | ChromaDB + sentence-transformers setup |
| `rag/ingest/mitre_attack.py` | Downloads and indexes MITRE ATT&CK into ChromaDB |
| `rag/ingest/run_all.py` | One-command RAG initialization |
| `agents/orchestrator.py` | LangGraph StateGraph multi-agent orchestrator |
| `benchmark/compare.py` | Case-agnostic side-by-side scoring (Protocol SIFT vs DeepSIFT) + HTML report |
| `benchmark/scorer.py` | Scores findings vs ground truth, detects hallucinations |
| `benchmark/vigia_runner.py` | vigia-cases standardized multi-case benchmark |
| `benchmark/ground_truth/rocba_ground_truth.json` | ROCBA case answer key + Protocol SIFT baseline score |
