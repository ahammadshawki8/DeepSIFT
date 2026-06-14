# DeepSIFT — CLAUDE.md

This file is read by Claude Code when running on the SANS SIFT Workstation VM.
It configures Claude's behavior for forensic investigations using DeepSIFT.

---

## Project Overview

DeepSIFT is a Python MCP middleware layer between Claude Code and SANS SIFT forensic tools.
It reduces hallucinations by parsing raw tool output into structured JSON before it reaches
the LLM, exposing typed functions instead of generic shell commands, and injecting RAG
threat intelligence context into every analysis step.

**148 typed MCP functions · 23 tool modules · 15 parser modules · Per-finding RAG enrichment**

**Status:** Production-ready — every tool runs a real forensic binary/parser (no demo/simulation/
placeholder paths), no evidence path is hard-coded, EZ Tools runs are case-isolated, and the RAG
corpus ships case-agnostic. Originally built for the Find Evil! (SANS DFIR, Devpost) challenge.

---

## Architecture

```
Claude Code (you)
    ↓ calls typed MCP functions only
DeepSIFT MCP Server (mcp_server/server.py)
    ↓ executes and parses raw output
SIFT Tools (volatility, log2timeline, sleuthkit, yara, ez tools, bulk_extractor, capa, FLOSS, hayabusa)
    ↑ structured JSON returned — never raw text
Middleware Parsers (15 modules — pslist, netscan, malfind, timeline, browser, cloud, document, network_log, linux, mitre_auto_map, rag_enrichment, grounding_verifier, confidence_scorer, forensic_knowledge)
    ↑ RAG enrichment injected per suspicious finding (ChromaDB + MITRE ATT&CK)
    ↑ Forensic knowledge envelope wraps every response (caveats, advisories, corroboration)
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
1. `get_process_list(image_path)` — Always start here; returns Hunt Evil baseline comparison + MITRE tags
2. `scan_hidden_processes(image_path)` — DKOM rootkit detection (pslist vs psscan diff → T1014)
3. `find_injected_code(image_path)` — Malfind with injection type + MITRE tags per finding
4. `get_running_services(image_path)` — svcscan with suspicious path detection (T1543.003)
5. `get_network_connections(image_path)` — Netscan with external IP flagging + MITRE tags
6. `get_command_history(image_path)` — Cmdline with suspicious pattern detection + MITRE tags
7. `get_loaded_dlls(image_path, pid)` — For specific suspicious PIDs
8. `lookup_ip_reputation(ip)` — For each external IP found
9. `get_registry_hives(image_path)` → `get_registry_key(...)` — Persistence
10. `finish_analysis(...)` — Call when sufficient evidence gathered

### Disk Image Investigation
1. `get_partition_table(image_path)` — Get partition offsets
2. `get_file_listing(image_path, offset)` — Browse file system
3. `search_deleted_files(image_path, offset)` — Anti-forensics check
4. `create_super_timeline(image_path, name)` → `filter_timeline(...)` — Timeline

### Windows Artifact Investigation (EZ Tools — evidence mount required)
1. `parse_event_logs(evtx_dir)` — Security/System event logs (logon, services, tasks, PS, WMI, RDP)
2. `parse_shimcache(system_hive)` — Executable existence history from SYSTEM hive
3. `parse_amcache(amcache_path)` — Executable run history with SHA1 hashes
4. `parse_prefetch(prefetch_dir)` — Execution history with last 8 run times
5. `parse_mft(mft_path)` — File system timeline; detects timestamp anomalies
6. `parse_lnk_files(lnk_dir)` — Recently accessed files via LNK shortcuts
7. `parse_jump_lists(jumplist_dir)` — Application-specific recent file access
8. `parse_recycle_bin(recycle_bin_path)` — Deleted file recovery metadata
9. `parse_srum(srum_path)` — System Resource Usage Monitor (network usage per process)
10. `parse_registry_hive(hive_path, pattern)` — Raw registry key/value search

### Extended Registry Investigation
1. `parse_shellbags(ntuser_hive)` — Folder access history (even deleted folders)
2. `parse_bam_dam(system_hive)` — Background Activity Monitor — last run times
3. `parse_run_mru(ntuser_hive)` — Run dialog history (T1059)
4. `parse_installed_software(software_hive)` — Installed software including RATs
5. `parse_wordwheelquery(ntuser_hive)` — Explorer search history
6. `parse_sam_users(sam_hive)` — Local user account details

### Browser Artifact Investigation
1. `parse_chrome_history(profile_dir)` — Chrome URL/visit/download history
2. `parse_firefox_history(profile_dir)` — Firefox history and downloads
3. `parse_edge_history(profile_dir)` — Edge browsing history
4. `parse_browser_downloads(profile_dir)` — Cross-browser download history
5. `parse_browser_extensions(profile_dir)` — Installed extensions (rogue extension detection)
6. `parse_browser_cookies(profile_dir)` — Session cookie analysis

### Email Artifact Investigation
1. `parse_pst_ost(email_file)` — Outlook PST/OST message extraction
2. `parse_thunderbird(profile_dir)` — Thunderbird message analysis
3. `parse_eml_files(eml_dir)` — Raw EML file analysis with header forensics
4. `analyze_email_headers(eml_path)` — SPF/DKIM/routing analysis

### Cloud Storage Investigation
1. `parse_dropbox_logs(log_dir)` — Dropbox sync activity and exfil detection
2. `parse_onedrive_logs(log_dir)` — OneDrive sync activity
3. `parse_googledrive_logs(log_dir)` — Google Drive activity
4. `parse_slack_artifacts(data_dir)` — Slack desktop client artifacts
5. `parse_teams_artifacts(data_dir)` — Microsoft Teams artifacts
6. `parse_icloud_artifacts(data_dir)` — iCloud activity

### Document Analysis Investigation
1. `analyze_pdf(file_path)` — PDF JavaScript/embedded object/exploit detection
2. `analyze_ole_vba(file_path)` — OLE macro + VBA code extraction
3. `analyze_rtf(file_path)` — RTF CLSID and exploit detection
4. `analyze_zip_archive(file_path)` — ZIP contents and embedded threat detection
5. `detect_dde(file_path)` — DDE formula injection in Office documents

### Linux Forensics Investigation
1. `get_linux_processes(image_path)` — Process list with attack pattern classification
2. `get_linux_network(image_path)` — Network connections (linux.netstat)
3. `get_bash_history(evidence_mount)` — Bash history with attack command detection
4. `get_linux_crontab(evidence_mount)` — Crontab entries (persistence T1053.003)
5. `get_linux_modules(image_path)` — Kernel module list with rootkit detection
6. `get_auth_logs(evidence_mount)` — Auth log brute-force and lateral movement detection
7. `get_syslog_events(evidence_mount)` — Syslog with attack keyword classification

### Network Analysis Investigation
1. `analyze_pcap(pcap_path)` — PCAP deep inspection (C2, exfil, lateral movement)
2. `analyze_dns_logs(log_path)` — DNS query analysis (tunneling, DGA detection)
3. `analyze_arp_cache(image_path)` — ARP table for lateral movement
4. `parse_zeek_logs(log_dir)` — Zeek/Bro log analysis
5. `parse_web_server_logs(log_path)` — IIS/Apache access log analysis (web shell detection)
6. `parse_firewall_logs(log_path)` — Firewall log review
7. `parse_netflow(flow_path)` — NetFlow data for exfiltration volume analysis

### Anti-Forensics Detection
1. `detect_timestomping(evidence_mount)` — MACB timestamp manipulation (T1070.006)
2. `detect_log_wiping(evidence_mount)` — Event log clearing detection (T1070.001)
3. `detect_secure_deletion(evidence_mount)` — SDelete/Eraser tool artifacts (T1070.004)
4. `detect_ads_streams(evidence_mount)` — NTFS alternate data streams (T1564.004)
5. `analyze_vss_shadows(evidence_mount)` — VSS shadow copy deletion (T1490)
6. `detect_prefetch_anomalies(evidence_mount)` — Suspicious prefetch patterns
7. `detect_event_log_tampering(evidence_mount)` — EVTX corruption/manipulation

### File Carving and Static Analysis
1. `run_bulk_extractor(image_path)` — Extract emails, URLs, domains from raw image
2. `detect_capabilities_capa(file_path)` — capa capability detection
3. `extract_floss_strings(file_path)` — FLOSS obfuscated string extraction
4. `get_file_type(file_path)` — Magic byte vs extension mismatch (T1036.005)
5. `analyze_pe_file(file_path)` — PE header, imports, exports, sections
6. `carve_files(image_path)` — File carving from raw image

### Threat Intelligence
1. `lookup_hash_reputation(file_hash)` — VirusTotal hash lookup
2. `lookup_domain_reputation(domain)` — VirusTotal + WHOIS domain check
3. `search_mitre_technique(technique_id)` — MITRE ATT&CK technique details
4. `search_ioc_database(query)` — Search RAG IOC database
5. `calculate_fuzzy_hash_similarity(file_a, file_b)` — ssdeep similarity

### YARA Hunting
1. `list_yara_rule_sets()` — See available rules
2. `scan_memory_with_yara(image_path, rule_set)` — Scan memory
3. `scan_file_with_yara(file_path, rule_set)` — Scan extracted files

### Hayabusa / Sigma
1. `run_hayabusa(evtx_dir)` — 3,700+ Sigma rules on EVTX logs
2. `list_hayabusa_profiles()` — List available detection profiles

### Correlation and Verification
1. `correlate_findings(findings_json)` — Cross-tool correlation of all findings
2. `adversarial_review(findings_json)` — Devil's advocate challenge of conclusions
3. `detect_contradictions(findings_json)` — Logical inconsistency detection across sources

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
| Service install (event 7045/4697) | T1543.003 — Windows Service |
| Scheduled task (event 4698/106) | T1053.005 — Scheduled Task |
| WMI persistence (event 5860/5861) | T1546.003 — WMI Event Subscription |
| Lateral movement via net/psexec | T1021.002 — SMB/Windows Admin Shares |
| Executable in temp dir (shimcache) | T1036.005 — Match Legitimate Name |
| PowerShell script block (event 4104) | T1059.001 — PowerShell |
| USB device artifact | T1052.001 — Exfiltration over USB |
| Cloud storage activity (browser/LNK) | T1567.002 — Exfiltration to Cloud Storage |
| Browser C2 download | T1105 — Ingress Tool Transfer |
| PDF/VBA macro execution | T1566.001 — Spearphishing Attachment |
| Rootkit (pslist vs psscan diff) | T1014 — Rootkit |
| NTFS ADS hidden data | T1564.004 — NTFS File Attributes |
| VSS shadow copy deletion | T1490 — Inhibit System Recovery |
| Log wiping / event log clear | T1070.001 — Clear Windows Event Logs |
| Secure deletion (SDelete) | T1070.004 — File Deletion |
| DNS tunneling | T1071.004 — DNS |
| Web shell (IIS/Apache logs) | T1505.003 — Web Shell |
| Kernel module rootkit | T1014 — Rootkit |
| Bash history attack commands | T1059.004 — Unix Shell |

---

## Project Status

### Completed
- [x] MCP server core (mcp_server/server.py) — 148 tools, 23 modules
- [x] Volatility 3 tool wrappers (34 tools across 3 modules)
- [x] log2timeline/psort wrappers (3 tools)
- [x] Sleuth Kit wrappers (4 tools)
- [x] Extended disk analysis (6 tools — slack space, integrity, mactime, ewfinfo)
- [x] YARA hunting wrappers (3 tools)
- [x] Hayabusa / Sigma wrappers (2 tools — 3,700+ Sigma rules)
- [x] Windows artifact tools — EZ Tools (16 tools)
  - [x] parse_prefetch, parse_lnk_files, parse_jump_lists, parse_registry_hive, lookup_ip_reputation
  - [x] parse_event_logs (EvtxECmd — logon/service/task/PS/WMI/RDP events)
  - [x] parse_shimcache (AppCompatCacheParser — execution evidence)
  - [x] parse_amcache (AmcacheParser — SHA1 hash per executable)
  - [x] parse_mft (MFTECmd — full file system with timestamp anomaly detection)
  - [x] parse_recycle_bin (RBCmd — deleted file recovery)
  - [x] parse_srum (SrumECmd — network usage per process)
- [x] Extended registry tools (10 tools — shellbags, BAM/DAM, MRU, wordwheel, SAM, USB)
- [x] Browser artifact tools (8 tools — Chrome, Firefox, Edge, extensions, downloads, cache)
- [x] Email artifact tools (5 tools — PST/OST, Thunderbird, EML, header forensics)
- [x] Cloud storage tools (6 tools — Dropbox, OneDrive, Google Drive, Slack, Teams, iCloud)
- [x] Document analysis tools (5 tools — PDF, OLE/VBA, RTF, ZIP, DDE)
- [x] Linux forensics tools (10 tools — processes, bash history, syslog, crontab, modules)
- [x] Network analysis tools (10 tools — PCAP, DNS, ARP, Zeek, IIS, Apache, firewall, netflow, RDP)
- [x] Anti-forensics detection (7 tools — timestomping, log wiping, ADS, VSS, prefetch, secure delete)
- [x] File carving and static analysis (11 tools — bulk_extractor, capa, FLOSS, PE, exiftool, carve)
- [x] Threat intelligence tools (5 tools — VT hash/domain, MITRE search, IOC DB, ssdeep)
- [x] Correlation tools (3 tools — correlate, adversarial review, contradiction detection)
- [x] pslist_parser — SANS Hunt Evil baseline (31 processes), masquerade detection
  - [x] Added: lsaiso.exe, fontdrvhost.exe, dwm.exe, sihost.exe, ctfmon.exe,
         WmiPrvSE.exe, audiodg.exe, SecurityHealthService.exe, MsMpEng.exe,
         ShellExperienceHost.exe, SearchUI.exe, userinit.exe, NisSrv.exe
- [x] netscan_parser with external IP flagging
- [x] malfind_parser with injection type classification
- [x] timeline_parser with suspicious keyword detection
- [x] browser_parser — cloud exfil domain classification + download risk scoring
- [x] cloud_parser — sync event risk scoring + volume threshold analysis
- [x] document_parser — PDF/OLE/RTF/DDE/ZIP malicious document classification
- [x] network_log_parser — web shell, SQLi, DNS tunneling, port scan detection
- [x] linux_parser — process, command, and syslog attack pattern classification
- [x] **mitre_auto_map.py** — rule-based MITRE ATT&CK auto-mapping (80+ rules, 19 categories)
  - [x] MITRE tags wired into all 23 tool modules
- [x] **rag_enrichment.py** — shared RAG enrichment: enrich_findings() + build_rag_summary()
  - [x] Per-finding RAG enrichment across all 148 tools
- [x] **grounding_verifier.py** — post-hoc verbatim token grounding check
- [x] **confidence_scorer.py** — 4-axis quantified confidence scoring (0-100)
- [x] **forensic_knowledge.py** — 148 per-tool caveats/advisories/corroboration entries
- [x] **scan_hidden_processes** — pslist vs psscan diff → DKOM rootkit detection (T1014)
- [x] **get_running_services** — svcscan with suspicious binary path detection (T1543.003)
- [x] RAG knowledge base (ChromaDB + sentence-transformers)
- [x] MITRE ATT&CK ingestion pipeline
- [x] Threat intel and case history ingestion
- [x] **Case-agnostic offline corpus** (`rag/ingest/knowledge_corpus.py`) — MITRE catalog + LOLBAS + Hunt Evil baseline; NO case IOCs auto-loaded
- [x] **Per-case IOC ingest** (`rag/ingest/case_history.py`, opt-in) — load a case's own IOCs only for that investigation, so one case never biases another. `rag/ingest/rocba_iocs.py` is an example pack (opt-in via `--load-rocba`).
- [x] **rag/ingest/run_all.py** — one-command RAG seeding script
- [x] Benchmark runner and scorer
- [x] **benchmark/vigia_runner.py** — standardized multi-case benchmark (vigia-cases)
- [x] **benchmark/reports/html_report.py** — rich visual HTML comparison (color-coded findings, MITRE badges, side-by-side diff)
- [x] LangGraph multi-agent orchestrator — memory + disk + network + browser agents
  - [x] disk_agent fully implemented (event logs, prefetch, shimcache, LNK files via EZ Tools)
  - [x] browser_agent implemented (Chrome history, downloads, cloud exfil classification)
- [x] **demo.py** — end-to-end deterministic pipeline (seed RAG → run investigation → generate report)
- [x] Unit tests (61 passing, 1 skipped)
- [x] docs/architecture.md, docs/dataset.md, docs/devpost_submission.md

### Completed — validation
- [x] **ROCBA (memory + disk):** DeepSIFT 4/4 (100%), Protocol SIFT 0/4, 0 hallucinations
- [x] **Vanko / FOR500 "Abducted Zebrafish" (disk-only):** DeepSIFT 4/4 (100%), Protocol SIFT 3/4,
      0 hallucinations, 100% claim grounding — uniquely recovered the zebrafish/cell-regeneration/
      DNA-splice subject matter via jump-list + shellbag analysis
- [x] RAG seeded offline (case-agnostic corpus) — works without network/torch

### Run modes
- **Agentic (senior-analyst):** `python3 investigate.py --image ... --evidence-mount ...` — LLM
  forms hypotheses, confirms/disproves them with confidence, picks tools, self-corrects, and builds
  the attack chain (`agents/reasoning_agent.py`, Anthropic tool-use over the 148 MCP tools; needs
  ANTHROPIC_API_KEY). Transcript -> `analysis/agent_transcript.json`.
- **Deterministic:** `python3 demo.py ...` — fixed pipeline, no LLM, for reproducible benchmarks.

### Guardrails (architectural, enforced in code)
- `mcp_server.audit.guard_command` blocks destructive/exfil binaries + shell redirection at every
  exec choke point (volatility `_run`, windows_artifacts `_run`, registry `_run_ez`); rejects
  shell-string commands. `guard_output_path` blocks writes to `/cases/`, `/mnt/`, `/media/`.

### EZ Tools / registry hardening (production-critical)
- **Cross-case isolation**: every EZ Tools wrapper clears its own CSV output dir before running
  (`_fresh_outdir`), so a prior case's CSVs (e.g. another profile's LNK history) are never re-read
  as the current case's findings.
- **Dirty hives**: RECmd/SbECmd always run with `--nl`. Live-acquired hives are routinely "dirty"
  and ship TxR `.blf` logs, not the `.LOG1/.LOG2` files those tools replay — without `--nl` they
  abort and silently return 0 rows.
- **Offline hives**: registry key paths resolve `ControlSet001` (acquired SYSTEM hives have no
  `CurrentControlSet`); single-key `--kn` dumps (which print to stdout, not CSV) are parsed from
  stdout into structured entries.
- **Decoding**: UserAssist is read from the decoded ValueData/ValueData2/ValueData3 columns (path /
  last-executed / run-count), not the raw ROT13 ValueName. SbECmd output (named per hive) is read by
  scanning every CSV it writes. EZ Tool resolution is case-insensitive (e.g. `SBECmd.dll`).

### SIFT-Linux runtime notes (important)
- **EZ Tools**: invoke as `dotnet /opt/zimmermantools/<Tool>.dll` (subdir-aware, e.g.
  `EvtxeCmd/EvtxECmd.dll`). PECmd may be absent → prefetch step no-ops gracefully.
- **Evidence mount**: read-only via kernel `ntfs3` (`losetup -fr` + `mount -t ntfs3 -o ro`); needed
  for NTFS volume images whose backup-boot sector is truncated (ntfs-3g refuses those).
- **Offline RAG**: `ForensicKnowledgeBase` falls back to an offline hashing embedder when
  torch/sentence-transformers or the model download is unavailable.
- **disk_agent**: parses curated evtx set (live channels + recent Security archives), date-stratified
  retention (≤120/day) so the incident window survives; clears its CSV output dir per run (avoids
  multi-GB stale-output re-reads); LNK targets per-user `Recent` folders; browser_agent covers ALL
  profiles of ALL browsers (Chrome/Edge/Brave + Firefox), auto-discovered from the mount.
- **Benchmark scorer**: `must_identify` uses content-based indicator groups + co-occurrence (artifact
  strings must appear together in one entry); prose mentions do not score. See
  `rocba_ground_truth.json._scoring_note`.

### Production readiness
- Every tool executes a real forensic binary or parser — no simulated, demo-only, or placeholder
  analysis paths anywhere in the product code.
- No evidence path is hard-coded: all image/hive/mount paths are supplied per invocation.
- The RAG knowledge base ships case-agnostic; per-case IOCs are opt-in (see above).
- Missing external tools (e.g. yara/hayabusa/capa/floss if not installed) degrade gracefully with a
  clear error rather than crashing — install them on the deployment host to enable those tools.

---

## File Structure

```
DeepSIFT/
├── mcp_server/          ← MCP server + tool wrappers + parsers
│   ├── server.py        ← Entry point: python3 mcp_server/server.py (148 tools)
│   ├── config.py        ← Tool paths and environment config
│   ├── audit.py         ← Chain-of-custody logging
│   ├── tools/           ← 23 modules (one per tool category)
│   │   ├── volatility.py              (12 tools)
│   │   ├── volatility_extended.py     (10 tools)
│   │   ├── volatility_advanced.py     (12 tools)
│   │   ├── windows_artifacts.py       (16 tools)
│   │   ├── registry_extended.py       (10 tools)
│   │   ├── browser_artifacts.py       (8 tools)
│   │   ├── email_artifacts.py         (5 tools)
│   │   ├── cloud_artifacts.py         (6 tools)
│   │   ├── document_analysis.py       (5 tools)
│   │   ├── linux_forensics.py         (10 tools)
│   │   ├── network_analysis.py        (3 tools)
│   │   ├── network_extended.py        (7 tools)
│   │   ├── anti_forensics.py          (7 tools)
│   │   ├── file_carving.py            (8 tools)
│   │   ├── file_analysis.py           (3 tools)
│   │   ├── disk_extended.py           (6 tools)
│   │   ├── threat_intel_extended.py   (5 tools)
│   │   ├── log2timeline.py            (3 tools)
│   │   ├── sleuthkit.py               (4 tools)
│   │   ├── yara_tools.py              (3 tools)
│   │   ├── hayabusa.py                (2 tools)
│   │   └── correlation.py             (3 tools)
│   └── parsers/         ← 15 middleware parser modules
│       ├── pslist_parser.py
│       ├── netscan_parser.py
│       ├── malfind_parser.py
│       ├── timeline_parser.py
│       ├── browser_parser.py
│       ├── cloud_parser.py
│       ├── document_parser.py
│       ├── network_log_parser.py
│       ├── linux_parser.py
│       ├── mitre_auto_map.py
│       ├── rag_enrichment.py
│       ├── grounding_verifier.py
│       ├── confidence_scorer.py
│       └── forensic_knowledge.py
├── rag/                 ← ChromaDB + threat intel
│   ├── knowledge_base.py
│   ├── query.py
│   └── ingest/          ← MITRE ATT&CK, IOCs, case history
├── benchmark/           ← Scoring vs Protocol SIFT baseline
├── agents/              ← LangGraph multi-agent orchestrator
├── tests/               ← pytest unit tests (32/32 passing)
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

# Initialize RAG knowledge base (one-command)
python3 rag/ingest/run_all.py

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
bulk_extractor:   bulk_extractor
capa:             capa
FLOSS:            floss
Hayabusa:         hayabusa
Cases:            /cases/<CASE_NAME>/
```
