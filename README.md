# DeepSIFT

**AI-Driven Forensic Investigation for SANS SIFT Workstation**

DeepSIFT is a Model Context Protocol (MCP) middleware layer that turns Claude into a
zero-hallucination digital forensics analyst. Instead of letting an LLM guess at raw CLI
output, DeepSIFT parses every SIFT tool response into structured JSON, injects per-tool
forensic discipline (caveats, advisories, corroboration hints), enriches findings with
MITRE ATT&CK tags and RAG-backed threat intelligence, and enforces chain-of-custody audit
logging before the LLM ever sees a single byte of evidence.

**148 typed MCP tools · 23 tool modules · 15 parser modules · Per-tool RAG enrichment · Post-hoc grounding verification · 4-axis quantified confidence scoring · 3,700+ Sigma rules via Hayabusa · 6-type contradiction detection · case-agnostic benchmark runner**

> **Status:** Production-ready. Every tool executes a real forensic binary or parser —
> no simulated, demo-only, or placeholder analysis paths. All evidence paths are supplied
> per invocation (nothing is hard-coded to a specific image), each EZ Tools run clears its
> own output directory to prevent cross-case contamination, dirty registry hives are parsed
> as-acquired, and the RAG knowledge base ships case-agnostic (case IOCs are opt-in, never
> auto-loaded). Originally built for the [Find Evil! — SANS DFIR](https://findevil.devpost.com/)
> challenge.

---

## Why DeepSIFT

Protocol SIFT (the prompt-only baseline) passes raw CLI output directly into LLM context,
relies on natural-language safety rules, and has no structured parsing. This creates three
failure modes that DeepSIFT eliminates architecturally:

| Problem | Protocol SIFT | DeepSIFT |
|---|---|---|
| Raw CLI output → hallucination | Volatility/log2timeline text enters context unparsed | Python parsers produce typed JSON — raw text never reaches the LLM |
| Safety via prompt → bypassable | "Do not write to /cases/" is a suggestion | `guard_output_path()` raises `PermissionError` at OS level |
| No context → generic analysis | LLM has no threat intel during tool execution | ChromaDB RAG + MITRE ATT&CK injected into every tool response |
| Unverifiable LLM claims | No grounding check — analyst must manually verify | `verify_findings` checks every claim token against raw export bytes |
| Qualitative confidence | "high/low" with no definition | 4-axis 0-100 score: Tool Reliability + Corroboration + IOC Specificity + MITRE Accuracy |
| No Sigma rule coverage | Raw event log text to LLM | Hayabusa 3,700+ Sigma rules → structured MITRE-tagged alerts |
| Contradictions ignored | No cross-artifact consistency check | `detect_contradictions` finds 6 contradiction types (DKOM, ghost PIDs, log wipes, etc.) |

---

## Architecture

```mermaid
flowchart TD
    A["Claude Code\n(LLM Agent)"] -->|"Typed MCP calls only\nno generic shell"| B

    B["DeepSIFT MCP Server\nmcp_server/server.py"]
    B -->|"Structured JSON only\nnever raw text"| A

    B --> C["Tool Modules\n23 modules · 148 typed functions"]
    C --> D["SIFT Tools\nVolatility · log2timeline · Sleuthkit\nEZ Tools · YARA · Hayabusa\nbulk_extractor · capa · FLOSS · exiftool"]
    D -->|"raw output"| E["Middleware Parsers\npslist · netscan · malfind · timeline\nbrowser · cloud · document · network_log\nlinux · mitre_auto_map · rag_enrichment"]
    E -->|"structured dict"| F["Forensic Knowledge Envelope\ncaveats · advisories · corroboration"]
    F -->|"enriched JSON"| B

    B --> G["RAG Pipeline\nChromaDB + sentence-transformers"]
    G --> H["Knowledge Sources (case-agnostic)\nMITRE ATT&CK · LOLBAS · Hunt Evil baseline\n+ opt-in per-case IOCs / threat intel"]
    H --> G

    B --> I["Audit Logger\naudit_id · SHA-256 · forensic_audit.log"]
    I --> J["exports/\nRaw tool output SHA-256 indexed\nanalysis/forensic_audit.log"]
```

---

## Tool Inventory

DeepSIFT exposes **148 typed MCP tools** across 18 categories. No `run_shell`, no
`execute_command` — every tool has a typed signature, a middleware parser, and returns
RAG-enriched structured JSON.

### Memory Forensics — Core (Volatility 3)

| Tool | Purpose | Key Output Fields |
|---|---|---|
| `get_process_list` | EPROCESS walk; SANS Hunt Evil baseline comparison | `suspicious`, `anomaly_details`, `mitre_techniques` |
| `scan_hidden_processes` | pslist vs psscan diff → DKOM detection (T1014) | `hidden_processes`, `dkom_suspected` |
| `find_injected_code` | malfind with injection type classification | `risk_level`, `injection_type`, `mitre_techniques` |
| `get_running_services` | svcscan with suspicious binary path detection (T1543.003) | `suspicious_services` |
| `get_network_connections` | netscan with external IP flagging + MITRE tags | `external_connections`, `mitre_techniques` |
| `get_command_history` | cmdline with suspicious pattern detection | `suspicious_cmdlines`, `mitre_techniques` |
| `get_loaded_dlls` | DLL listing for a specific PID | `dlls`, `unsigned_count` |
| `get_registry_hives` | List hives in memory image | `hives` |
| `get_registry_key` | Read a specific registry key from memory | `key`, `values` |

### Memory Forensics — Extended (Volatility 3)

| Tool | Purpose | Key Forensic Value |
|---|---|---|
| `get_privileges` | Token privilege enumeration per PID | SeDebugPrivilege on non-system process = T1134 |
| `get_mutexes` | Mutex object scan (mutantscan) | Malware-family mutex fingerprinting |
| `get_env_vars` | Process environment block variables | PATH hijacking, unusual TEMP locations |
| `get_vad_info` | Virtual Address Descriptor tree | Private RWX non-file-backed regions = injection staging |
| `get_ldrmodules` | Compare InLoad / InMem / InInit PEB lists | DLLs absent from all three = reflective injection (T1055.001) |
| `get_ssdt` | System Service Descriptor Table hooks | Non-ntoskrnl hooks = rootkit (T1014) |
| `get_callbacks` | Kernel callback registrations | Unknown driver callbacks = rootkit |
| `get_filescan` | FILE_OBJECT pool scan | Open handles to files not visible in process DLL list |
| `get_timeliner` | Memory-resident timestamp timeline | Process / DLL / registry chronology |
| `get_devicetree` | Kernel device tree | Hidden filter drivers, rootkit stack position |

### Timeline Analysis (log2timeline / Plaso)

| Tool | Purpose |
|---|---|
| `create_super_timeline` | Build a Plaso super-timeline from a disk image (long-running) |
| `filter_timeline` | Extract events for a specific time window; highlights suspicious keywords |
| `get_browser_history` | Extract WEBHIST events (URLs, downloads, searches) from timeline |

### Disk Forensics (Sleuth Kit)

| Tool | Purpose |
|---|---|
| `get_partition_table` | Read partition layout; returns sector offsets for follow-up calls |
| `get_file_listing` | Recursive file listing with deleted-file flags |
| `extract_file` | Extract file by inode number to `exports/` |
| `search_deleted_files` | List only deleted/unallocated entries |

### Windows Artifact Analysis (EZ Tools)

| Tool | Source Artifact | Key Evidence |
|---|---|---|
| `parse_event_logs` | .evtx via EvtxECmd | Logon, service install, task create, PS script blocks, WMI, RDP |
| `parse_shimcache` | SYSTEM hive via AppCompatCacheParser | Executable existence (proves file was on disk) |
| `parse_amcache` | Amcache.hve via AmcacheParser | Execution evidence + SHA1 hash per executable |
| `parse_prefetch` | C:\Windows\Prefetch via PECmd | Execution history with last 8 run times |
| `parse_mft` | $MFT via MFTECmd | Full file-system timeline; detects timestamp anomalies |
| `parse_lnk_files` | Recent Items via LECmd | Recently accessed file paths with timestamps |
| `parse_jump_lists` | AutomaticDestinations via JLECmd | Application-specific recent file access |
| `parse_registry_hive` | Any hive via RECmd | Raw key/value search with pattern matching |
| `parse_recycle_bin` | $Recycle.Bin via RBCmd | Deleted file recovery with original paths |
| `parse_srum` | SRUDB.dat via SrumECmd | Network bytes sent/received per application (exfil quantification) |
| `parse_usn_journal` | $UsnJrnl:$J via MFTECmd | File system change journal; burst deletion detection |
| `lookup_ip_reputation` | AbuseIPDB + VirusTotal APIs | Confidence score, country, ISP, VT malicious count |

### Windows Event Log — Hayabusa / Sigma

| Tool | Purpose | Key Output Fields |
|---|---|---|
| `parse_hayabusa` | Apply 3,700+ community Sigma rules to .evtx directory | `alerts`, `critical_count`, `mitre_techniques` |
| `list_hayabusa_rules` | Show available Hayabusa rule profiles | `profiles`, `rule_count` |

### Static File Analysis

| Tool | Purpose | Key Output Fields |
|---|---|---|
| `get_pe_metadata` | PE header, sections, imports, compile timestamp, entropy | `high_entropy_sections`, `suspicious_imports`, `timestamp_anomaly` |
| `extract_strings` | String extraction + IOC pattern scan (IPs, URLs, base64, registry) | `iocs_found`, `ioc_summary` |
| `detect_packer` | Entropy analysis + UPX/MPRESS/Themida signature detection | `verdict`, `overall_entropy`, `packer_signatures_found` |

### Network Traffic Analysis

| Tool | Purpose | Key Output Fields |
|---|---|---|
| `parse_pcap_summary` | TShark PCAP summary — top talkers, exfil signals | `large_transfers`, `external_conversations` |
| `extract_dns_queries` | DNS extraction — DGA detection, beaconing, DNS tunneling | `suspicious_domains`, `beaconing_candidates` |
| `parse_arp_cache` | Volatility netstat as host enumeration proxy | `unique_hosts_seen`, `hosts` |

### Cross-Artifact Correlation

| Tool | Purpose |
|---|---|
| `correlate_artifacts` | Join findings across memory/disk/network/registry by PID, path, IP, user |
| `adversarial_review` | Challenge current hypothesis with counter-arguments before `finish_analysis` |
| `detect_contradictions` | Find UNRESOLVED_CONTRADICTION findings: DKOM, ghost PIDs, log wipes, hidden services |

### Investigation Control

| Tool | Purpose |
|---|---|
| `verify_findings` | Verbatim token grounding check — every claim vs raw export bytes (run before `finish_analysis`) |
| `finish_analysis` | Structured report with grounding score, 4-axis confidence score, `audit_ids` citation |

### YARA Hunting

| Tool | Purpose |
|---|---|
| `list_yara_rule_sets` | Enumerate available rule sets |
| `scan_memory_with_yara` | Yarascan via Volatility 3 (finds memory-resident payloads) |
| `scan_file_with_yara` | Static file scan against named rule set |

**Built-in YARA rule sets:** `suspicious_strings` · `webshells` · `ransomware` · `rats` · `packers`

### Memory Forensics — Advanced (Volatility 3)

| Tool | Purpose | Key Output Fields |
|---|---|---|
| `get_modules` | Kernel module list; flags unsigned/suspicious drivers | `suspicious_modules`, `mitre_techniques`, `threat_intel` |
| `get_driverirp` | IRP dispatch table hook detection (rootkit) | `hooked_handlers`, `threat_intel` |
| `get_getsids` | Security identifiers per process (privilege enumeration) | `sids`, `admin_processes` |
| `get_hashdump` | NTLM password hash extraction from SAM in memory | `accounts`, `non_empty_hashes`, `threat_intel` |
| `get_lsadump` | LSA secrets from memory (service account passwords) | `secrets`, `threat_intel` |
| `get_cachedump` | Domain cached credential hashes (DCC2) | `cached_accounts` |
| `get_clipboard` | Clipboard contents at time of acquisition | `clipboard_text` |
| `get_atoms` | Windows atom table (GUI attack staging) | `atoms` |
| `get_sessions` | Terminal Services / RDP session list | `sessions`, `rdp_sessions` |
| `get_mft_memory` | In-memory MFT record extraction | `mft_records` |
| `get_ads_memory` | Alternate Data Stream detection from memory image | `ads_entries` |
| `dump_process` | Dump a suspicious process to disk for static analysis | `output_path`, `sha256` |

### Browser Artifacts

| Tool | Purpose | Key Output Fields |
|---|---|---|
| `parse_chrome_history` | SQLite history + downloads; cloud exfil domain classification | `suspicious_visits`, `suspicious_downloads`, `parser_summary`, `threat_intel` |
| `parse_firefox_history` | places.sqlite history + downloads; threat flags | `suspicious_visits`, `parser_summary`, `threat_intel` |
| `parse_chrome_extensions` | Installed extensions; flags risky permissions | `suspicious_extensions`, `high_risk_count` |
| `parse_browser_cookies` | Cookie store extraction; session token discovery | `cookies`, `suspicious_domains` |
| `run_hindsight` | Full Chrome/Chromium browser artifact extraction | `output_dir`, `summary` |
| `parse_browser_passwords` | Saved password store; credential theft evidence | `credentials`, `domain_count` |
| `parse_ie_edge_legacy_history` | IE/Edge Legacy WebCacheV01.dat history | `visits`, `downloads` |
| `parse_chromium_cache` | Chromium disk cache; cached malware delivery pages | `cache_entries`, `suspicious_urls` |

### Email Artifacts

| Tool | Purpose | Key Output Fields |
|---|---|---|
| `parse_pst_ost` | Outlook PST/OST via readpst; exfiltration email search | `email_count`, `suspicious_emails`, `attachments` |
| `parse_thunderbird` | Thunderbird mbox profile extraction | `emails`, `suspicious_emails` |
| `parse_eml_file` | Single .eml file; header analysis + attachment extraction | `headers`, `attachments`, `iocs` |
| `extract_email_attachments` | Bulk attachment extraction for malware analysis | `extracted_count`, `suspicious_attachments` |
| `analyze_email_headers` | RFC 5322 header forensics; spoofing + routing analysis | `spf_result`, `dkim_result`, `hop_analysis`, `mitre_techniques` |

### Cloud Storage Artifacts

| Tool | Purpose | Key Output Fields |
|---|---|---|
| `parse_dropbox_logs` | Dropbox sync logs; exfiltration risk classification | `sync_events`, `parser_summary`, `threat_intel` |
| `parse_onedrive_logs` | OneDrive sync/activity logs | `sync_events`, `parser_summary`, `threat_intel` |
| `parse_google_drive_logs` | Google Drive desktop sync logs | `sync_events`, `parser_summary` |
| `parse_slack_artifacts` | Slack desktop app data; workspace + channel forensics | `workspaces`, `suspicious_events` |
| `parse_teams_artifacts` | Microsoft Teams SQLite databases; chat + call forensics | `accounts`, `messages`, `suspicious_events` |
| `parse_icloud_logs` | iCloud for Windows sync logs | `sync_events`, `parser_summary` |

### Document Analysis

| Tool | Purpose | Key Output Fields |
|---|---|---|
| `analyze_pdf_doc` | pdfid keyword scan; JavaScript/OpenAction/launch classification | `risk_score`, `suspicious_keywords`, `mitre_techniques`, `threat_intel` |
| `analyze_ole_doc` | oletools VBA macro extraction + malicious pattern detection | `macros`, `classified_risks`, `mitre_techniques` |
| `analyze_rtf_doc` | rtfobj embedded object extraction; malicious CLSID detection | `objects`, `clsid_risks` |
| `analyze_zip_archive` | ZIP entry inspection; password-protected + double-ext detection | `entries`, `suspicious_entries` |
| `detect_dde_payload` | DDE/DDEAUTO command injection in Office documents | `dde_found`, `commands`, `threat_intel` |

### Linux / macOS Forensics

| Tool | Purpose | Key Output Fields |
|---|---|---|
| `get_linux_processes` | Volatility linux.pslist; attack command + LD_PRELOAD detection | `suspicious`, `threat_flags`, `threat_intel` |
| `get_linux_bash_history` | Bash command history with attack pattern classification | `commands`, `classified_suspicious`, `threat_intel` |
| `get_linux_network` | linux.netstat via Volatility | `connections`, `external` |
| `get_linux_modules` | Kernel module list; rootkit LKM detection | `modules`, `suspicious` |
| `get_linux_syscall` | System call table hook detection | `hooks` |
| `get_linux_malfind` | malfind equivalent for Linux memory images | `injected` |
| `get_linux_envars` | Process environment variables | `envars`, `suspicious` |
| `get_linux_mounts` | Mount table; network share + hidden mount detection | `mounts`, `suspicious` |
| `parse_syslog` | Syslog/auth.log parsing; auth failure + sudo classification | `classified_events`, `classified_summary`, `threat_intel` |
| `parse_linux_crontab` | Crontab persistence detection across all users | `cron_entries`, `suspicious_schedules` |

### Network Forensics — Extended

| Tool | Purpose | Key Output Fields |
|---|---|---|
| `parse_zeek_logs` | Zeek conn/dns/http/ssl/files log parsing; DNS tunneling detection | `suspicious_dns`, `external_conns`, `threat_intel` |
| `parse_iis_logs` | IIS W3C access logs; web shell + SQLi + scanner detection | `suspicious_requests`, `web_shells`, `threat_intel` |
| `parse_apache_logs` | Apache access/error logs; same threat classification | `suspicious_requests`, `port_scans` |
| `extract_pcap_files` | Extract files from PCAP via NetworkMiner/tshark | `extracted_files` |
| `parse_firewall_logs` | Firewall deny/allow logs; lateral movement flagging | `suspicious_flows`, `internal_scanning` |
| `decode_rdp_bitmap_cache` | RDP bitmap cache → screenshot reconstruction | `output_dir`, `image_count` |
| `parse_netflow` | NetFlow/IPFIX analysis; top talkers + exfil signals | `top_talkers`, `large_flows`, `exfil_candidates` |

### Anti-Forensics Detection

| Tool | Purpose | Key Output Fields |
|---|---|---|
| `detect_timestomping` | SI vs FN MACB delta comparison; round-number timestamps | `si_fn_delta_anomalies`, `mitre_techniques`, `threat_intel` |
| `detect_log_wiping` | Event ID 1102/104/4719; zero-byte EVTX detection | `log_clear_events`, `threat_intel` |
| `detect_secure_deletion` | SDelete/Eraser/CCleaner traces in prefetch + shimcache | `secure_deletion_indicators`, `threat_intel` |
| `detect_ads_streams` | NTFS Alternate Data Stream discovery | `suspicious_streams`, `threat_intel` |
| `analyze_vss_shadows` | Volume Shadow Copy inventory; deletion evidence | `shadow_copy_count`, `rag_context` |
| `detect_prefetch_anomalies` | Temp path execution + anti-forensics tool execution | `suspicious_entries`, `anti_forensics_tools` |
| `detect_event_log_tampering` | Event ID 1102/4719/7040 audit policy changes | `findings`, `threat_intel` |

### File Carving and Static Analysis

| Tool | Purpose | Key Output Fields |
|---|---|---|
| `run_bulk_extractor` | Bulk feature extraction: emails, URLs, IPs, CCNs, Base64 | `top_iocs`, `enriched_email_iocs`, `enriched_url_iocs` |
| `carve_files_foremost` | Header/footer file carving from unallocated space | `recovered_files_by_type`, `total_recovered` |
| `carve_files_scalpel` | Configurable signature-based file carving | `recovered_files_by_type` |
| `analyze_with_exiftool` | Metadata extraction (GPS, author, software, revision) | `interesting_fields`, `full_metadata` |
| `calculate_file_hashes` | MD5/SHA1/SHA256/SHA512 + ssdeep fuzzy hash | `hashes`, `ssdeep` |
| `detect_capabilities_capa` | capa: capability detection mapped to MITRE ATT&CK | `capabilities`, `mitre_techniques`, `threat_intel` |
| `extract_floss_strings` | FLOSS: XOR/stack/tight decoded string extraction | `decoded_strings`, `ioc_ips_in_decoded`, `threat_intel` |
| `get_file_type` | Magic byte vs extension mismatch (masquerade detection) | `extension_mismatch`, `mitre_techniques` |

### Extended Registry Forensics

| Tool | Purpose | Key Output Fields |
|---|---|---|
| `parse_shellbags` | Folder navigation history; deleted dir + USB + share access | `suspicious_path_accesses`, `threat_intel` |
| `parse_windows_timeline` | ActivitiesCache.db: app launches + file opens | `file_opens`, `app_launches` |
| `parse_bam_dam` | BAM/DAM last-execution timestamps per user SID | `suspicious_executions`, `threat_intel` |
| `parse_typed_paths` | Explorer address bar history; network share + admin share paths | `network_share_paths`, `removable_media_paths` |
| `parse_run_mru` | Run dialog (Win+R) execution history | `suspicious_run_commands`, `threat_intel` |
| `parse_open_save_mru` | Open/Save dialog recent file access | `entries` |
| `parse_wordwheelquery` | Windows Search query history; sensitive file discovery | `suspicious_searches`, `threat_intel` |
| `parse_installed_software` | Installed programs; RAT/hacking tool detection | `suspicious_software`, `threat_intel` |
| `parse_sam_hive` | Local user accounts and last logon info | `entries` |
| `parse_logon_history` | Cached domain credentials in SECURITY hive | `entries`, `forensic_note` |

### Extended Disk Forensics

| Tool | Purpose | Key Output Fields |
|---|---|---|
| `get_fs_statistics` | fsstat: block size, volume name, creation/mount timestamps | `fs_type`, `block_size`, `creation_time` |
| `get_image_info` | ewfinfo/mmls: image format, acquisition hash, partition table | `ewf_metadata`, `partition_table` |
| `create_mac_timeline` | mactime: body-file MAC(B) timeline generation | `total_timeline_entries`, `output_path` |
| `read_raw_block` | blkcat: hexdump specific sectors; magic byte detection | `hexdump`, `detected_structure` |
| `analyze_slack_space` | blkls: file slack space extraction + IOC scanning | `ips_in_slack`, `urls_in_slack`, `threat_intel` |
| `verify_image_integrity` | MD5/SHA256 + ewfverify chain-of-custody verification | `integrity_verified`, `chain_of_custody` |

### Threat Intelligence

| Tool | Purpose | Key Output Fields |
|---|---|---|
| `lookup_hash_reputation` | VirusTotal file hash lookup (MD5/SHA1/SHA256) | `detection_ratio`, `verdict`, `mitre_techniques`, `threat_intel` |
| `lookup_domain_reputation` | VirusTotal + WHOIS domain reputation check | `verdict`, `mitre_techniques`, `threat_intel` |
| `search_mitre_technique` | RAG query for MITRE ATT&CK technique details | `rag_results`, `static_knowledge` |
| `search_ioc_database` | Search all IOCs in the RAG knowledge base | `matches`, `match_count` |
| `calculate_fuzzy_hash_similarity` | ssdeep similarity between two files/hashes (malware variants) | `similarity_score`, `interpretation` |

---

## Hallucination Reduction Pipeline

```mermaid
flowchart LR
    A["Raw Tool Output\nVolatility / EZ Tools / etc."] --> B["Python Parser\nStructured dict"]
    B --> C["MITRE Auto-Map\nmap_process_anomalies\nmap_injection\nmap_network_connection"]
    C --> D["RAG Enrichment\nChromaDB query\nMITRE · threat intel · case IOCs"]
    D --> E["Forensic Knowledge Envelope\ncaveats · advisories · corroboration"]
    E --> F["audit_id\nSHA-256 of raw output\nTimestamp + export file path"]
    F --> G["Structured JSON\nto LLM Context"]
```

Every tool call generates a unique `audit_id` (e.g. `dsift-2026-06-11-a3f9b2c1`).
`finish_analysis` **requires** an `audit_ids` list — fabricated findings without a
traced audit_id are structurally impossible to submit.

---

## Investigation Workflow

### Memory Image

```mermaid
flowchart TD
    A["get_process_list\nHunt Evil baseline + MITRE tags"] --> B["scan_hidden_processes\nDKOM rootkit detection"]
    B --> C["find_injected_code\nmalfind injection classification"]
    C --> D["get_running_services\nsuspicious binary paths"]
    D --> E["get_network_connections\nexternal IP flagging"]
    E --> F["get_command_history\nsuspicious pattern detection"]
    F --> G["lookup_ip_reputation\nAbuseIPDB + VirusTotal"]
    G --> H["correlate_artifacts\ncross-source PID/path/IP joins"]
    H --> I["adversarial_review\nchallenge hypothesis"]
    I --> J["finish_analysis\nobservation + interpretation\naudit_ids required"]
```

### Windows Artifact Analysis

```mermaid
flowchart TD
    A["parse_event_logs\nlogon · service · task · PS · WMI · RDP"] --> B["parse_shimcache\nexecutable existence"]
    B --> C["parse_amcache\nSHA1 hash per executable"]
    C --> D["parse_prefetch\nexecution history x8 runs"]
    D --> E["parse_mft\nfull FS timeline + timestamp anomalies"]
    E --> F["parse_srum\nbytes sent per application\nexfil quantification"]
    F --> G["parse_usn_journal\nburst deletion detection"]
    G --> H["correlate_artifacts"]
    H --> I["adversarial_review"]
    I --> J["finish_analysis"]
```

---

## Competitive Differentiation

DeepSIFT was designed knowing the competitive landscape. Here is what sets it apart:

| Feature | DeepSIFT | casefile | Valhuntir | Agentic-DART | Mulder |
|---|:---:|:---:|:---:|:---:|:---:|
| MCP typed tools | **148** | ~30 | 75–100 | ~25 | 140+ |
| Post-hoc grounding verification | ✅ verbatim token | ✅ CSV verbatim | ✗ | ✗ | ✗ |
| Quantified confidence score (0-100) | ✅ 4-axis | ✗ | ✗ | ✗ | ✗ |
| Contradiction detection | ✅ 6 types | ✗ | ✗ | ✗ | ✗ |
| RAG injected at every tool call | ✅ | ✗ | Report-only | ✗ | ✗ |
| Hayabusa Sigma rules (3,700+) | ✅ | ✗ | ✅ | ✗ | ✗ |
| MITRE auto-map at tool call time | ✅ | ✗ | ✗ | ✗ | Navigator export |
| Cross-artifact correlation | ✅ | ✗ | OpenSearch | DuckDB | SQLite FTS |
| Adversarial self-review | ✅ | ✗ | ✗ | ✗ | Phase 4 |
| Chain-of-custody audit_id | ✅ | ✅ | HMAC+PBKDF2 | SHA-256 chained | BLAKE2b |
| Forensic knowledge envelope | ✅ per-tool | ✗ | YAML catalog | ✗ | ✗ |
| Observation/interpretation split | ✅ | ✗ | ✗ | ✗ | ✗ |
| vigia-cases benchmark | ✅ | ✗ | ✗ | ✅ | ✅ |
| SRUM exfil quantification | ✅ | ✗ | ✗ | ✗ | ✗ |
| Evidence write protection | Architectural | ✗ | Bubblewrap | Read-only | ✗ |

**DeepSIFT's unique advantages:**
- **Only submission** with post-hoc grounding verification at the tool layer, scoring every claim token against raw export bytes
- **Only submission** with quantified 4-axis confidence scoring (not qualitative "high/low")
- **Only submission** with structured contradiction detection — `UNRESOLVED_CONTRADICTION` findings that prove anti-forensics occurred
- **Only submission** that injects RAG-backed MITRE threat intelligence into every individual tool call, not just at report generation time

---

## Autonomous Reasoning Loop (agentic) + Architectural Guardrails

DeepSIFT runs three ways:

- **Claude Code + MCP server** *(how a judge can drive it directly, no extra API key)*: point
  Claude Code at the DeepSIFT MCP server via `.mcp.json` and ask it to investigate `/mnt/evidence`.
  Claude Code *is* the agent; every action goes through the typed, parsed, audited, guard-railed
  tools — it cannot run a raw shell command.
- **`investigate.py` — agentic reasoning** *(the senior-analyst mode)*: an LLM forms explicit
  **hypotheses**, chooses which typed MCP tool to run next, reads the parsed/audited JSON,
  marks each hypothesis **confirmed / disproved / inconclusive with a confidence**, **self-corrects**
  when a tool fails or a result contradicts a hypothesis, and reconstructs the **attack chain**.
  Works on **any** evidence shape and adapts its first triage step accordingly:
  ```bash
  export ANTHROPIC_API_KEY=sk-ant-...
  # disk-only (no memory image) — a first-class autonomous run
  python3 investigate.py --evidence-mount /mnt/evidence
  # memory + disk
  python3 investigate.py --image /cases/<case>/memory.raw --evidence-mount /mnt/evidence
  # memory-only
  python3 investigate.py --image /cases/<case>/memory.raw
  ```
- **`demo.py` — deterministic pipeline**: fixed multi-agent sequence (no LLM/key) for reproducible,
  scriptable benchmark runs.

**Architectural guardrails (enforced in code, not prompts):**
- `mcp_server.audit.guard_command` blocks destructive/exfiltration binaries (`rm`, `dd`, `shred`,
  `mkfs`, `wget`, `curl`, `scp`, `ssh`, `nc`, shells…) and shell redirection/chaining tokens at
  **every** tool-execution choke point — the server physically cannot run them.
- `guard_command` rejects shell-string commands outright (argv lists only; no `shell=True`).
- `guard_output_path` blocks writes under evidence roots (`/cases/`, `/mnt/`, `/media/`).
- Tool output is parsed to JSON before reaching the LLM; every call is logged with a SHA-256 of
  the raw output (`analysis/forensic_audit.log`).

## Validated Results — ROCBA Case (Memory + Disk)

End-to-end benchmark on the SANS FOR508 **ROCBA** case (`Rocba-Memory.raw` 18 GB +
`rocba-cdrive.e01` 81 GiB C: volume), scored against ground truth:

| | Protocol SIFT (memory-only) | **DeepSIFT (memory + disk)** |
|---|---|---|
| Accuracy (`must_identify`) | 0 / 4 (0 %) | **4 / 4 (100 %)** |
| Hallucinations | 0 | **0** |

The memory image was captured **3 days after** the 2020-11-13 incident, so the break-in evidence
exists only on disk. DeepSIFT's disk + browser analysis reconstructs it with zero hallucinations:

- **Unauthorized access (2020-11-13)** — wave of Event 4625 *Failed Logon* (RDP brute force).
- **IP theft / exfiltration** — LNK artifacts show SRL project files (`Megaforce Specs & Research.docx`,
  `Blue Thunder blueprint`, `Files from SRL system`) copied to an external **`F:\` USB drive** on 2020-11-13.
- **Cloud usage + incident-window browsing** — Google Drive + SharePoint (`starkresearchlabs-my.sharepoint.com`)
  access on Nov 14 UTC (= Nov 13 evening EST), and a Google search for **`sdelete download`** (anti-forensics).

Reproduce (deterministic, no LLM/API key required):

```bash
python3 demo.py \
  --image /cases/ROCBA/Rocba-Memory.raw \
  --evidence-mount /mnt/evidence \
  --baseline benchmark/baselines/protocol_sift_rocba_findings.json \
  --ground-truth benchmark/ground_truth/rocba_ground_truth.json
```

DeepSIFT has also been validated on the SANS FOR500 **"Abducted Zebrafish" (Vanko)** disk-only
case (physical Surface 3 image), scoring **4/4 must-identify with 0 hallucinations and 100 %
claim grounding** — uniquely recovering the classified zebrafish / cell-regeneration / DNA-splice
subject matter via jump-list and shellbag analysis.

### Production Hardening

The EZ Tools / registry path was hardened so disk-artifact analysis is correct and
case-isolated on any acquired image (no behaviour is specific to a particular case):

- **Cross-case isolation** — every EZ Tools run clears its own CSV output directory first, so a
  prior case's output (e.g. another user profile's LNK history) can never be re-read as the
  current case's evidence.
- **Dirty-hive parsing** — RECmd/SbECmd are invoked with `--nl` so live-acquired registry hives
  (which ship TxR `.blf` logs, not the `.LOG1/.LOG2` files those tools replay) are parsed
  as-acquired instead of aborting and silently returning zero rows.
- **Offline-hive keys** — registry lookups resolve `ControlSet001` (acquired hives have no
  `CurrentControlSet` symlink), and single-key (`--kn`) dumps that write to stdout rather than
  CSV are still parsed into structured entries.
- **Correct artifact decoding** — UserAssist entries are read from the decoded program-path /
  run-count / last-executed columns (not the raw ROT13 value name); SbECmd output (named per
  hive) is read by scanning all CSVs it produces.
- **Case-agnostic knowledge base** — the offline RAG corpus contains only general forensic
  knowledge (MITRE catalog, LOLBAS, Hunt Evil baseline). Per-case IOCs are opt-in
  (`--case-ioc-json` / `--load-rocba`) so one case never biases another.

### Running on SIFT Workstation (Linux) — notes

- **EZ Tools** are invoked as .NET assemblies (`dotnet /opt/zimmermantools/<Tool>.dll`, subdir-aware),
  not Windows `.exe` — works on stock SIFT with the dotnet runtime.
- **Evidence mounting** is read-only; NTFS volume images with a truncated backup-boot sector mount via
  the kernel `ntfs3` driver (`mount -t ntfs3 -o ro <loop> /mnt/evidence`).
- **Offline / air-gapped RAG** — if a GPU build of `torch`/sentence-transformers or the embedding model
  is unavailable, the knowledge base falls back to an offline hashing embedder and seeds from the bundled
  Hunt Evil process baseline + case IOCs (no network needed).
- **Event-log scope** — disk_agent parses live security/system/RDP/PowerShell channels plus the most
  recent rotated Security archives (bounded), and retains events **date-stratified** so the incident
  window is never truncated away.
- **Browser coverage** — all profiles of all installed browsers (Chrome/Edge/Brave + Firefox) are
  analysed, auto-discovered from the evidence mount.

## Setup

### Prerequisites

- SANS SIFT Workstation (Ubuntu 20.04+)
- Python 3.10+
- Volatility 3, log2timeline, Sleuth Kit (pre-installed on SIFT)
- EZ Tools at `/opt/zimmermantools/` (install with SIFT EZ Tools script) — run via the dotnet runtime

### Installation

```bash
git clone https://github.com/your-username/deepsift
cd deepsift

# Install Python dependencies
pip3 install -r requirements.txt

# Copy environment config
cp .env.example .env
nano .env   # Add ABUSEIPDB_API_KEY and VIRUSTOTAL_API_KEY (optional but recommended)

# Initialize RAG knowledge base (first run only, ~3-5 minutes)
python3 rag/ingest/run_all.py

# Run tests
pytest tests/
# Expected: 39 passed
```

### Connect to Claude Code

Add to `~/.claude.json` (or `.claude/settings.json` in your project):

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

Start the server in a separate terminal:

```bash
python3 mcp_server/server.py
```

---

## Running an Investigation

### Quick start (memory image only)

```bash
python3 demo.py --image /cases/ROCBA/Rocba-Memory.raw
```

### Full investigation with comparison report

```bash
python3 demo.py \
    --image /cases/ROCBA/Rocba-Memory.raw \
    --baseline benchmark/baselines/protocol_sift_rocba_findings.json \
    --ground-truth benchmark/ground_truth/rocba_ground_truth.json
```

### With pre-loaded case IOCs

```bash
# Seed ROCBA-specific threat intel into RAG
python3 rag/ingest/run_all.py --load-rocba

python3 demo.py --image /cases/ROCBA/Rocba-Memory.raw
```

### Ask Claude to investigate interactively

Once the MCP server is running and connected:

```
Investigate /cases/ROCBA/Rocba-Memory.raw for signs of unauthorized access
on or after November 13, 2020. Use DeepSIFT tools only.
```

Claude will follow the investigation workflow, call up to 10 tools, cross-correlate
artifacts, challenge its own findings with adversarial review, and call `finish_analysis`
with a structured report citing every audit_id.

---

## Evidence Integrity

Every tool call generates an immutable audit record:

```json
{
  "audit_id": "dsift-2026-06-11-a3f9b2c1",
  "timestamp": "2026-06-11T14:23:07.412Z",
  "tool": "get_process_list",
  "command": "python3 -m volatility3 -f /cases/ROCBA/Rocba-Memory.raw windows.pslist.PsList",
  "raw_output_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "raw_output_file": "exports/get_process_list_2026-06-11T14-23-07-412Z.txt"
}
```

The `finish_analysis` tool requires an `audit_ids` list. Any finding not traceable to a
prior tool call is structurally blocked — the tool returns an error and no report is written.

---

## RAG Knowledge Base

The RAG pipeline (ChromaDB + sentence-transformers) is seeded from:

| Source | Documents | Coverage |
|---|---|---|
| MITRE ATT&CK Enterprise | ~650 techniques | Full technique descriptions, detection guidance, mitigations |
| Threat intelligence IOCs | Case-specific | ROCBA hostile IPs, MRC.exe verdict, cloud exfil surface |
| Case history | Investigation reports | Prior findings from related cases |

RAG context is injected into tool responses at call time — the LLM sees threat intelligence
alongside the parsed artifact data, not as a separate lookup step.

---

## Benchmark

### Protocol SIFT vs DeepSIFT (ROCBA case)

```bash
python3 demo.py \
    --image /cases/ROCBA/Rocba-Memory.raw \
    --baseline benchmark/baselines/protocol_sift_rocba_findings.json \
    --ground-truth benchmark/ground_truth/rocba_ground_truth.json \
    --report-output docs/accuracy_report.html
```

The HTML report shows:
- Side-by-side finding comparison (DeepSIFT vs Protocol SIFT)
- Color-coded MITRE ATT&CK badges
- Precision, recall, and F1 scores vs ground truth
- Chain-of-custody audit trail summary

### vigia-cases Standardized Benchmark

DeepSIFT supports the `annatchijova/vigia-cases` standardized benchmark dataset used
across multiple hackathon submissions for objective cross-system comparison:

```bash
# Clone vigia-cases dataset
git clone https://github.com/annatchijova/vigia-cases

# Run DeepSIFT against all cases
python3 benchmark/vigia_runner.py \
    --vigia-root ./vigia-cases \
    --results-root ./benchmark/deepsift_results \
    --output-json benchmark/reports/vigia_report.json \
    --output-md benchmark/reports/vigia_report.md
```

Scored dimensions: MITRE Recall · IOC Recall · Narrative Recall · Hallucination Rate · Grounding Score · Confidence Score · Contradictions Found

---

## Project Structure

```
DeepSIFT/
├── mcp_server/
│   ├── server.py                    ← MCP server entry point (148 tools, 23 modules)
│   ├── config.py                    ← Tool paths, environment config
│   ├── audit.py                     ← audit_id generation, tool counter, chain-of-custody log
│   ├── tools/
│   │   ├── volatility.py            ← 12 core Volatility tools + verify_findings + finish_analysis
│   │   ├── volatility_extended.py   ← 10 advanced Volatility tools (privileges, VAD, SSDT, callbacks)
│   │   ├── volatility_advanced.py   ← 12 Volatility tools (modules, IRP hooks, hashdump, dump_process)
│   │   ├── windows_artifacts.py     ← 16 EZ Tools wrappers (event logs, registry, execution artifacts)
│   │   ├── registry_extended.py     ← 10 registry tools (shellbags, BAM/DAM, MRU, SAM, timeline)
│   │   ├── browser_artifacts.py     ← 8 browser tools (Chrome, Firefox, Edge, Hindsight, cache)
│   │   ├── email_artifacts.py       ← 5 email tools (PST/OST, Thunderbird, EML, header forensics)
│   │   ├── cloud_artifacts.py       ← 6 cloud tools (Dropbox, OneDrive, Google Drive, Slack, Teams)
│   │   ├── document_analysis.py     ← 5 document tools (PDF, OLE/VBA, RTF, ZIP, DDE)
│   │   ├── linux_forensics.py       ← 10 Linux tools (processes, bash history, syslog, crontab)
│   │   ├── network_analysis.py      ← 3 network tools (PCAP, DNS, ARP)
│   │   ├── network_extended.py      ← 7 network tools (Zeek, IIS, Apache, firewall, netflow, RDP)
│   │   ├── anti_forensics.py        ← 7 anti-forensics detection tools (timestomp, log wipe, ADS, VSS)
│   │   ├── file_carving.py          ← 8 tools (bulk_extractor, foremost, scalpel, capa, FLOSS, exiftool)
│   │   ├── file_analysis.py         ← 3 static analysis tools (PE metadata, strings, packer detection)
│   │   ├── disk_extended.py         ← 6 disk tools (fsstat, ewfinfo, mactime, blkcat, slack, integrity)
│   │   ├── threat_intel_extended.py ← 5 threat intel tools (VT hash/domain, MITRE search, IOC DB, ssdeep)
│   │   ├── log2timeline.py          ← 3 Plaso tools
│   │   ├── sleuthkit.py             ← 4 Sleuth Kit tools
│   │   ├── yara_tools.py            ← 3 YARA tools
│   │   ├── hayabusa.py              ← 2 Hayabusa tools (3,700+ Sigma rules)
│   │   └── correlation.py           ← 3 tools: correlate_artifacts, adversarial_review, detect_contradictions
│   └── parsers/
│       ├── pslist_parser.py         ← SANS Hunt Evil baseline (31 processes), masquerade detection
│       ├── netscan_parser.py        ← External IP extraction and flagging
│       ├── malfind_parser.py        ← Injection type classification (PE/shellcode/reflective)
│       ├── timeline_parser.py       ← Suspicious keyword detection in Plaso timeline
│       ├── mitre_auto_map.py        ← Rule-based MITRE ATT&CK mapping (80+ rules, 19 categories)
│       ├── rag_enrichment.py        ← Shared RAG enrichment helpers (enrich_findings, build_rag_summary)
│       ├── browser_parser.py        ← Browser URL/download threat classification
│       ├── cloud_parser.py          ← Cloud sync exfiltration risk classification
│       ├── document_parser.py       ← PDF/OLE/RTF/DDE/ZIP malicious document classification
│       ├── network_log_parser.py    ← Web/firewall/DNS log threat classification
│       ├── linux_parser.py          ← Linux process/command/syslog threat classification
│       ├── grounding_verifier.py    ← Post-hoc verbatim token grounding check
│       ├── confidence_scorer.py     ← 4-axis quantified confidence scoring (0-100)
│       └── forensic_knowledge.py    ← Per-tool forensic caveats/advisories/corroboration (148 entries)
├── rag/
│   ├── knowledge_base.py            ← ChromaDB vector store
│   ├── query.py                     ← Semantic search interface
│   └── ingest/
│       ├── knowledge_corpus.py      ← Case-agnostic offline corpus (MITRE catalog + LOLBAS + Hunt Evil)
│       ├── mitre_attack.py          ← MITRE ATT&CK Enterprise ingestion
│       ├── case_history.py          ← Per-case findings ingestion (opt-in, per investigation)
│       ├── rocba_iocs.py            ← Example case-IOC pack (opt-in via --load-rocba; not auto-loaded)
│       └── run_all.py               ← One-command RAG initialization
├── agents/
│   ├── orchestrator.py              ← LangGraph multi-agent coordination (deterministic pipeline)
│   └── reasoning_agent.py           ← Agentic LLM reasoning loop over the typed tools
├── benchmark/
│   ├── runner.py                    ← Benchmark execution (Protocol SIFT vs DeepSIFT)
│   ├── scorer.py                    ← must-identify / hallucination scoring vs ground truth
│   ├── compare.py                   ← Case-agnostic side-by-side comparison + HTML report
│   ├── vigia_runner.py              ← vigia-cases standardized multi-case benchmark
│   ├── ground_truth/                ← Per-case ground-truth scoring files
│   ├── baselines/                   ← Protocol SIFT reference findings
│   └── reports/html_report.py       ← Visual HTML comparison report
├── tests/                           ← pytest unit tests (61 passing)
├── yara_rules/
│   ├── suspicious_strings.yar       ← T1059.001, T1003, T1218, T1547.001
│   ├── webshells.yar                ← T1505.003
│   ├── ransomware.yar               ← T1486, T1490
│   ├── rats.yar                     ← T1219, T1071
│   └── packers.yar                  ← T1027.002
├── analysis/                        ← findings.json + forensic_audit.log (runtime)
├── exports/                         ← raw tool outputs SHA-256 indexed (runtime)
├── docs/                            ← architecture.md, dataset.md, devpost_submission.md
├── demo.py                          ← End-to-end demo script
├── .env.example                     ← Environment template
└── requirements.txt
```

---

## MITRE ATT&CK Coverage

DeepSIFT's `mitre_auto_map.py` (80+ rules, 19 categories) tags findings at the tool layer:

| Finding | Technique |
|---|---|
| Process injection (PE header in RWX region) | T1055 — Process Injection |
| PowerShell encoding (`-enc`, `-e` flags) | T1059.001 — PowerShell |
| Registry run key modification | T1547.001 — Registry Run Keys |
| Active external network connection from suspicious process | T1071 — Application Layer Protocol |
| LSASS memory access | T1003.001 — LSASS Memory |
| DKOM-hidden process (pslist vs psscan gap) | T1014 — Rootkit |
| Service install (event 7045 / 4697) | T1543.003 — Windows Service |
| Scheduled task (event 4698 / 106) | T1053.005 — Scheduled Task |
| WMI event subscription (event 5860 / 5861) | T1546.003 — WMI Persistence |
| Lateral movement (RDP / SMB) | T1021.001 / T1021.002 |
| Executable in temp dir (shimcache) | T1036.005 — Match Legitimate Name |
| PowerShell script block (event 4104) | T1059.001 — PowerShell |
| Cloud storage upload (SRUM high bytes_sent) | T1567.002 — Exfiltration to Cloud Storage |
| Burst file deletion (USN Journal) | T1070 — Indicator Removal |
| Timestamp anomaly (MFT 0x10 vs 0x30) | T1070.006 — Timestomping |
| Browser visit to cloud exfil domain | T1567.002 — Exfiltration to Cloud Storage |
| DNS query subdomain length > 40 chars | T1048.003 — DNS Tunneling |
| Web shell URL pattern (cmd.php, shell.aspx) | T1505.003 — Web Shell |
| VBA AutoOpen / Shell / PowerShell call | T1566.001 — Spearphishing Attachment |
| DDE/DDEAUTO in Office document | T1559.002 — Dynamic Data Exchange |
| LD_PRELOAD in process environment | T1574.006 — LD_PRELOAD |
| Linux crontab persistence entry | T1053.003 — Cron |
| History file wiped (`.bash_history` → `/dev/null`) | T1070.003 — Clear Command History |
| Port scan (10+ unique ports from one host) | T1046 — Network Service Discovery |
| IRP hook in driver dispatch table | T1014 — Rootkit |
| Secure deletion tool in prefetch | T1070.004 — File Deletion |
| VSS shadow count = 0 | T1490 — Inhibit System Recovery |
| NTFS Alternate Data Stream | T1564.004 — Hide Artifacts: NTFS ADS |
| File extension / magic byte mismatch | T1036.007 — Masquerading |
| Remote access tool installed (AnyDesk, TeamViewer) | T1219 — Remote Access Software |

---

## Hard Rules (Architectural Enforcement)

These are not prompts — they are code:

1. **Read-only evidence** — `guard_output_path()` raises `PermissionError` for any write
   attempt under `/cases/`, `/mnt/`, or `/media/`. No prompt override possible.

2. **No shell escape** — There is no `run_command` or `execute_shell` tool on the MCP
   surface. The server exposes only the 148 typed tools listed above.

3. **Maximum 10 tool calls** — `audit.py` counter enforces this. At call 10, every tool
   returns a `MAX_ITERATIONS reached` warning and `finish_analysis` must be called.

4. **Provenance-gated reporting** — `finish_analysis` requires a non-empty `audit_ids`
   list. An empty list returns an error — fabricated findings structurally cannot be submitted.

5. **Observation/interpretation split** — `finish_analysis` takes separate `observation`
   (factual, what tools showed) and `interpretation` (analytical, what it means) parameters.
   This separation reduces hallucination by preventing blending of artifact data with inference.

---

## Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
# SIFT tool commands (usually pre-configured on SIFT VM)
VOLATILITY_CMD=python3 -m volatility3
LOG2TIMELINE_CMD=log2timeline.py
PSORT_CMD=psort.py
FLS_CMD=fls
MMLS_CMD=mmls
ICAT_CMD=icat
YARA_CMD=yara

# EZ Tools directory (SIFT default)
EZ_TOOLS_DIR=/opt/zimmermantools

# Hayabusa event log analyzer (3,700+ Sigma rules)
HAYABUSA_CMD=hayabusa

# Optional — enables IP reputation lookups
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here

# Investigation constraints
MAX_TOOL_TIMEOUT=120
MAX_ITERATIONS=10
```

---

## Development

```bash
# Run tests (61 passing, 1 skipped)
pytest tests/ -v

# Syntax check
python -m py_compile mcp_server/tools/*.py mcp_server/parsers/*.py

# Seed the case-agnostic RAG knowledge base (MITRE + LOLBAS + Hunt Evil baseline)
python3 rag/ingest/run_all.py

# Optionally load a case's own IOCs for that investigation (per case, opt-in)
python3 rag/ingest/run_all.py --case-ioc-json analysis/findings.json
# (the bundled ROCBA example pack: --load-rocba)
```

---

## License

MIT License — see `LICENSE` file.

---

*DeepSIFT was built for the [Find Evil! hackathon](https://findevil.devpost.com/) hosted by SANS DFIR.*
