"""
Forensic Knowledge Base — per-tool caveats, advisories, and corroboration hints.

Injected into every MCP tool response so the LLM reasons about forensic discipline
at the tool layer, not just via system prompt. Inspired by Valhuntir's YAML catalog.

Every tool response that passes through wrap_response() gains:
  - caveats:       Known limitations / false-positive sources for this tool
  - advisories:    What the LLM must NOT conclude without further evidence
  - corroboration: Specific follow-up tool calls that increase confidence
"""
from __future__ import annotations
import json


FORENSIC_KNOWLEDGE: dict[str, dict] = {

    # ── Volatility tools ───────────────────────────────────────────────────────

    "get_process_list": {
        "caveats": [
            "pslist walks the EPROCESS doubly-linked list — DKOM-hidden processes will NOT appear.",
            "CreateTime reflects kernel struct initialisation, not necessarily user-visible launch time.",
            "WOW64 (32-bit on 64-bit) processes are normal and do not indicate malice.",
        ],
        "advisories": [
            "A suspicious=true flag means the process is anomalous vs the SANS Hunt Evil baseline — "
            "it is NOT confirmed malicious. Corroborate before attributing.",
            "Parent-child spoofing (T1134.004) is possible — explorer.exe spawning cmd.exe is suspicious "
            "but not definitive proof of compromise.",
            "Do NOT report a process as malware based solely on an unusual name or path.",
        ],
        "corroboration": [
            "Run scan_hidden_processes to detect DKOM-hidden processes missing from this list.",
            "Run get_loaded_dlls on suspicious PIDs to check for injected or unusual DLLs.",
            "Run get_command_history to see what arguments were passed to suspicious processes.",
            "Run get_network_connections to check for C2 communication from suspicious PIDs.",
        ],
    },

    "find_injected_code": {
        "caveats": [
            "malfind flags ALL RWX (PAGE_EXECUTE_READWRITE) regions — JIT engines produce false positives.",
            "Known benign false-positive generators: MsMpEng.exe, SearchApp.exe, LockApp.exe, "
            "RuntimeBroker.exe, Edge/Chrome renderer, .NET CLR, Teams, Slack.",
            "A PE header in a private region is suspicious but not definitive — some loaders do this legitimately.",
        ],
        "advisories": [
            "Do NOT report a malfind hit as confirmed malware without corroboration.",
            "risk_level=high means PE header present — it significantly raises confidence but is not proof.",
            "risk_level=medium (RWX only) is very commonly benign — require process-level corroboration.",
        ],
        "corroboration": [
            "Cross-reference the flagged PID with get_process_list anomalies.",
            "Run get_network_connections to check if the flagged PID has C2 connections.",
            "Run get_loaded_dlls on the PID to look for reflectively-loaded unsigned DLLs.",
            "Extract the memory region and run scan_file_with_yara against known RAT/packer signatures.",
        ],
    },

    "get_network_connections": {
        "caveats": [
            "netscan finds network objects in pool memory — recently closed connections may appear.",
            "CLOSE_WAIT / TIME_WAIT states mean the connection is ending, not active.",
            "Source ports above 49152 are ephemeral and expected — focus on destination ports.",
        ],
        "advisories": [
            "An external IP is NOT evidence of C2 without additional corroboration.",
            "Cloud service IPs (Microsoft, Google, Apple, Akamai) are expected on a managed workstation.",
            "Perform lookup_ip_reputation before attributing any IP to malicious activity.",
        ],
        "corroboration": [
            "Run lookup_ip_reputation on every external IP in external_ips list.",
            "Cross-reference PIDs with suspicious processes from get_process_list.",
            "Run get_loaded_dlls on PIDs with external connections to check for DLL injection.",
            "Correlate timestamps with disk event logs (parse_event_logs) for the same time window.",
        ],
    },

    "scan_hidden_processes": {
        "caveats": [
            "PIDs in psscan but not pslist may be recently-exited legitimate processes, not just rootkits.",
            "Terminated processes linger in pool memory until overwritten — this is normal.",
            "false_positive_note: Chrome/Edge GPU processes, RuntimeBroker, and WerFault commonly appear here.",
        ],
        "advisories": [
            "A discrepancy between pslist and psscan alone does NOT prove rootkit activity.",
            "Only flag as DKOM-hidden if the process name and path are also suspicious.",
        ],
        "corroboration": [
            "For each hidden PID, run get_loaded_dlls to check for suspicious DLLs.",
            "Run get_network_connections to check if the hidden process has active connections.",
            "Cross-reference process names with SANS Hunt Evil baseline expectations.",
        ],
    },

    "get_command_history": {
        "caveats": [
            "cmdline retrieves arguments from PEB (Process Environment Block) — can be spoofed by malware.",
            "Missing cmdline for a PID is not suspicious — the PEB may have been paged out.",
            "Encoded PowerShell commands require decoding before the payload can be assessed.",
        ],
        "advisories": [
            "A suspicious_pattern match means the command string CONTAINS a known-bad pattern — "
            "always review the full cmdline before classifying.",
            "PowerShell -EncodedCommand is used by legitimate IT management tools — check the origin process.",
        ],
        "corroboration": [
            "Cross-reference suspicious PIDs with get_process_list for parent-child context.",
            "Run parse_event_logs to find Event 4688 (process creation) or 4104 (PowerShell script block).",
            "Run parse_prefetch to confirm if the executable ran on disk and when.",
        ],
    },

    "get_running_services": {
        "caveats": [
            "svcscan finds SERVICE_RECORD structures in pool memory — deleted services may still appear.",
            "State = STOPPED does not mean the service never ran.",
            "Services with svchost.exe binary path are Windows-native — flag based on ServiceDll, not the binary.",
        ],
        "advisories": [
            "A service binary in a user-writable path is highly suspicious but requires the binary to be verified.",
            "T1543.003 attribution requires the service to have been installed, not merely registered.",
        ],
        "corroboration": [
            "Cross-reference service PIDs with get_process_list results.",
            "Run parse_event_logs filtering for Event 7045 (new service installed).",
            "Run parse_shimcache or parse_amcache on the binary path to confirm it existed on disk.",
        ],
    },

    "get_loaded_dlls": {
        "caveats": [
            "dlllist reads the PEB InLoadOrder list — unlinked (reflectively-loaded) DLLs may not appear.",
            "Unsigned DLLs from System32 or SysWOW64 are normal for COM components.",
            "Path-only flags (e.g. AppData) are suspicious but common for some legitimate apps (Slack, Teams).",
        ],
        "advisories": [
            "A DLL in an unusual path does not prove injection — check digital signature and hash first.",
        ],
        "corroboration": [
            "Run find_injected_code on the same PID to check for reflective DLL injection.",
            "Hash any suspicious DLL and check with lookup_ip_reputation or external threat intel.",
        ],
    },

    "get_registry_hives": {
        "caveats": [
            "hivelist reads virtual memory — offline hive files on disk may contain different values.",
            "NTUSER.DAT is per-user; SOFTWARE and SYSTEM are system-wide.",
        ],
        "advisories": [
            "Hive offsets are valid only for this specific memory image at capture time.",
        ],
        "corroboration": [
            "Use get_registry_key to read persistence keys: Software\\Microsoft\\Windows\\CurrentVersion\\Run.",
            "For deeper analysis, extract hive via disk and use parse_registry_hive.",
        ],
    },

    "get_registry_key": {
        "caveats": [
            "Values reflect memory state at capture time, which may differ from on-disk registry.",
        ],
        "advisories": [
            "Registry Run key entries require corroboration — check if the binary actually ran via Prefetch/Amcache.",
        ],
        "corroboration": [
            "Run parse_shimcache or parse_prefetch on paths found in Run keys.",
            "Cross-reference service paths with get_running_services.",
        ],
    },

    # ── EZ Tools / Windows artifacts ──────────────────────────────────────────

    "parse_event_logs": {
        "caveats": [
            "Event logs can be cleared by an attacker (Event 1102/104) — absence of logs is also evidence.",
            "EvtxECmd MapDescription is a best-effort translation — always verify with raw EventData.",
            "Timestamps in .evtx files are UTC — convert to local timezone for timeline correlation.",
        ],
        "advisories": [
            "A failed logon (4625) alone does NOT prove a brute-force attack — could be fat-finger.",
            "Require 5+ failed logons from the same source within a short window before attributing T1110.",
            "Event 4624 logon type 10 (RemoteInteractive) proves RDP connection but not malicious intent.",
        ],
        "corroboration": [
            "Correlate logon events with get_network_connections external IPs.",
            "Cross-reference service install events (7045) with get_running_services from memory.",
            "Use parse_prefetch to confirm execution of any paths mentioned in event payloads.",
            "Use parse_shimcache to verify executable existence for paths in event payloads.",
        ],
    },

    "parse_shimcache": {
        "caveats": [
            "On Windows 8+, Shimcache proves an executable EXISTED on disk — NOT that it ran.",
            "On Windows XP/Vista/7, the Executed flag is reliable. On Win8+, it is not set.",
            "Order in Shimcache (position 0 = most recent modification) is approximate.",
        ],
        "advisories": [
            "Do NOT say 'this executable ran' based solely on Shimcache on Windows 8+.",
            "Shimcache is NOT execution proof on modern Windows — use Prefetch or Amcache for that.",
        ],
        "corroboration": [
            "Run parse_prefetch to confirm actual execution (last 8 run times).",
            "Run parse_amcache to get SHA1 hash for VirusTotal lookup.",
            "Cross-reference paths with parse_mft for timestamp anomalies.",
        ],
    },

    "parse_amcache": {
        "caveats": [
            "Amcache records executables that were run, but timestamps reflect file install time, not run time.",
            "Amcache.hve may be out of sync with actual execution — Windows cleans it periodically.",
        ],
        "advisories": [
            "SHA1 hashes from Amcache should be checked against VirusTotal / NSRL before attribution.",
        ],
        "corroboration": [
            "Cross-reference with parse_prefetch for execution time confirmation.",
            "Hash lookup via external threat intel for any suspicious entries.",
        ],
    },

    "parse_prefetch": {
        "caveats": [
            "Prefetch is disabled on Windows Server by default and on SSDs if SuperFetch is off.",
            "LastRun time is reliable. RunCount is accurate but resets if .pf file is deleted.",
            "The 8 most recent run times are the only execution timestamps available.",
        ],
        "advisories": [
            "Prefetch proves EXECUTION and APPROXIMATE TIME — it is strong evidence of T1059 / T1204.",
        ],
        "corroboration": [
            "Cross-reference with parse_shimcache for existence-only confirmation.",
            "Run parse_event_logs for Event 4688 (process creation) if available.",
            "Run parse_mft on the executable path to check for timestamp anomalies.",
        ],
    },

    "parse_mft": {
        "caveats": [
            "Timestamps in $MFT can be manipulated by timestomping (T1070.006) — compare 0x10 vs 0x30.",
            "Only executable/script extensions are returned by default — this filter can miss renamed malware.",
            "Deleted files may have their $MFT entries overwritten — not all deletions are recoverable.",
        ],
        "advisories": [
            "A timestamp_anomaly=True flag (modified before created) proves the file was COPIED from elsewhere.",
            "This is strong evidence of T1070.006 (Timestomping) or dropped malware.",
        ],
        "corroboration": [
            "Cross-reference timestamp anomalies with parse_prefetch to confirm execution.",
            "Run parse_usn_journal (if available) to see the file creation/deletion sequence.",
            "Use parse_recycle_bin to check if the file was subsequently deleted.",
        ],
    },

    "parse_srum": {
        "caveats": [
            "SRUM data is stored in ESE database format — SrumECmd may fail on locked/corrupted databases.",
            "Network bytes are cumulative per app per hour — not per-connection.",
            "SRUM NetworkConnections table shows which apps connected to which IPs.",
        ],
        "advisories": [
            "High background bytes for a cloud sync app is expected — only flag unexpected apps.",
            "SRUM proves network activity occurred — it does NOT prove what data was transferred.",
        ],
        "corroboration": [
            "Cross-reference high-traffic apps with get_network_connections from memory.",
            "Run parse_event_logs to correlate timestamps with logon/logoff events.",
            "Run parse_lnk_files or parse_jump_lists to identify files that may have been exfiltrated.",
        ],
    },

    "parse_usn_journal": {
        "caveats": [
            "USN Journal wraps around and old entries are lost — coverage period varies by disk activity.",
            "Journal entries show file system operations, not file contents.",
            "FILE_DELETE entries do NOT prove anti-forensic intent — routine deletions appear here too.",
        ],
        "advisories": [
            "A burst of deletions in a short window is suspicious, especially of log/temp/evidence files.",
            "Malware staging and cleanup leaves characteristic create-execute-delete patterns.",
        ],
        "corroboration": [
            "Cross-reference deletion timestamps with parse_event_logs logon events.",
            "Run parse_mft to check if any of the deleted files had timestamp anomalies.",
            "Run parse_recycle_bin to see if deleted files went to Recycle Bin first.",
        ],
    },

    "parse_lnk_files": {
        "caveats": [
            "LNK files record user interaction — they prove the USER accessed the target, not an attacker necessarily.",
            "LNK files can persist after the target is deleted, revealing former file paths.",
        ],
        "advisories": [
            "LNK file timestamps can be manipulated — corroborate with MFT timestamps.",
        ],
        "corroboration": [
            "Run parse_jump_lists for application-specific recent access.",
            "Cross-reference target paths with parse_mft for existence/deletion confirmation.",
        ],
    },

    "parse_recycle_bin": {
        "caveats": [
            "$I files record original path and deletion time — $R files contain the actual content.",
            "Recycle Bin only captures explicit user-deleted files — malware may delete without going through Bin.",
        ],
        "advisories": [
            "A suspicious executable in Recycle Bin proves it was placed on the system, then deleted.",
            "This is strong evidence of cleanup / anti-forensics (T1070).",
        ],
        "corroboration": [
            "Cross-reference deletion times with parse_event_logs logon sessions.",
            "Run parse_mft on the original path to check for any timestamp anomalies before deletion.",
        ],
    },

    "lookup_ip_reputation": {
        "caveats": [
            "AbuseIPDB confidence score can be zero for recently-registered C2 infrastructure.",
            "VirusTotal reputation covers IPs reported by security vendors — novel infrastructure scores 0.",
            "Cloud provider IPs (AWS, Azure, GCP) are routinely used for C2 via legitimate hosting.",
        ],
        "advisories": [
            "A score of 0 does NOT prove an IP is clean — it may be new C2 infrastructure.",
            "Always correlate IP reputation with the process making the connection.",
        ],
        "corroboration": [
            "Cross-reference with WHOIS data and ASN to determine hosting provider.",
            "Check get_network_connections for the PID associated with this IP.",
        ],
    },

    # ── log2timeline tools ────────────────────────────────────────────────────

    "create_super_timeline": {
        "caveats": [
            "log2timeline processes ALL parseable evidence — runtime for an 18 GB image is 15-45 minutes.",
            "The .plaso file is a SQLite database — query via psort/filter_timeline only.",
        ],
        "advisories": [
            "Do not attempt to read the .plaso file directly — it is binary SQLite format.",
        ],
        "corroboration": [
            "After creation, call filter_timeline with the incident time window.",
            "Use get_browser_history to isolate web activity from the timeline.",
        ],
    },

    "filter_timeline": {
        "caveats": [
            "Timeline events are extracted from multiple sources — some timestamps are file-system times, "
            "others are log entries. They have different reliability levels.",
            "WEBHIST entries are browser history — not all web visits are investigatively relevant.",
        ],
        "advisories": [
            "A suspicious keyword match means the event contains the keyword — always read the full description.",
        ],
        "corroboration": [
            "Cross-reference suspicious events with parse_event_logs for the same time window.",
            "Correlate file accesses with parse_lnk_files and parse_jump_lists.",
        ],
    },

    # ── YARA tools ────────────────────────────────────────────────────────────

    "scan_memory_with_yara": {
        "caveats": [
            "YARA memory scanning via Volatility yarascan scans ALL process memory — expect noise.",
            "String-based rules will match legitimate processes that contain those strings as data.",
            "Signature rules target known malware — novel malware will not match.",
        ],
        "advisories": [
            "A YARA match is a TIP, not a verdict — confirm with full investigation workflow.",
        ],
        "corroboration": [
            "Cross-reference matched PIDs with get_process_list for process context.",
            "Run find_injected_code on matched PIDs to check for injection.",
            "Run get_network_connections on matched PIDs to look for active C2.",
        ],
    },

    "scan_file_with_yara": {
        "caveats": [
            "File-based YARA scans match static signatures — packed/obfuscated malware may evade.",
            "Only the file content on disk is scanned — in-memory decrypted payloads are not covered.",
        ],
        "advisories": [
            "A YARA match against a known family is strong evidence but can be coincidental for generic rules.",
        ],
        "corroboration": [
            "Submit the file hash to lookup_ip_reputation for VirusTotal confirmation.",
            "Run scan_memory_with_yara to find if the file's code is also loaded in memory.",
        ],
    },

    # ── Sleuth Kit tools ──────────────────────────────────────────────────────

    "get_partition_table": {
        "caveats": [
            "mmls reads the partition table — damaged MBR or GPT may return incomplete results.",
            "Hidden partitions or full-disk encryption will not reveal contents through this tool.",
        ],
        "advisories": [
            "Always use 'offset' values (sector offsets) from this output for follow-up fls/icat calls.",
        ],
        "corroboration": [
            "Run get_file_listing on each NTFS/FAT partition to enumerate file system contents.",
        ],
    },

    "get_file_listing": {
        "caveats": [
            "fls returns allocated AND unallocated (deleted) entries — the 'deleted' flag marks unallocated.",
            "Inode numbers are required for extract_file — note them before pivoting.",
        ],
        "advisories": [
            "Deleted files may have been overwritten — successful recovery is not guaranteed.",
        ],
        "corroboration": [
            "Run search_deleted_files to get only deleted entries.",
            "Run extract_file to recover specific files of interest.",
        ],
    },

    # ── SRUM / USN Journal ────────────────────────────────────────────────────

    "parse_srum": {
        "caveats": [
            "SRUM records approximate usage data — byte counts may differ from actual exfiltration volume.",
            "SRUM data is stored in an ESE database that may be locked or partially flushed on live systems.",
            "Application identity (AppId) uses shell notation — map to executable names for clarity.",
            "SRUM retention is typically 30 days — older exfiltration events will not appear.",
        ],
        "advisories": [
            "High bytes_sent for OneDrive/Dropbox/Google Drive is suspicious but not definitively malicious — "
            "confirm it correlates with logon sessions from the incident window.",
            "Do NOT assert data exfiltration volume solely from SRUM without corroborating with timeline.",
        ],
        "corroboration": [
            "Cross-reference SRUM timestamps with parse_event_logs logon sessions to confirm attacker presence.",
            "Run filter_timeline to find DNS queries and file access events matching the SRUM upload window.",
            "Run lookup_ip_reputation on any cloud storage IPs observed in network connections.",
        ],
    },

    "parse_usn_journal": {
        "caveats": [
            "The USN Journal wraps (overwrites old entries) — events older than ~72 hours on active systems may be lost.",
            "USN reasons (FILE_DELETE, DATA_EXTEND, etc.) are bitmask combinations — parse carefully.",
            "Burst deletions can be triggered by legitimate software updaters and antivirus quarantine operations.",
        ],
        "advisories": [
            "A burst of .log and .evtx deletions is suspicious, but automated patching also deletes logs — "
            "verify the deleting process identity via event logs.",
            "File renames (RENAME_OLD_NAME + RENAME_NEW_NAME pairs) may indicate timestomping or masquerading.",
        ],
        "corroboration": [
            "Cross-reference deletion timestamps with parse_event_logs logon sessions (4624/4625).",
            "Run parse_recycle_bin to check if deleted files went through the Recycle Bin.",
            "Run parse_mft on specific file entries to check for timestamp anomalies.",
        ],
    },

    # ── Correlation and adversarial review ───────────────────────────────────

    "correlate_artifacts": {
        "caveats": [
            "Correlation requires accurate artifact loading — missing audit_ids produce incomplete results.",
            "PID reuse between sessions can create false correlations — verify process create times align.",
            "Path matching is case-insensitive but may miss renamed or moved executables.",
        ],
        "advisories": [
            "A correlation finding increases confidence but does NOT replace individual artifact verification.",
            "Coverage gaps listed in the output represent evidence sources that should be collected before finish_analysis.",
        ],
        "corroboration": [
            "After correlating, run adversarial_review to challenge the emerging hypothesis.",
            "For each high-confidence correlation, verify the corroboration steps in the individual tool entries.",
        ],
    },

    "adversarial_review": {
        "caveats": [
            "This tool generates structured challenges based on common investigation errors — it does not access live data.",
            "Counter-hypotheses are generic templates — apply them to the specific artifact context.",
        ],
        "advisories": [
            "Every challenge listed must be explicitly addressed before submitting finish_analysis.",
            "If ready_for_finish_analysis is False, do NOT call finish_analysis until gaps are resolved.",
        ],
        "corroboration": [
            "Address each required_corroboration step in the challenges output.",
            "Document in the finish_analysis interpretation which alternative hypotheses were ruled out.",
        ],
    },

    "detect_contradictions": {
        "caveats": [
            "Contradiction detection requires audit_ids from the current session — loading exports from prior sessions may fail.",
            "PREFETCH_WITHOUT_SHIMCACHE false positives can occur when Shimcache was parsed from a different drive or partial hive.",
            "LOG_WIPE_INDICATOR requires a continuous event log — a fresh install or log rotation produces the same gap.",
        ],
        "advisories": [
            "UNRESOLVED_CONTRADICTION findings significantly raise attack confidence — include ALL in finish_analysis.",
            "A DKOM_HIDDEN_PROCESS contradiction is among the highest-confidence rootkit indicators available without a kernel debugger.",
            "Do NOT dismiss contradictions as artifacts without at least one corroborating source.",
        ],
        "corroboration": [
            "For DKOM_HIDDEN_PROCESS: cross-reference psscan-only PIDs with get_network_connections.",
            "For LOG_WIPE_INDICATOR: look for EventID 1102 (Security log cleared) or 104 (System log cleared) at the gap boundary.",
            "For PREFETCH_WITHOUT_SHIMCACHE: run parse_mft to check if the file path exists on disk.",
            "For HIDDEN_SERVICE: parse_registry_hive on SYSTEM hive for the service key to confirm deletion.",
        ],
    },

    # ── Hayabusa / Sigma ──────────────────────────────────────────────────────

    "parse_hayabusa": {
        "caveats": [
            "Hayabusa applies 3,700+ Sigma rules to Windows event logs — expect some false positives, especially at 'low' severity.",
            "Rule accuracy varies by community source — Hayabusa built-in rules are higher quality than all community rules.",
            "Hayabusa requires the evtx directory to contain .evtx files — mounted volume or extracted evidence required.",
            "Timestamps in Hayabusa output are UTC — convert for local timezone correlation.",
        ],
        "advisories": [
            "Critical and High severity alerts are reliable — Medium and Low alerts require corroboration before attribution.",
            "A Hayabusa alert alone does NOT constitute proof of an ATT&CK technique — it identifies candidate events.",
            "Do NOT attribute a MITRE technique solely from a low-severity Hayabusa rule match.",
        ],
        "corroboration": [
            "For Critical/High alerts: confirm the specific EventID and data in the raw event via parse_event_logs.",
            "Cross-reference Hayabusa MITRE tags with findings from memory tools (malfind, netscan) for convergence.",
            "For credential access alerts: run scan_hidden_processes and get_loaded_dlls on lsass.exe.",
            "For lateral movement alerts: correlate with get_network_connections external IPs.",
        ],
    },

    "list_hayabusa_rules": {
        "caveats": [
            "Rule count reflects installed Hayabusa version — update hayabusa to get the latest Sigma rule set.",
        ],
        "advisories": [],
        "corroboration": [
            "Use parse_hayabusa with min_severity='critical' first, then broaden to 'medium' if needed.",
        ],
    },

    # ── Volatility extended tools ─────────────────────────────────────────────

    "get_privileges": {
        "caveats": [
            "Privilege listing reflects the current token state — not historical state before privilege manipulation.",
            "SeDebugPrivilege enabled for non-system processes is strongly suspicious but not unique to malware.",
            "System processes (lsass, services, winlogon) legitimately hold elevated privileges.",
        ],
        "advisories": [
            "SeDebugPrivilege + SeImpersonatePrivilege on a non-system process (e.g. cmd.exe, powershell.exe) "
            "is a high-confidence indicator of privilege escalation (T1134).",
            "Do NOT flag svchost.exe or lsass.exe — their privileges are expected.",
        ],
        "corroboration": [
            "Cross-reference the PID with get_process_list parent-child context.",
            "Run get_command_history on the PID to understand the argument context.",
            "Check parse_event_logs for Event 4672 (special logon with SeDebugPrivilege assignment).",
        ],
    },

    "get_mutexes": {
        "caveats": [
            "Mutex names are set by application developers — all-caps GUIDs are common in both malware and legitimate software.",
            "A mutex in one process does not confirm that specific process is malicious — shared mutexes exist.",
            "Mutex scanning via mutantscan can produce stale entries from already-exited processes.",
        ],
        "advisories": [
            "Known malware mutex signatures exist for many RAT families — compare against threat intel before attributing.",
            "Do NOT classify a mutex as malicious based on name alone without additional corroboration.",
        ],
        "corroboration": [
            "Search known-malware mutex lists via RAG or external threat intel for the exact mutex name.",
            "Cross-reference the owning PID with find_injected_code and get_network_connections.",
        ],
    },

    "get_env_vars": {
        "caveats": [
            "Environment variables are read from the PEB — they can be manipulated after process creation.",
            "TEMP/TMP paths pointing to unusual locations may indicate sandboxed or modified environments.",
        ],
        "advisories": [
            "Suspicious TEMP paths or PATH hijacking attempts are indicators but require corroboration.",
            "Do NOT conclude DLL hijacking (T1574) solely from an unusual PATH — confirm a DLL was loaded from that path.",
        ],
        "corroboration": [
            "Run get_loaded_dlls on the PID to check if DLLs were loaded from the suspicious PATH location.",
            "Cross-reference COMPUTERNAME / USERNAME with expected system identity.",
        ],
    },

    "get_vad_info": {
        "caveats": [
            "VAD (Virtual Address Descriptor) tree shows all memory regions — most RWX regions are from JIT engines.",
            "Private non-file-backed RWX regions are suspicious but browsers and .NET produce many of these legitimately.",
            "VAD region sizes and addresses differ from process to process — absolute addresses are not stable.",
        ],
        "advisories": [
            "A large private RWX region with no file backing and high entropy is the strongest single malfind indicator.",
            "Do NOT flag every private RWX region — focus on those with PE magic bytes or entropy > 7.0.",
        ],
        "corroboration": [
            "Run find_injected_code to check for PE headers in flagged VAD regions.",
            "Run detect_packer on any extracted region files for entropy confirmation.",
        ],
    },

    "get_ldrmodules": {
        "caveats": [
            "ldrmodules compares three PEB lists: InLoad, InMem, InInit. Missing from all three = reflectively loaded.",
            "Some legitimate modules (e.g. NTDLL entry points, mapped executables) may be absent from InInit.",
            "This plugin produces false positives on some .NET assemblies and JIT-compiled modules.",
        ],
        "advisories": [
            "A DLL absent from ALL THREE lists is the strongest indicator of reflective DLL injection (T1055.001).",
            "Missing from InInit only is weak — focus on missing from InLoad + InMem simultaneously.",
        ],
        "corroboration": [
            "Cross-reference the mapped address with get_vad_info to check the region permissions.",
            "Run get_loaded_dlls on the same PID for the normal DLL list as comparison.",
        ],
    },

    "get_ssdt": {
        "caveats": [
            "SSDT hooking is a classic rootkit technique that AV/EDR products also use.",
            "Any security product (AV, EDR, DLP) can legitimately hook the SSDT.",
            "Virtual machines (VMware, VirtualBox) may show SSDT hooks from hypervisor integration drivers.",
        ],
        "advisories": [
            "SSDT hooks from ntoskrnl/win32k are EXPECTED. Only flag hooks from non-standard driver addresses.",
            "Do NOT conclude rootkit presence solely from SSDT hooks without identifying the hooking driver.",
        ],
        "corroboration": [
            "Identify the hooking module with get_callbacks and get_devicetree.",
            "Check if the hooking driver is a known AV/EDR product before attributing to malware.",
        ],
    },

    "get_callbacks": {
        "caveats": [
            "Kernel callbacks are used by AV/EDR products extensively — most callbacks are legitimate.",
            "Callback addresses must be resolved to their owning driver — raw addresses are not actionable.",
        ],
        "advisories": [
            "A callback from an unsigned or unknown driver is the key indicator — not the presence of callbacks per se.",
        ],
        "corroboration": [
            "Cross-reference callback driver names with get_devicetree for the driver load chain.",
            "Check parse_event_logs for driver load events (Event 6) at boot time.",
        ],
    },

    "get_filescan": {
        "caveats": [
            "filescan finds FILE_OBJECT structures in pool memory — includes open handles from all processes.",
            "Paths are reconstructed from memory — partial paths or corruption may produce incomplete paths.",
            "Many files appear here from Windows internals (pagefile.sys, registry hives, log files).",
        ],
        "advisories": [
            "Focus on executable paths in user-writable locations (Temp, AppData, Downloads, Public).",
            "A file open handle does NOT mean the file was read, written, or executed.",
        ],
        "corroboration": [
            "Cross-reference suspicious paths with parse_shimcache and parse_prefetch for execution evidence.",
            "Extract the file via extract_file (Sleuth Kit) and run scan_file_with_yara.",
        ],
    },

    "get_timeliner": {
        "caveats": [
            "timeliner produces events from process, DLL, registry, and file object timestamps in memory.",
            "Timestamps from kernel objects reflect the OS clock at the time — subject to clock skew.",
            "Very long output — this tool returns only the top 200 events sorted by time.",
        ],
        "advisories": [
            "Use this for approximate chronology only — verify key timestamps against more authoritative sources.",
        ],
        "corroboration": [
            "Cross-reference memory timeliner events with disk-based filter_timeline for consistency.",
            "Look for process creation times that precede the expected incident window.",
        ],
    },

    "get_devicetree": {
        "caveats": [
            "Device tree reflects the kernel state at memory capture time — dynamically loaded drivers may appear.",
            "Driver names in the device tree are internal kernel names, not necessarily the .sys filename.",
        ],
        "advisories": [
            "Drivers with no recognizable name or manufacturer in unusual positions in the tree are suspicious.",
            "Do NOT flag WdFilter (Windows Defender) or similar security product drivers.",
        ],
        "corroboration": [
            "Cross-reference driver module names with get_callbacks for callback registrations.",
            "Check get_ssdt for hooks registered by suspicious drivers found here.",
        ],
    },

    # ── File analysis tools ───────────────────────────────────────────────────

    "get_pe_metadata": {
        "caveats": [
            "pefile compile timestamp can be set to any value by the compiler or post-compilation — it is NOT reliable proof of creation date.",
            "imphash matching requires the exact same import table — minor linker differences produce different hashes for the same malware family.",
            "Digital signature absence does NOT prove malice — many legitimate tools are unsigned.",
        ],
        "advisories": [
            "A compile timestamp in the future (past 2030) or before 1995 strongly indicates timestomping (T1070.006).",
            "High-entropy sections (>7.0) are the single most reliable packing indicator — packed binaries evade AV.",
            "Do NOT attribute malware based on imphash alone — check for confirmed malicious imports + unsigned status together.",
        ],
        "corroboration": [
            "Run detect_packer to confirm packing before asserting T1027 (Obfuscated Files).",
            "Submit the imphash to VirusTotal via lookup_ip_reputation for family attribution.",
            "Cross-reference suspicious imports (VirtualAllocEx, WriteProcessMemory) with find_injected_code findings.",
        ],
    },

    "extract_strings": {
        "caveats": [
            "String extraction is static — packed/encrypted binaries yield mostly garbage strings until unpacked.",
            "base64 pattern matching produces false positives on binary data that happens to be base64-like.",
            "URLs and IPs embedded as compile-time strings may be hardcoded C2, but may also be documentation or test code.",
        ],
        "advisories": [
            "Embedded IP addresses in a packed or obfuscated binary strongly suggest C2 hardcoding.",
            "Do NOT assert a URL is a C2 endpoint without corroborating with network connection data.",
        ],
        "corroboration": [
            "Cross-reference extracted IPs with get_network_connections and lookup_ip_reputation.",
            "If base64 strings are found, attempt decoding and re-extract strings from the decoded output.",
            "Run detect_packer first — if packed, strings are unreliable until the binary is unpacked.",
        ],
    },

    "detect_packer": {
        "caveats": [
            "Entropy analysis is a heuristic — legitimate encrypted archives (ZIP, 7z) also show high entropy.",
            "UPX signature detection only catches unmodified UPX — custom-patched UPX will evade this check.",
            "CLEAN verdict means no known signature was found — it does NOT mean the file is clean.",
        ],
        "advisories": [
            "A PACKED verdict means the binary's static analysis is severely limited — focus on memory dumps.",
            "Do NOT attempt YARA or AV scanning of a PACKED binary without first unpacking it.",
        ],
        "corroboration": [
            "Run find_injected_code on any process running the packed binary — the unpacked payload appears in memory.",
            "Run scan_memory_with_yara against the running process to detect the unpacked malware family.",
        ],
    },

    # ── Network analysis tools ────────────────────────────────────────────────

    "parse_pcap_summary": {
        "caveats": [
            "TShark conversation stats are aggregated — they do NOT show per-packet timing or content.",
            "Bytes transferred includes both directions — split bytes_ab (outbound) from bytes_ba (inbound) for exfil assessment.",
            "PCAP captures only what was on the monitored interface — encrypted (TLS) payloads appear as ciphertext.",
        ],
        "advisories": [
            "Large outbound transfers (>1 MB) are suspicious only if to an unexpected external IP.",
            "Cloud storage (OneDrive, Dropbox, GDrive) legitimately transfers large volumes — verify the IP ownership.",
        ],
        "corroboration": [
            "Run extract_dns_queries to identify domains queried during large transfer windows.",
            "Cross-reference top-talker IPs with lookup_ip_reputation.",
            "Correlate transfer timestamps with parse_event_logs logon sessions.",
        ],
    },

    "extract_dns_queries": {
        "caveats": [
            "DNS data is only available if DNS traffic was captured on the monitored interface.",
            "DGA detection is heuristic — short random-looking domains exist in legitimate CDN and analytics services.",
            "Long subdomain labels (>50 chars) may be from legitimate cloud services using base64-encoded routing labels.",
        ],
        "advisories": [
            "A beaconing candidate (>30 queries to same domain) could be an auto-update check — verify the domain owner.",
            "Do NOT attribute DNS tunnelling (T1071.004) without evidence of unusual query volume AND data in the label.",
        ],
        "corroboration": [
            "Run lookup_ip_reputation on resolved IPs from suspicious domains.",
            "Cross-reference beaconing domain query times with parse_event_logs logon sessions.",
            "If DGA-style domains resolve to the same IP, run parse_pcap_summary for data volume to those IPs.",
        ],
    },

    "parse_arp_cache": {
        "caveats": [
            "ARP cache data is derived from Volatility netstat — not a true ARP cache dump.",
            "IPs observed this way reflect connections at memory capture time — prior lateral movement leaves no ARP trace.",
        ],
        "advisories": [
            "Additional IPs not in the process list may indicate prior lateral movement — corroborate with event logs.",
        ],
        "corroboration": [
            "Run lookup_ip_reputation on any external IPs discovered.",
            "Cross-reference with get_network_connections PIDs for process attribution.",
        ],
    },

    # ── Windows artifact registry extensions ──────────────────────────────────

    "parse_userassist": {
        "caveats": [
            "UserAssist tracks GUI execution — CLI tools run without a GUI do not appear here.",
            "RunCount may reset when the registry is flushed or after Windows Update.",
            "UserAssist entries are per-user (NTUSER.DAT) — evidence only for the specific user's hive.",
        ],
        "advisories": [
            "UserAssist proves a USER clicked an executable in Explorer — not that it was launched by malware.",
            "Do NOT use UserAssist to prove attacker execution — use Prefetch or Amcache for that.",
        ],
        "corroboration": [
            "Cross-reference with parse_prefetch to confirm execution time.",
            "Run parse_shimcache to confirm the executable existed on disk before execution.",
        ],
    },

    "parse_recentdocs": {
        "caveats": [
            "RecentDocs tracks documents opened by the user via Explorer — not programmatic file access.",
            "Entries persist even after the referenced file is deleted.",
        ],
        "advisories": [
            "RecentDocs proves document access by the logged-in user, not necessarily an attacker.",
            "Cross-reference document types (e.g. .docx, .pdf, .xlsx) with known exfiltration targets.",
        ],
        "corroboration": [
            "Run parse_lnk_files and parse_jump_lists to expand the accessed-file picture.",
            "Cross-reference filenames with parse_mft for existence/deletion confirmation.",
        ],
    },

    "parse_network_history": {
        "caveats": [
            "Network history from SYSTEM hive reflects current/past interface configurations, not connection logs.",
            "IP addresses here are configured addresses, not destinations — this is not a connection log.",
        ],
        "advisories": [
            "Use this to understand the system's network configuration — not for IOC extraction.",
        ],
        "corroboration": [
            "Cross-reference with get_network_connections for active connections at capture time.",
        ],
    },

    "parse_usb_history": {
        "caveats": [
            "USBSTOR entries record devices that were EVER connected — not necessarily at incident time.",
            "Last-connection timestamps require cross-referencing with setupapi.dev.log for precision.",
            "USB device serial numbers are vendor-assigned and may not be globally unique for cheap devices.",
        ],
        "advisories": [
            "A USB device connection alone does NOT prove data exfiltration (T1052.001) — require file access evidence.",
            "Legitimate USB devices (keyboards, mice, phones) appear in USBSTOR — focus on storage devices.",
        ],
        "corroboration": [
            "Cross-reference USB connection timestamps with parse_event_logs logon sessions.",
            "Run parse_mft to find files accessed from the USB drive path during the connection window.",
            "Run parse_lnk_files to see if documents on the USB were opened by the user.",
        ],
    },

    # ── Grounding and confidence tools ────────────────────────────────────────

    "verify_findings": {
        "caveats": [
            "Grounding verification checks verbatim token presence in raw export bytes — paraphrased claims may fail even if accurate.",
            "Grounding only covers the current session's audit log — claims from prior sessions cannot be verified.",
            "A PASS verdict means all checked tokens were found — it does NOT validate the forensic interpretation.",
        ],
        "advisories": [
            "ALWAYS call verify_findings before finish_analysis when grounding_score < 100%.",
            "An UNVERIFIED claim must be either removed, corrected, or explicitly marked as 'interpretation' not 'observation'.",
        ],
        "corroboration": [
            "Review each unverified_claim and trace it to the specific tool call that should support it.",
            "Re-run the relevant tool if the audit_id is missing or the export file is empty.",
        ],
    },
}


def wrap_response(tool_name: str, data: dict, audit_id: str = "") -> str:
    """
    Inject audit_id + forensic knowledge envelope into a tool response dict.

    The envelope fields (audit_id, caveats, advisories, corroboration) are
    added at the TOP LEVEL of the response alongside existing data keys.
    Existing keys are never overwritten — the envelope is purely additive.

    Returns a JSON string.
    """
    if audit_id:
        data.setdefault("audit_id", audit_id)

    knowledge = FORENSIC_KNOWLEDGE.get(tool_name, {})
    if knowledge.get("caveats"):
        data.setdefault("caveats", knowledge["caveats"])
    if knowledge.get("advisories"):
        data.setdefault("advisories", knowledge["advisories"])
    if knowledge.get("corroboration"):
        data.setdefault("corroboration", knowledge["corroboration"])

    return json.dumps(data, default=str)
