"""
Forensic Knowledge Base — per-tool caveats, advisories, and corroboration hints.

Injected into every MCP tool response so the LLM reasons about forensic discipline
at the tool layer, not just via system prompt — a per-tool forensic knowledge catalog.

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

    # ── Browser artifact tools ────────────────────────────────────────────────

    "parse_chrome_history": {
        "caveats": [
            "Chrome history is stored in an SQLite WAL database — visit_time is microseconds since 1601-01-01.",
            "Incognito mode visits are NOT stored — their absence is expected, not evidence of deletion.",
            "Multiple Chrome profiles exist per user — all profile directories should be checked.",
        ],
        "advisories": [
            "A visit to a cloud storage URL does NOT prove exfiltration — it proves the page was visited.",
            "Correlation with download records is required before asserting data transfer.",
        ],
        "corroboration": [
            "Cross-reference suspicious URLs with parse_chrome_extensions for malicious extensions.",
            "Run lookup_domain_reputation on flagged domains.",
            "Correlate download timestamps with parse_mft for files created at the same time.",
        ],
    },

    "parse_firefox_history": {
        "caveats": [
            "Firefox history is in places.sqlite — the moz_places table contains all visited URLs.",
            "Private browsing mode visits are never stored.",
            "Firefox profile names are random — search all profiles under the Profiles directory.",
        ],
        "advisories": [
            "visit_count > 1 means the user repeatedly visited — it does not prove intentional use.",
        ],
        "corroboration": [
            "Cross-reference with parse_chrome_history if both browsers are present.",
            "Run lookup_domain_reputation on suspicious domains.",
        ],
    },

    "parse_chrome_extensions": {
        "caveats": [
            "Extension IDs are 32-character hashes — map them to names via the Chrome Web Store.",
            "Malicious extensions may have legitimate-looking names — check the permissions manifest.",
        ],
        "advisories": [
            "An extension with permissions for 'all URLs' + 'storage' + 'nativeMessaging' is a high-risk combination.",
        ],
        "corroboration": [
            "Cross-reference extension install dates with parse_event_logs logon sessions.",
            "Search extension IDs against lookup_hash_reputation or external threat intel.",
        ],
    },

    "run_hindsight": {
        "caveats": [
            "Hindsight requires the Chrome profile directory to be accessible — copy from evidence mount first.",
            "Hindsight output covers: history, downloads, cookies, cache, extensions, and login data (hashed).",
        ],
        "advisories": [
            "Hindsight integrates multiple Chrome artifact sources — treat it as a starting point, not a final report.",
        ],
        "corroboration": [
            "Follow up suspicious URLs with lookup_domain_reputation.",
            "Cross-reference download paths with parse_mft for file system timeline correlation.",
        ],
    },

    # ── Email artifact tools ──────────────────────────────────────────────────

    "parse_pst_ost": {
        "caveats": [
            "pffexport must process the entire PST/OST file before output is available — may take minutes for large files.",
            "OST files require the associated Exchange account to be accessible for decryption in some cases.",
        ],
        "advisories": [
            "Email timestamps can be spoofed by the sender — only trust internal server-added timestamps.",
        ],
        "corroboration": [
            "Run analyze_email_headers on suspicious emails to verify routing and authentication.",
            "Cross-reference attachment filenames with parse_mft for disk evidence.",
        ],
    },

    "analyze_email_headers": {
        "caveats": [
            "Received headers are added by each mail server — the oldest (bottom) Received header is most trustworthy.",
            "From: and Reply-To: fields can be trivially spoofed without DMARC enforcement.",
            "SPF/DKIM/DMARC results in Authentication-Results are added by the RECEIVING mail server.",
        ],
        "advisories": [
            "SPF PASS does not prove the email is legitimate — it only proves it came from an authorized server.",
            "A DMARC FAIL with a forged From: address is strong evidence of phishing (T1566.001).",
        ],
        "corroboration": [
            "Run lookup_domain_reputation on the sending domain.",
            "Cross-reference recipient names with case subject identities.",
        ],
    },

    # ── Cloud artifact tools ──────────────────────────────────────────────────

    "parse_dropbox_logs": {
        "caveats": [
            "Dropbox sync_history.db only retains a limited number of sync events — older events are pruned.",
            "sync_history.db schema varies between Dropbox client versions.",
            "Deleted files appear as sync events but the deleted content may not be recoverable from local artifacts.",
        ],
        "advisories": [
            "A sync event proves the file was synced, not necessarily that it was READ by an attacker.",
            "Correlation with logon sessions is required before asserting intentional exfiltration.",
        ],
        "corroboration": [
            "Cross-reference sync timestamps with parse_event_logs logon sessions (Event 4624).",
            "Run parse_lnk_files to confirm the user accessed the Dropbox synced files.",
        ],
    },

    "parse_onedrive_logs": {
        "caveats": [
            "ODL binary log files require string extraction — structured parsing is limited without the official SDK.",
            "SyncDiagnostics.log retention varies — may be 7-30 days depending on client version.",
        ],
        "advisories": [
            "OneDrive sync activity for O365 accounts is expected — only flag files with sensitive names or unusual volumes.",
        ],
        "corroboration": [
            "Cross-reference file names in ODL entries with parse_mft for creation timestamps.",
            "Run parse_event_logs for Event 4688 (process creation) showing OneDrive.exe command lines.",
        ],
    },

    "parse_teams_artifacts": {
        "caveats": [
            "Teams LevelDB (IndexedDB) files are binary — string extraction is heuristic, not structured.",
            "Teams chat content in IndexedDB is not full-text — only recent messages are cached locally.",
        ],
        "advisories": [
            "Teams file sharing happens via SharePoint/OneDrive — local Teams artifacts may not capture all transfers.",
        ],
        "corroboration": [
            "Cross-reference account email addresses with parse_event_logs logon identities.",
            "Run parse_onedrive_logs to find files shared via Teams (stored in SharePoint/OneDrive).",
        ],
    },

    # ── Registry extended tools ───────────────────────────────────────────────

    "parse_shellbags": {
        "caveats": [
            "Shellbags persist even after the folder is deleted — they prove a folder WAS accessed, not that it currently exists.",
            "Shellbag timestamps reflect the last time the user OPENED the folder via Explorer, not created it.",
            "Network paths in shellbags (\\\\server\\share) can indicate lateral movement to mapped shares.",
        ],
        "advisories": [
            "Shellbag analysis requires both NTUSER.DAT (user hive) and UsrClass.dat for complete coverage.",
            "External drive paths in shellbags (D:\\, E:\\) indicate USB/external media access.",
        ],
        "corroboration": [
            "Cross-reference shellbag paths with parse_lnk_files and parse_jump_lists.",
            "Run parse_mft to check if files from the accessed folders existed on disk.",
        ],
    },

    "parse_bam_dam": {
        "caveats": [
            "BAM (Background Activity Monitor) tracks executable execution since Windows 10 1803.",
            "BAM entries reset when the system restarts — they only cover the current boot cycle.",
            "DAM (Desktop Activity Moderator) tracks execution for suspended (modern/UWP) apps.",
        ],
        "advisories": [
            "BAM LastExecutionTime is reliable for the current boot session only.",
            "BAM proves execution with timestamp — stronger than shimcache on its own.",
        ],
        "corroboration": [
            "Cross-reference BAM entries with parse_prefetch for execution count.",
            "Run parse_amcache to get SHA1 hash of executables seen in BAM.",
        ],
    },

    "parse_sam_hive": {
        "caveats": [
            "SAM hive stores local account password hashes (LM/NTLM) — these can be cracked offline.",
            "SAM hive is locked while Windows is running — requires offline access via memory or disk forensics.",
            "Account creation/deletion timestamps in SAM are UTC.",
        ],
        "advisories": [
            "A recently-created local account with admin privileges is a strong lateral movement indicator (T1136.001).",
            "Password hash extraction from SAM is also possible via Volatility get_hashdump.",
        ],
        "corroboration": [
            "Cross-reference account creation timestamps with parse_event_logs Event 4720 (user created).",
            "Run get_hashdump from Volatility for live memory extraction.",
        ],
    },

    # ── Volatility advanced tools ─────────────────────────────────────────────

    "get_hashdump": {
        "caveats": [
            "Hashdump extracts password hashes from the SAM hive in memory — requires SYSTEM privileges.",
            "LM hashes should be empty (aad3b435...) on modern Windows — a populated LM hash is anachronistic.",
            "Hashes should NEVER be included verbatim in investigation reports — use partial hashes only.",
        ],
        "advisories": [
            "Extracted NTLM hashes can be used for pass-the-hash attacks — handle with care.",
            "Hash extraction is T1003.002 — the technique itself is a credential access finding if done by malware.",
        ],
        "corroboration": [
            "Cross-reference accounts with parse_sam_hive for account creation dates.",
            "Run get_lsadump to find cached credentials from domain accounts.",
        ],
    },

    "get_lsadump": {
        "caveats": [
            "LSA secrets may include service account credentials, auto-logon passwords, and domain cached credentials.",
            "LSA dump is only available if the SECURITY hive is accessible and not encrypted by DPAPI.",
        ],
        "advisories": [
            "LSA secret exposure is T1003.004 — Credentials from Password Stores.",
            "Any plaintext credentials in LSA secrets must be treated as compromised.",
        ],
        "corroboration": [
            "Cross-reference service account names with get_running_services.",
            "Run parse_event_logs for Event 4625 (failed logon) using extracted credentials.",
        ],
    },

    "get_modules": {
        "caveats": [
            "Modules lists loaded kernel drivers from PsLoadedModuleList — DKOM-hidden modules will not appear.",
            "Unsigned drivers are suspicious but not always malicious — kernel mode drivers may be unsigned.",
        ],
        "advisories": [
            "An unsigned driver from a non-standard path is a high-confidence rootkit indicator.",
        ],
        "corroboration": [
            "Cross-reference suspicious drivers with get_driverirp to check for hooked IRP handlers.",
            "Run calculate_file_hashes on extracted driver files and lookup_hash_reputation.",
        ],
    },

    "get_driverirp": {
        "caveats": [
            "IRP hooks that point outside the driver's normal address range indicate rootkit hooking.",
            "Some legitimate security products hook IRPs — AV/EDR drivers commonly do this.",
        ],
        "advisories": [
            "IRP hooks combined with a hidden module (get_modules) is a high-confidence rootkit finding.",
        ],
        "corroboration": [
            "Cross-reference the hooking module address with get_modules to identify the driver.",
            "Run scan_memory_with_yara with rootkit rule sets on the image.",
        ],
    },

    "dump_process": {
        "caveats": [
            "dumpfiles recreates the PE from memory — the dump may differ from the on-disk binary if patched in memory.",
            "Memory-resident payloads (shellcode, reflective DLLs) may not produce valid PE dumps.",
        ],
        "advisories": [
            "Dumped processes are evidence — treat them as sensitive forensic artifacts.",
        ],
        "corroboration": [
            "Run scan_file_with_yara on the dumped PE to identify malware family.",
            "Run calculate_file_hashes and lookup_hash_reputation on the dump.",
            "Run detect_capabilities_capa on the dump for MITRE-mapped capability analysis.",
        ],
    },

    # ── File carving tools ────────────────────────────────────────────────────

    "run_bulk_extractor": {
        "caveats": [
            "bulk_extractor finds patterns in raw bytes — it does NOT respect file system boundaries.",
            "Email and URL extractors will match fragments in deleted file space and slack space — these may be historical.",
            "Credit card number (CCN) detection has a high false-positive rate on random binary data.",
        ],
        "advisories": [
            "URLs found by bulk_extractor may be from temporary files, browser cache, or deleted data.",
            "Treat bulk_extractor IOCs as leads for further investigation, not confirmed activity.",
        ],
        "corroboration": [
            "Cross-reference extracted email addresses with parse_pst_ost for email client confirmation.",
            "Cross-reference extracted URLs with parse_chrome_history for browser visit confirmation.",
        ],
    },

    "carve_files_foremost": {
        "caveats": [
            "foremost recovery rate depends on overwrite — files deleted long ago may be partially overwritten.",
            "Carved files have NO metadata — no original filename, creation time, or path.",
            "JPEG/PNG recovery is reliable; Word/Excel/ZIP recovery is approximate based on header/footer patterns.",
        ],
        "advisories": [
            "A recovered file proves it EXISTED on the media — it does not prove WHO created or accessed it.",
        ],
        "corroboration": [
            "Run analyze_with_exiftool on recovered files to extract embedded metadata.",
            "Run get_file_type on carved files to verify the magic bytes match the claimed extension.",
        ],
    },

    "detect_capabilities_capa": {
        "caveats": [
            "capa uses static code analysis — packed or obfuscated malware may evade capability detection.",
            "capa requires the file to be a PE executable — shellcode analysis requires a different invocation.",
            "Some capabilities (e.g. 'allocate memory') are present in legitimate software.",
        ],
        "advisories": [
            "A capa MITRE mapping is a static analysis finding — dynamic behavior may differ from detected capabilities.",
            "Multiple high-severity capabilities (injection + network + anti-analysis) together are a strong malware indicator.",
        ],
        "corroboration": [
            "Run extract_floss_strings to decode any obfuscated strings missed by static analysis.",
            "Submit the file hash via lookup_hash_reputation for VirusTotal cross-reference.",
        ],
    },

    "get_file_type": {
        "caveats": [
            "Magic byte detection identifies the file header — a partially-overwritten file may have a misidentified header.",
            "Polyglot files are valid in multiple formats simultaneously — both detections may be correct.",
        ],
        "advisories": [
            "Extension mismatch (masquerade_suspected=True) is a strong T1036.007 indicator but requires the file to be executable to be actionable.",
        ],
        "corroboration": [
            "Run analyze_with_exiftool to confirm file type via additional metadata.",
            "Run scan_file_with_yara against executable rules to check for malware signatures.",
        ],
    },

    # ── Linux forensics tools ─────────────────────────────────────────────────

    "get_linux_processes": {
        "caveats": [
            "linux.pslist reads the task_struct doubly-linked list — DKOM-hidden processes will NOT appear.",
            "Shell interpreter processes (bash, python) may be legitimate system processes — check parent context.",
        ],
        "advisories": [
            "A reverse shell process (nc, socat, bash -i) in process list is a high-confidence indicator of compromise.",
        ],
        "corroboration": [
            "Run get_linux_modules to check for kernel-level rootkit hiding processes.",
            "Run get_linux_network to check open sockets for suspicious processes.",
        ],
    },

    "get_linux_bash_history": {
        "caveats": [
            "Bash history in memory covers only the current session — prior sessions require ~/.bash_history on disk.",
            "Attackers commonly unset HISTFILE or set HISTSIZE=0 — absence of history is suspicious.",
        ],
        "advisories": [
            "wget/curl commands downloading from external IPs are T1105 (Ingress Tool Transfer) indicators.",
        ],
        "corroboration": [
            "Cross-reference commands with parse_syslog for corresponding system activity.",
            "Run parse_linux_crontab to check if any commands created persistence.",
        ],
    },

    "get_linux_modules": {
        "caveats": [
            "linux.check_modules compares /proc/modules list with kernel module list — requires correct kernel profile.",
            "Legitimate security modules (SELinux, AppArmor, auditd) may appear in module checks.",
        ],
        "advisories": [
            "A hidden kernel module is a definitive rootkit indicator (T1014).",
        ],
        "corroboration": [
            "Run get_linux_syscall to check for syscall table hooks by the hidden module.",
        ],
    },

    "parse_syslog": {
        "caveats": [
            "Syslog rotation may have removed logs from the incident time window.",
            "Log injection attacks can introduce false entries — verify high-confidence findings against kernel log.",
        ],
        "advisories": [
            "Mass SSH failed authentication from a single IP requires 3+ failures before attributing T1110 (Brute Force).",
        ],
        "corroboration": [
            "Cross-reference SSH logon success with get_linux_processes to confirm attacker session.",
            "Run parse_linux_crontab to check if attacker added persistence after gaining access.",
        ],
    },

    # ── Anti-forensics detection tools ───────────────────────────────────────

    "detect_timestomping": {
        "caveats": [
            "Some legitimate software (installers, backup tools) set $SI timestamps deliberately — not all deltas are malicious.",
            "A $SI vs $FN delta of exactly 0 seconds is also suspicious — tools that zero both timestamps are known.",
        ],
        "advisories": [
            "A $SI timestamp BEFORE the OS installation date strongly suggests timestomping.",
            "Round-number timestamps (2020-01-01 00:00:00) indicate attacker use of default timestomping values.",
        ],
        "corroboration": [
            "Run parse_usn_journal to find the real file creation timestamp from the journal record.",
            "Cross-reference the file path with parse_prefetch to confirm when it actually ran.",
        ],
    },

    "detect_log_wiping": {
        "caveats": [
            "A zero-byte EVTX file is suspicious, but may also result from a crash during log rotation.",
            "python-evtx is required for full event parsing — without it, only file size checks are performed.",
        ],
        "advisories": [
            "Event 1102 (Security log cleared) is one of the strongest anti-forensics indicators available.",
            "The absence of event logs for a time period when the system was running is itself evidence.",
        ],
        "corroboration": [
            "Run detect_event_log_tampering to check for audit policy changes that preceded the clearing.",
            "Use detect_contradictions LOG_WIPE_INDICATOR for record-ID gap analysis.",
        ],
    },

    "detect_secure_deletion": {
        "caveats": [
            "Prefetch-based detection only covers the Windows Prefetch directory — enabled only on non-server Windows.",
            "Some legitimate IT management tools (BleachBit for privacy) may appear — context matters.",
        ],
        "advisories": [
            "SDelete and similar tools overwrite file content — file content recovery is not possible after use.",
            "Detection of secure deletion tools is T1070.004 evidence even if the original files are gone.",
        ],
        "corroboration": [
            "Cross-reference execution timestamps with parse_event_logs logon sessions.",
            "Run detect_log_wiping to check if log clearing accompanied the secure deletion.",
        ],
    },

    # ── Document analysis tools ───────────────────────────────────────────────

    "analyze_pdf_doc": {
        "caveats": [
            "pdfid counts keyword occurrences but does not decode embedded content — /JavaScript count=1 is significant.",
            "PDFs with /XFA are dynamically rendered — static analysis may miss active content.",
        ],
        "advisories": [
            "A PDF with /JavaScript + /OpenAction is a high-confidence malicious document (T1566.001).",
            "CVE-2019-0797 and similar Acrobat vulnerabilities are triggered via /Launch actions.",
        ],
        "corroboration": [
            "Cross-reference the document's received time with parse_event_logs logon sessions.",
            "Run scan_file_with_yara with exploit document rules on the PDF.",
        ],
    },

    "analyze_ole_doc": {
        "caveats": [
            "olevba may produce false positives for macro-enabled templates that contain no harmful code.",
            "Heavily obfuscated macros may score LOW risk due to encoding — review decoded strings manually.",
        ],
        "advisories": [
            "AutoOpen + Shell + URLDownloadToFile combination is definitive malicious macro evidence.",
            "VBA stomping (hollow macros) may hide true code — olevba may show an empty macro.",
        ],
        "corroboration": [
            "Extract the SHA256 of the document and run lookup_hash_reputation.",
            "Cross-reference document metadata (author, company) with suspect identities.",
        ],
    },

    "detect_dde_payload": {
        "caveats": [
            "DDE detection is regex-based — highly obfuscated DDE fields may evade pattern matching.",
            "Modern Office (2016+) with security updates blocks DDE by default — check target Office version.",
        ],
        "advisories": [
            "A DDE field containing =cmd|'/c powershell' is definitive T1559.002 evidence.",
        ],
        "corroboration": [
            "Run analyze_with_exiftool on the document to find the author and last-modified identity.",
            "Cross-reference DDE command strings with get_command_history or parse_event_logs 4688.",
        ],
    },

    # ── Network extended tools ────────────────────────────────────────────────

    "parse_zeek_logs": {
        "caveats": [
            "Zeek conn.log records one entry per connection — bidirectional bytes are tracked separately.",
            "DNS log captures queries the Zeek sensor saw — encrypted DNS (DoH/DoT) will not appear.",
            "Zeek file extraction requires file analysis framework to be enabled in the Zeek configuration.",
        ],
        "advisories": [
            "DNS queries with subdomain length > 50 characters are a strong DNS tunneling indicator (T1071.004).",
            "A POST to an external IP without a matching DNS resolution is a hardcoded C2 indicator.",
        ],
        "corroboration": [
            "Run lookup_domain_reputation on domains with high query volumes.",
            "Cross-reference destination IPs with lookup_hash_reputation via passive DNS.",
        ],
    },

    "parse_iis_logs": {
        "caveats": [
            "IIS logs record only server-side activity — client actions (JS execution) are not logged.",
            "W3C format field order depends on IIS configuration — the #Fields header defines the order.",
            "URL encoding (%2e, %2f) must be decoded before applying detection patterns.",
        ],
        "advisories": [
            "A POST request to a .aspx file with HTTP 200 response from an external IP is a high-confidence web shell indicator.",
        ],
        "corroboration": [
            "Cross-reference client IPs with lookup_domain_reputation.",
            "Run parse_event_logs (System/Security) to confirm if IIS service was installed/modified.",
        ],
    },

    "parse_firewall_logs": {
        "caveats": [
            "Firewall logs record allowed/blocked connections — they do NOT capture payload content.",
            "A single blocked connection does not indicate a port scan — require 10+ unique ports from the same source.",
        ],
        "advisories": [
            "Outbound connections to non-standard ports (not 80/443/53) that were ALLOWED are worth investigating.",
        ],
        "corroboration": [
            "Run lookup_domain_reputation or lookup_hash_reputation on destination IPs.",
            "Cross-reference allowed connection times with parse_event_logs logon sessions.",
        ],
    },

    # ── Disk extended tools ───────────────────────────────────────────────────

    "verify_image_integrity": {
        "caveats": [
            "Computing SHA256 of a large image (>100 GB) takes several minutes — be patient.",
            "Hash mismatch may indicate: unintentional modification, write blocker failure, or deliberate tampering.",
        ],
        "advisories": [
            "A hash mismatch (integrity_verified=False) is a critical chain-of-custody failure — document immediately.",
            "Never proceed with analysis on a tampered image without supervisor notification.",
        ],
        "corroboration": [
            "Re-acquire the evidence if hash mismatch is confirmed.",
            "Compare against the acquisition report hash — the hash on the acquisition machine is authoritative.",
        ],
    },

    "analyze_slack_space": {
        "caveats": [
            "Slack space extraction requires correct partition offset — use get_partition_table first.",
            "Most slack space contains random data from previous file allocations — careful string filtering is required.",
        ],
        "advisories": [
            "Readable IOC strings (IPs, URLs) in slack space may be from DELETED files, not current malware.",
        ],
        "corroboration": [
            "Cross-reference IPs in slack space with get_network_connections from memory.",
            "Run carve_files_foremost to recover the deleted files that may have contained these strings.",
        ],
    },

    # ── Threat intel extended tools ───────────────────────────────────────────

    "lookup_hash_reputation": {
        "caveats": [
            "VirusTotal free API is rate-limited to 4 requests/minute — batch lookups may be throttled.",
            "A detection ratio of 0/70 does NOT prove a file is clean — it may be a novel sample.",
            "VirusTotal caches results — a recently submitted sample may show old results.",
        ],
        "advisories": [
            "Detection ratio > 5/70 is suspicious. > 20/70 is strong malware evidence.",
            "Known malware families (Emotet, Cobalt Strike) will have high detection ratios and known names.",
        ],
        "corroboration": [
            "Cross-reference the file hash with parse_amcache to confirm it ran on the system.",
            "Run detect_capabilities_capa on the file for MITRE-mapped behavior analysis.",
        ],
    },

    "search_mitre_technique": {
        "caveats": [
            "MITRE ATT&CK descriptions are generic — apply them to the specific evidence context.",
            "RAG results reflect the seeded knowledge base — run rag/ingest/run_all.py to ensure it is current.",
        ],
        "advisories": [
            "ATT&CK technique membership does not imply the technique is confirmed — evidence must be cited.",
        ],
        "corroboration": [
            "For each ATT&CK technique, identify the specific tool call that provides evidence for it.",
            "Cross-reference with adversarial_review to ensure the attribution is well-supported.",
        ],
    },

    "calculate_fuzzy_hash_similarity": {
        "caveats": [
            "ssdeep similarity is based on context-triggered piecewise hashing — file size affects reliability.",
            "Small files (< 4096 bytes) produce unreliable ssdeep scores — use SHA256 for exact matching instead.",
        ],
        "advisories": [
            "A similarity score >= 50 is strong evidence of malware variant relationship.",
        ],
        "corroboration": [
            "Cross-reference both files with lookup_hash_reputation for independent VirusTotal verdict.",
            "Run detect_capabilities_capa on both files to compare capability profiles.",
        ],
    },

    # ── Anti-forensics detection ───────────────────────────────────────────────

    "detect_timestomping": {
        "caveats": [
            "SI vs FN delta > 2 seconds is suspicious but NOT definitive — some legitimate installers update $SI.",
            "Round-number timestamps (00:00:00) may be set by backup/imaging software, not just attackers.",
            "Pre-epoch timestamps may result from clock skew or VM migration, not necessarily anti-forensics.",
        ],
        "advisories": [
            "Do NOT conclude timestomping without corroborating with Shimcache/Prefetch execution evidence.",
            "A $FN timestamp predating OS installation is highly suspicious but requires timeline cross-check.",
        ],
        "corroboration": [
            "Run parse_shimcache to see if the file appears in execution history despite anomalous timestamp.",
            "Run parse_prefetch to check execution times against MFT timestamps.",
            "Run filter_timeline around the anomalous timestamp to see surrounding file system activity.",
        ],
    },

    "detect_log_wiping": {
        "caveats": [
            "Zero-byte EVTX files are suspicious but may result from log rotation configuration.",
            "Event ID 1102 requires administrator rights — low-privileged attackers cannot trigger it.",
            "python-evtx must be installed; without it only file-size checks run.",
        ],
        "advisories": [
            "Absence of log clearing events does NOT mean logs were not wiped — wevtutil.exe leaves no 1102.",
            "Do NOT conclude log tampering without checking for wevtutil/Clear-EventLog in Prefetch/Shimcache.",
        ],
        "corroboration": [
            "Run detect_event_log_tampering for event ID 4719 (audit policy change).",
            "Run parse_prefetch to check for wevtutil.exe or powershell.exe execution.",
            "Run detect_secure_deletion to check if deletion tools were present.",
        ],
    },

    "detect_secure_deletion": {
        "caveats": [
            "Presence of SDelete/CCleaner in Prefetch proves execution, not necessarily evidence destruction.",
            "IT departments legitimately use CCleaner/BleachBit — context matters.",
            "File-system search only covers common installation paths; portable tools may be missed.",
        ],
        "advisories": [
            "Do NOT attribute data destruction without establishing intent and timeline proximity to incident.",
        ],
        "corroboration": [
            "Run detect_timestomping to check if deletion preceded timestamp anomalies.",
            "Run parse_usn_journal to look for burst file deletion events.",
            "Run detect_log_wiping to check if logs were also cleared.",
        ],
    },

    "detect_ads_streams": {
        "caveats": [
            "Zone.Identifier is a legitimate Mark-of-the-Web ADS — not suspicious.",
            "Streams tool (Sysinternals) may not be available; fls fallback has lower accuracy.",
            "ADS are NTFS-only; FAT32 and exFAT volumes cannot have ADS.",
        ],
        "advisories": [
            "A suspicious ADS requires content examination (icat) to determine if it is executable code.",
            "Do NOT report an ADS as malicious without extracting and analyzing its content.",
        ],
        "corroboration": [
            "Extract ADS content with extract_file (icat) and analyze with get_file_type/detect_capabilities_capa.",
            "Run scan_file_with_yara on extracted ADS content.",
        ],
    },

    "analyze_vss_shadows": {
        "caveats": [
            "VSS requires NTFS and is often disabled on SSDs for performance reasons — absence is not proof of deletion.",
            "vshadowinfo may require root/elevated privileges on SIFT.",
            "Some editions of Windows (Home) have VSS disabled by default.",
        ],
        "advisories": [
            "Zero shadow copies may be normal on SSDs or minimal-install VMs — do NOT conclude ransomware without corroboration.",
        ],
        "corroboration": [
            "Run parse_event_logs and look for Event ID 7036 (service stopped) or vssadmin in process list.",
            "Run parse_prefetch to check if vssadmin.exe was recently executed.",
            "Run get_command_history for 'vssadmin delete shadows' or 'wmic shadowcopy delete'.",
        ],
    },

    "detect_prefetch_anomalies": {
        "caveats": [
            "Prefetch is disabled by default on Windows Server and SSDs with SuperFetch disabled.",
            "Temp-path execution may be legitimate (installer, update package).",
            "Anti-forensics tool detection is keyword-based — obfuscated names bypass it.",
        ],
        "advisories": [
            "Execution from %TEMP% alone does NOT confirm malware — corroborate with hash lookup.",
        ],
        "corroboration": [
            "Run parse_shimcache for execution corroboration independent of Prefetch.",
            "Run parse_amcache to get the SHA1 hash of the executed binary for VT lookup.",
            "Run parse_event_logs for Event ID 4688 (process creation) if audit policy enabled.",
        ],
    },

    "detect_event_log_tampering": {
        "caveats": [
            "Event ID 7040 (service start type change) may be legitimate GPO enforcement.",
            "Requires python-evtx; without it returns a manual check note only.",
        ],
        "advisories": [
            "Audit policy changes via GPO are normal in enterprise environments — check the account that made the change.",
        ],
        "corroboration": [
            "Run detect_log_wiping to correlate with zero-byte EVTX files.",
            "Run parse_shimcache for auditpol.exe or wevtutil.exe execution.",
        ],
    },

    # ── File carving and static analysis ──────────────────────────────────────

    "run_bulk_extractor": {
        "caveats": [
            "bulk_extractor extracts features WITHOUT parsing the file system — results may overlap with FS artifacts.",
            "False positives are common in email and URL feature files (base64 in images, HTML in docs).",
            "Credit card regex matches are high FP — require manual confirmation.",
        ],
        "advisories": [
            "bulk_extractor emails/URLs are NOT confirmed IOCs — they require manual triage.",
        ],
        "corroboration": [
            "Run lookup_ip_reputation on discovered IPs.",
            "Run lookup_domain_reputation on discovered domains.",
            "Cross-reference email addresses with parse_pst_ost for context.",
        ],
    },

    "carve_files_foremost": {
        "caveats": [
            "File carving recovers partial/fragmented files — many carved files are corrupt or truncated.",
            "Carving by header/footer only; fragmented files may be unrecoverable.",
            "High false-positive rate for JPEG (JPEG fragments are common in swap/RAM).",
        ],
        "advisories": [
            "Carved EXE/DLL files may be corrupt — do NOT run them; analyze statically only.",
            "A carved file may come from deleted legitimate software, not attacker activity.",
        ],
        "corroboration": [
            "Calculate hashes with calculate_file_hashes and look up with lookup_hash_reputation.",
            "Run get_file_type on carved files to verify actual type.",
            "Run scan_file_with_yara on carved executables.",
        ],
    },

    "carve_files_scalpel": {
        "caveats": [
            "scalpel requires a configuration file — default config may not be enabled.",
            "Same fragmentation and truncation caveats as foremost.",
        ],
        "advisories": [
            "Carved files require hash verification before reporting as evidence.",
        ],
        "corroboration": [
            "Cross-reference carved file timestamps with MFT timeline from parse_mft.",
            "Run calculate_file_hashes + lookup_hash_reputation on carved executables.",
        ],
    },

    "analyze_with_exiftool": {
        "caveats": [
            "Metadata can be trivially modified or stripped — absence of metadata is not suspicious.",
            "GPS coordinates in photos require timezone correction for accurate geolocation.",
            "LastSavedBy field reflects the Office installation name, not necessarily the attacker's real name.",
        ],
        "advisories": [
            "Author/creator fields are user-controlled — do NOT treat as definitive attacker identity without corroboration.",
        ],
        "corroboration": [
            "Cross-reference author name with parse_sam_hive and parse_event_logs for known usernames.",
            "Check GPS coordinates against known attacker infrastructure locations.",
        ],
    },

    "calculate_file_hashes": {
        "caveats": [
            "Hash is only as reliable as the file acquisition — verify image integrity first.",
            "ssdeep requires the ssdeep binary; falls back to a note if not installed.",
        ],
        "advisories": [
            "A clean VirusTotal result does NOT mean the file is benign — new/targeted malware has 0 detections.",
        ],
        "corroboration": [
            "Run lookup_hash_reputation with the SHA256 for VirusTotal verdict.",
            "Run detect_capabilities_capa if the file is an executable.",
            "Run extract_floss_strings to find obfuscated C2 indicators.",
        ],
    },

    "detect_capabilities_capa": {
        "caveats": [
            "capa requires pip3 install capa and a current rules database.",
            "Packed/obfuscated binaries defeat capa — run extract_floss_strings + detect_packer first.",
            "capa rules are static signatures — novel capabilities may not be detected.",
        ],
        "advisories": [
            "capa capability detection is NOT malware classification — a capability may be used legitimately.",
            "Do NOT report a binary as malware based solely on capa output without additional evidence.",
        ],
        "corroboration": [
            "Run lookup_hash_reputation on the file SHA256.",
            "Run scan_file_with_yara for family-specific signatures.",
            "Run extract_floss_strings to find configuration strings not in static code.",
        ],
    },

    "extract_floss_strings": {
        "caveats": [
            "FLOSS requires pip3 install floss and may be slow on large binaries (>30 seconds).",
            "FLOSS cannot decode all obfuscation schemes — custom XOR keys and compression may evade it.",
            "Decoded strings may be from legitimate software components bundled with the malware.",
        ],
        "advisories": [
            "Decoded IP/URL strings are IOC CANDIDATES — they require lookup_ip_reputation confirmation.",
        ],
        "corroboration": [
            "Run lookup_ip_reputation on all decoded IPs.",
            "Run lookup_domain_reputation on all decoded domains.",
            "Run detect_capabilities_capa to map decoded string context to MITRE techniques.",
        ],
    },

    "get_file_type": {
        "caveats": [
            "Magic byte detection covers common types — proprietary formats may be misidentified.",
            "The 'file' command is not available on all systems; falls back to Python magic byte map.",
        ],
        "advisories": [
            "Extension mismatch alone is suspicious but NOT definitive — some tools legitimately rename files.",
        ],
        "corroboration": [
            "Run analyze_with_exiftool to inspect embedded metadata.",
            "Run scan_file_with_yara to check for known malware signatures.",
            "If PE detected: run get_pe_metadata and detect_capabilities_capa.",
        ],
    },

    # ── Browser artifacts ──────────────────────────────────────────────────────

    "parse_chrome_history": {
        "caveats": [
            "Chrome history is stored in SQLite — WAL file may contain recent entries not in main DB.",
            "History may be cleared by the user or the attacker — absence is not conclusive.",
            "Multiple Chrome profiles per user are common — check all profile directories.",
        ],
        "advisories": [
            "A cloud storage domain visit does NOT confirm exfiltration — verify with SRUM bytes_sent.",
        ],
        "corroboration": [
            "Run parse_srum to quantify bytes sent to cloud storage domains.",
            "Run parse_chrome_extensions to check for data-exfiltrating extensions.",
            "Run parse_browser_passwords if credential theft is suspected.",
        ],
    },

    "parse_firefox_history": {
        "caveats": [
            "Firefox uses places.sqlite + WAL — both must be present for complete history.",
            "Private browsing (Incognito equivalent) history is NOT stored.",
        ],
        "advisories": [
            "Firefox history timestamps are in microseconds since epoch — verify timezone conversion.",
        ],
        "corroboration": [
            "Run parse_srum to quantify network activity from Firefox.",
            "Cross-reference visited domains with lookup_domain_reputation.",
        ],
    },

    "parse_chrome_extensions": {
        "caveats": [
            "Extension IDs are stable; names can be changed by the developer.",
            "Sideloaded extensions (not from Chrome Web Store) are higher risk but may be legitimate enterprise tools.",
        ],
        "advisories": [
            "An extension with webRequest/nativeMessaging permissions is suspicious but not confirmed malicious.",
        ],
        "corroboration": [
            "Search extension IDs in lookup_domain_reputation / external threat databases.",
            "Run parse_chrome_history to see if the extension was recently installed.",
        ],
    },

    "parse_browser_cookies": {
        "caveats": [
            "Cookie values are encrypted on Chrome/Edge (DPAPI) — plaintext extraction requires decryption key from user profile.",
            "Cookies expire — session cookies from an incident may be gone by acquisition time.",
        ],
        "advisories": [
            "Cookie presence does NOT prove session hijacking — confirm with network traffic or auth logs.",
        ],
        "corroboration": [
            "Cross-reference cookie domains with parse_chrome_history URLs.",
            "Check parse_event_logs for authentication events at matching timestamps.",
        ],
    },

    "run_hindsight": {
        "caveats": [
            "Hindsight requires pip3 install pyhindsight.",
            "Results quality depends on Chrome version — very new versions may have schema changes.",
        ],
        "advisories": [
            "Hindsight reconstructed history should be cross-validated against raw SQLite parse_chrome_history.",
        ],
        "corroboration": [
            "Cross-reference Hindsight URLs with lookup_domain_reputation.",
        ],
    },

    "parse_browser_passwords": {
        "caveats": [
            "Chrome/Edge passwords use DPAPI encryption — DPAPI master key must be available for decryption.",
            "On a forensic image, DPAPI decryption is not possible without the user's password or domain backup key.",
        ],
        "advisories": [
            "Encrypted password entries prove credential storage but do NOT expose plaintext without decryption key.",
        ],
        "corroboration": [
            "Use get_hashdump (memory) or Volatility lsadump for DPAPI key extraction from live system.",
        ],
    },

    "parse_ie_edge_legacy_history": {
        "caveats": [
            "IE/Edge Legacy history is in WebCacheV01.dat (ESE database) — requires esedbexport or similar.",
            "Edge Legacy was replaced by Chromium-based Edge — verify which Edge version is present.",
        ],
        "advisories": [
            "IE compatibility mode visits may appear in Edge Legacy history — check User-Agent for context.",
        ],
        "corroboration": [
            "Cross-reference with parse_lnk_files for file:// URL accesses.",
        ],
    },

    "parse_chromium_cache": {
        "caveats": [
            "Cache entries may contain partial/truncated content.",
            "Cache eviction means recent entries may overwrite incident-time entries.",
        ],
        "advisories": [
            "Cached malware delivery pages are evidence of browsing, not execution — corroborate with Prefetch.",
        ],
        "corroboration": [
            "Run parse_chrome_history to match cache URLs to browsing timeline.",
            "Run scan_file_with_yara on any extracted cached executables.",
        ],
    },

    # ── Email artifacts ────────────────────────────────────────────────────────

    "parse_pst_ost": {
        "caveats": [
            "Requires readpst (libpst) — install with apt install pst-utils.",
            "OST files may not be fully exportable if Exchange server is offline.",
            "PST password protection blocks export.",
        ],
        "advisories": [
            "Email content alone does NOT prove data exfiltration — requires evidence the email was sent.",
        ],
        "corroboration": [
            "Run parse_event_logs for Outlook process events and SMTP connection logs.",
            "Cross-reference attachment hashes with lookup_hash_reputation.",
            "Run parse_srum for Outlook process network bytes.",
        ],
    },

    "parse_thunderbird": {
        "caveats": [
            "Thunderbird stores mail in mbox format — each folder is a flat file.",
            "IMAP accounts may only cache recent emails locally.",
        ],
        "advisories": [
            "Local mail store only reflects what was downloaded — server-side sent items may not be present.",
        ],
        "corroboration": [
            "Cross-reference sender addresses with known threat actor infrastructure.",
            "Run analyze_email_headers on suspicious .eml files.",
        ],
    },

    "parse_eml_file": {
        "caveats": [
            "From/Reply-To headers are trivially spoofed — use Received headers for actual routing.",
            "DKIM/SPF results in headers are from the receiving MTA, not independently verified here.",
        ],
        "advisories": [
            "A malicious attachment in an .eml does NOT prove the user opened it — check Prefetch/Shimcache.",
        ],
        "corroboration": [
            "Run analyze_email_headers for full spoofing analysis.",
            "Run calculate_file_hashes + lookup_hash_reputation on all attachments.",
            "Run scan_file_with_yara on any executable attachments.",
        ],
    },

    "extract_email_attachments": {
        "caveats": [
            "Bulk extraction may produce thousands of files — triage by extension and hash before analysis.",
            "Password-protected archives cannot be extracted without the password.",
        ],
        "advisories": [
            "Attachment extraction does NOT mean the attachment was opened — verify with Prefetch/Shimcache.",
        ],
        "corroboration": [
            "Run get_file_type on all EXE/DLL/PDF/DOC attachments.",
            "Run lookup_hash_reputation on attachment hashes.",
        ],
    },

    "analyze_email_headers": {
        "caveats": [
            "SPF/DKIM results depend on DNS lookup availability — offline forensics cannot re-verify.",
            "X-Originating-IP is user-controlled in some mail systems.",
        ],
        "advisories": [
            "A failed SPF result alone is common with legitimate forwarded email — do NOT conclude spoofing.",
        ],
        "corroboration": [
            "Run lookup_ip_reputation on all Received header IPs.",
            "Cross-reference sender domain with lookup_domain_reputation.",
        ],
    },

    # ── Cloud storage artifacts ────────────────────────────────────────────────

    "parse_dropbox_logs": {
        "caveats": [
            "Dropbox logs may be incomplete if sync was disabled or the app was uninstalled.",
            "Log format varies by Dropbox version — parsing may miss fields in newer versions.",
        ],
        "advisories": [
            "A Dropbox sync event proves the file was synced, not that it was intentionally exfiltrated.",
        ],
        "corroboration": [
            "Run parse_srum to quantify bytes uploaded from Dropbox process.",
            "Cross-reference synced filenames with sensitive file patterns (*.kdbx, *.pfx, source code).",
        ],
    },

    "parse_onedrive_logs": {
        "caveats": [
            "OneDrive logs are in binary/SQLite format — parsing may be incomplete.",
            "Corporate OneDrive and personal OneDrive have different log locations.",
        ],
        "advisories": [
            "OneDrive sync of sensitive files may be legitimate corporate policy — check DLP policy context.",
        ],
        "corroboration": [
            "Run parse_srum for OneDrive process network bytes.",
            "Run parse_event_logs for Azure AD / Office 365 sign-in events.",
        ],
    },

    "parse_google_drive_logs": {
        "caveats": [
            "Google Drive for Desktop logs may be minimal compared to other cloud providers.",
        ],
        "advisories": [
            "Google Drive sync does NOT confirm exfiltration — verify with SRUM and network logs.",
        ],
        "corroboration": [
            "Cross-reference with parse_chrome_history for drive.google.com uploads.",
            "Run parse_srum for GoogleDriveFS process bytes.",
        ],
    },

    "parse_slack_artifacts": {
        "caveats": [
            "Slack desktop caches only the channels and messages downloaded to the local client.",
            "Enterprise Slack may have DLP controls that prevent sensitive content from reaching the client.",
        ],
        "advisories": [
            "Slack message content in local cache may be incomplete — full history requires eDiscovery export.",
        ],
        "corroboration": [
            "Run parse_event_logs for Slack network activity.",
            "Cross-reference file shares with lookup_hash_reputation.",
        ],
    },

    "parse_teams_artifacts": {
        "caveats": [
            "Teams stores data in multiple SQLite databases across user profile directories.",
            "Teams data is partially encrypted (DPAPI) — some fields may not be decryptable offline.",
        ],
        "advisories": [
            "Teams chat content may be truncated — full audit trail requires Microsoft Purview compliance export.",
        ],
        "corroboration": [
            "Run parse_event_logs for Teams-related authentication (Azure AD token) events.",
        ],
    },

    "parse_icloud_logs": {
        "caveats": [
            "iCloud for Windows logs are minimal compared to macOS native iCloud logs.",
            "iCloud log format changes frequently with Apple software updates.",
        ],
        "advisories": [
            "iCloud sync events require correlation with SRUM network bytes to confirm exfiltration volume.",
        ],
        "corroboration": [
            "Run parse_srum for iCloud process bytes.",
        ],
    },

    # ── Document analysis ──────────────────────────────────────────────────────

    "analyze_pdf_doc": {
        "caveats": [
            "pdfid counts keyword occurrences — a high /JavaScript count may be from legitimate analytics.",
            "Embedded objects require extraction (pdfextract) for full analysis.",
            "PDF risk score is heuristic — novel exploits may score low.",
        ],
        "advisories": [
            "Do NOT conclude a PDF is malicious based solely on /JavaScript presence — corroborate with execution evidence.",
        ],
        "corroboration": [
            "Run scan_file_with_yara with the suspicious_strings rule set.",
            "Check Prefetch/Shimcache for Reader/Acrobat spawning cmd.exe or powershell.exe.",
            "Run parse_event_logs for process creation (4688) from PDF reader process.",
        ],
    },

    "analyze_ole_doc": {
        "caveats": [
            "oletools requires pip3 install oletools.",
            "VBA macro presence alone is normal in many legitimate Office documents.",
            "Obfuscated macros may evade oletools pattern detection.",
        ],
        "advisories": [
            "Do NOT report a macro as malicious without identifying a specific malicious action (Shell, WScript, download).",
        ],
        "corroboration": [
            "Run parse_event_logs for Office process spawning cmd.exe/wscript.exe (Event 4688).",
            "Run parse_prefetch for WINWORD.EXE/EXCEL.EXE execution timestamps.",
            "Run scan_file_with_yara on the document.",
        ],
    },

    "analyze_rtf_doc": {
        "caveats": [
            "RTF is highly polymorphic — obfuscated RTF may evade rtfobj parsing.",
            "Embedded objects may require extraction and separate analysis.",
        ],
        "advisories": [
            "RTF with embedded objects requires CLSID lookup to confirm exploit potential.",
        ],
        "corroboration": [
            "Cross-reference extracted CLSIDs with known CVE databases.",
            "Run parse_event_logs for Office process creation events.",
        ],
    },

    "analyze_zip_archive": {
        "caveats": [
            "Password-protected ZIPs cannot be inspected without the password.",
            "ZIP64 extensions may not be fully parsed.",
        ],
        "advisories": [
            "Double-extension detection (.pdf.exe) is heuristic — verify with get_file_type.",
        ],
        "corroboration": [
            "Run get_file_type on all extracted entries.",
            "Run calculate_file_hashes + lookup_hash_reputation on suspicious entries.",
        ],
    },

    "detect_dde_payload": {
        "caveats": [
            "DDE/DDEAUTO was patched by Microsoft in 2017 — only affects unpatched Office installations.",
            "False positives possible in documents with embedded field codes for legitimate purposes.",
        ],
        "advisories": [
            "DDE presence requires corroboration that the document was opened — check Prefetch/recent files.",
        ],
        "corroboration": [
            "Run parse_event_logs for cmd.exe/powershell.exe spawned by WINWORD.EXE.",
            "Run parse_lnk_files to confirm the document was accessed.",
        ],
    },

    # ── Linux forensics ────────────────────────────────────────────────────────

    "get_linux_processes": {
        "caveats": [
            "linux.pslist uses Volatility 3 Linux profile — profile must match kernel version exactly.",
            "Some kernel threads have similar names to malicious processes — verify by path and parent.",
        ],
        "advisories": [
            "A suspicious process name alone is NOT confirmation of compromise — verify path and parent chain.",
        ],
        "corroboration": [
            "Run get_linux_modules to check for kernel rootkit LKMs.",
            "Run get_linux_network to see if the suspicious process has network connections.",
            "Run get_linux_malfind for injected code in Linux process address space.",
        ],
    },

    "get_linux_bash_history": {
        "caveats": [
            "Bash history can be disabled (HISTFILE=/dev/null) or truncated — absence is suspicious.",
            "Commands from non-interactive sessions (cron, scripts) may not appear in .bash_history.",
        ],
        "advisories": [
            "A single suspicious command in bash history requires timeline corroboration before attribution.",
        ],
        "corroboration": [
            "Run parse_syslog to find corresponding auth/sudo events.",
            "Run get_linux_modules to check if any kernel module was loaded after the suspicious commands.",
        ],
    },

    "get_linux_network": {
        "caveats": [
            "linux.netstat reflects connections at memory acquisition time — transient connections may be missed.",
        ],
        "advisories": [
            "An ESTABLISHED connection to an external IP requires lookup_ip_reputation before attribution.",
        ],
        "corroboration": [
            "Run lookup_ip_reputation on all external IPs.",
            "Run parse_zeek_logs or parse_apache_logs to correlate network activity.",
        ],
    },

    "get_linux_modules": {
        "caveats": [
            "linux.lsmod lists modules known to the kernel — DKOM-hidden LKMs will NOT appear.",
            "Unsigned module presence is suspicious but may be a legitimate custom driver.",
        ],
        "advisories": [
            "Do NOT conclude rootkit without corroborating with get_linux_syscall hook detection.",
        ],
        "corroboration": [
            "Run get_linux_syscall to check for syscall table hooks.",
            "Run get_linux_processes to see if suspicious processes appeared at module load time.",
        ],
    },

    "get_linux_syscall": {
        "caveats": [
            "Syscall table hook detection requires accurate kernel symbol resolution — version mismatch causes false negatives.",
        ],
        "advisories": [
            "A hooked syscall is very high confidence rootkit evidence but requires kernel symbol corroboration.",
        ],
        "corroboration": [
            "Run get_linux_modules to identify which LKM registered the hook.",
            "Run get_linux_malfind for userland injection from the same actor.",
        ],
    },

    "get_linux_malfind": {
        "caveats": [
            "Linux malfind has higher false positive rate than Windows — JIT (Java, Node.js) creates RWX regions.",
        ],
        "advisories": [
            "Linux malfind hits require manual review — do NOT report as confirmed injection without PE/ELF header.",
        ],
        "corroboration": [
            "Cross-reference with get_linux_processes to confirm the PID is suspicious.",
        ],
    },

    "get_linux_envars": {
        "caveats": [
            "Environment variables reflect process launch state — modified envars may not appear here.",
        ],
        "advisories": [
            "LD_PRELOAD in an environment is strongly suspicious but may be set by legitimate profiling tools.",
        ],
        "corroboration": [
            "Run get_linux_processes to check the process parent chain for the LD_PRELOAD setter.",
        ],
    },

    "get_linux_mounts": {
        "caveats": [
            "Mount table reflects state at acquisition time — transient mounts may be unmounted.",
        ],
        "advisories": [
            "A hidden bind mount or FUSE mount requires correlation with file system artifacts to confirm purpose.",
        ],
        "corroboration": [
            "Run parse_syslog to find mount/umount events around incident time.",
        ],
    },

    "parse_syslog": {
        "caveats": [
            "Syslog may be forwarded to a remote host — local copy may be incomplete or truncated.",
            "Auth.log rotation may have removed pre-incident entries.",
        ],
        "advisories": [
            "Authentication failure bursts may be scan/brute-force noise, not targeted attack — check source IP reputation.",
        ],
        "corroboration": [
            "Run lookup_ip_reputation on source IPs of authentication failures.",
            "Run get_linux_bash_history to correlate authenticated sessions with commands.",
        ],
    },

    "parse_linux_crontab": {
        "caveats": [
            "System crontabs (/etc/cron*) and user crontabs (crontab -l) may differ.",
            "Anacron entries may not appear in standard crontab files.",
        ],
        "advisories": [
            "A crontab entry running a script from /tmp or home directory is suspicious — verify the script content.",
        ],
        "corroboration": [
            "Run get_linux_bash_history to check if crontab was modified during the incident window.",
            "Run parse_syslog for cron execution entries at the scheduled times.",
        ],
    },

    # ── Network forensics extended ─────────────────────────────────────────────

    "parse_zeek_logs": {
        "caveats": [
            "Zeek logs reflect network traffic at the sensor — blind spots exist if traffic is encrypted or tunneled.",
            "DNS over HTTPS (DoH) bypasses DNS log visibility.",
            "Zeek log retention period may not cover the full incident timeline.",
        ],
        "advisories": [
            "A DNS query to a suspicious domain does NOT confirm a successful connection or data transfer.",
        ],
        "corroboration": [
            "Cross-reference Zeek conn.log bytes with SRUM process bytes for the same time window.",
            "Run lookup_domain_reputation on all suspicious Zeek DNS queries.",
            "Run parse_iis_logs or parse_apache_logs to correlate HTTP activity.",
        ],
    },

    "parse_iis_logs": {
        "caveats": [
            "IIS log timestamps are in UTC — timezone conversion required for incident timeline.",
            "Scanner/crawler traffic creates significant noise — web shell detection uses extension + parameter patterns.",
        ],
        "advisories": [
            "A web shell URL pattern requires corroboration that the file exists on disk (parse_mft / get_file_listing).",
        ],
        "corroboration": [
            "Run get_file_listing to verify the web shell path exists on disk.",
            "Run scan_file_with_yara (webshells ruleset) on the suspect file.",
            "Run parse_event_logs for IIS Worker Process spawning cmd.exe.",
        ],
    },

    "parse_apache_logs": {
        "caveats": [
            "Apache combined log format may vary — custom formats reduce parser accuracy.",
            "Reverse proxy deployments may mask real client IPs with proxy IP.",
        ],
        "advisories": [
            "SQLi/traversal patterns in logs indicate ATTEMPT — confirm success via HTTP response code (200/302).",
        ],
        "corroboration": [
            "Filter for 200/302 responses to suspicious URLs to confirm successful exploitation.",
            "Run lookup_ip_reputation on attacker source IPs.",
        ],
    },

    "extract_pcap_files": {
        "caveats": [
            "Requires NetworkMiner or tshark — check availability on SIFT.",
            "TLS-encrypted traffic cannot be reassembled without session keys.",
        ],
        "advisories": [
            "Extracted files from PCAP may be partial if the capture started mid-session.",
        ],
        "corroboration": [
            "Run get_file_type + scan_file_with_yara on extracted files.",
            "Calculate hashes and run lookup_hash_reputation.",
        ],
    },

    "parse_firewall_logs": {
        "caveats": [
            "Firewall DENY logs prove attempted connections, not successful ones.",
            "Source IP in firewall logs may be NAT/proxy — not necessarily attacker's real IP.",
        ],
        "advisories": [
            "Internal-to-internal deny traffic may indicate compromised host attempting lateral movement.",
        ],
        "corroboration": [
            "Cross-reference with parse_zeek_logs to confirm traffic volume.",
            "Run lookup_ip_reputation on external source IPs.",
        ],
    },

    "decode_rdp_bitmap_cache": {
        "caveats": [
            "RDP bitmap cache only captures screen tiles — not a continuous session recording.",
            "Cache files require BMC-Tools or bmc_tools.py for reconstruction.",
        ],
        "advisories": [
            "Reconstructed bitmap tiles provide visual evidence of RDP session but may be incomplete or jumbled.",
        ],
        "corroboration": [
            "Cross-reference with parse_event_logs for RDP logon events (Event ID 4624 Type 10).",
            "Check parse_shimcache/parse_prefetch for mstsc.exe execution times.",
        ],
    },

    "parse_netflow": {
        "caveats": [
            "NetFlow only provides metadata (IP, port, bytes) — no packet content.",
            "Sampling-based NetFlow (1:1000) may miss low-volume C2 beaconing.",
        ],
        "advisories": [
            "Large bytes_sent to external IP is exfiltration EVIDENCE, not proof — corroborate with endpoint artifacts.",
        ],
        "corroboration": [
            "Cross-reference top talkers with parse_zeek_logs for protocol detail.",
            "Run lookup_ip_reputation on all external large-transfer destinations.",
        ],
    },

    # ── Extended registry ──────────────────────────────────────────────────────

    "parse_shellbags": {
        "caveats": [
            "Shellbags persist after the target folder is deleted — this is a key forensic artifact.",
            "SbECmd.exe requires mono on Linux SIFT.",
            "Shellbag entries for USB drives require correlation with DeviceClasses registry for USB serial number.",
        ],
        "advisories": [
            "A shellbag entry for a network share proves browsing, not necessarily data access — corroborate with MRU.",
        ],
        "corroboration": [
            "Cross-reference network path shellbags with parse_event_logs for SMB authentication (Event 4624 Type 3).",
            "Run parse_lnk_files to confirm files accessed on the network share.",
        ],
    },

    "parse_windows_timeline": {
        "caveats": [
            "Windows Timeline (ActivitiesCache.db) is only present on Windows 10 version 1709+.",
            "Timeline sync to Microsoft cloud may have been disabled by group policy.",
            "Focus time and clipboard sync require specific Timeline settings to be enabled.",
        ],
        "advisories": [
            "Timeline activity is user-session based — background processes and services do NOT appear.",
        ],
        "corroboration": [
            "Cross-reference file open events with parse_lnk_files for corroboration.",
            "Compare app launch times with parse_prefetch for independent execution confirmation.",
        ],
    },

    "parse_bam_dam": {
        "caveats": [
            "BAM/DAM is Windows 10 version 1709+ only — not present on older systems.",
            "BAM entries persist after executable deletion — only creation date is missing.",
            "Only user-mode executables are tracked — kernel drivers and services may not appear.",
        ],
        "advisories": [
            "BAM provides LAST execution time only — total run count is not recorded.",
        ],
        "corroboration": [
            "Cross-reference with parse_prefetch for corroboration (run count + last 8 run times).",
            "Run parse_amcache for SHA1 hash of executed binaries for VT lookup.",
        ],
    },

    "parse_typed_paths": {
        "caveats": [
            "TypedPaths only records MANUALLY typed paths — paths navigated by clicking are not recorded.",
            "The MRU list has a maximum size — oldest entries are purged.",
        ],
        "advisories": [
            "A network share in TypedPaths proves the user TYPED that path — not necessarily that they accessed data.",
        ],
        "corroboration": [
            "Cross-reference with parse_shellbags for folder navigation evidence.",
            "Run parse_event_logs for SMB logon events (4624 Type 3) at the same time.",
        ],
    },

    "parse_run_mru": {
        "caveats": [
            "Run MRU has a fixed size — oldest entries are purged by FIFO.",
            "Only Win+R dialog entries are recorded — cmd.exe opened from Start menu is not.",
        ],
        "advisories": [
            "A malicious command in Run MRU proves ATTEMPT but not necessarily EXECUTION — check Prefetch.",
        ],
        "corroboration": [
            "Run parse_prefetch for the executed binary.",
            "Run parse_event_logs for Event 4688 (process creation) around the same time.",
        ],
    },

    "parse_open_save_mru": {
        "caveats": [
            "OpenSavePidlMRU stores SHELLITEMIDs (binary path format) — requires SbECmd for full decode.",
            "MRU is application-specific — separate entries exist per extension/application.",
        ],
        "advisories": [
            "An MRU entry for a sensitive file proves ACCESS via a file dialog, not necessarily exfiltration.",
        ],
        "corroboration": [
            "Cross-reference with parse_lnk_files for the same file path.",
            "Run parse_jump_lists for application-specific recent file access.",
        ],
    },

    "parse_wordwheelquery": {
        "caveats": [
            "WordWheelQuery only records searches via Explorer address bar and File Explorer search box.",
            "Outlook/Edge/Office internal searches are NOT recorded here.",
        ],
        "advisories": [
            "A search for 'passwords' or 'salary' proves INTENT but requires file access artifacts to confirm OUTCOME.",
        ],
        "corroboration": [
            "Cross-reference search terms with parse_lnk_files and parse_open_save_mru for accessed files.",
            "Run parse_event_logs for file access audit events (if Object Access auditing was enabled).",
        ],
    },

    "parse_installed_software": {
        "caveats": [
            "SOFTWARE hive only records MSI-installed software — portable tools are NOT listed.",
            "Uninstalled software may leave registry remnants with no Install Date.",
            "Version number alone does NOT confirm a vulnerable version was exploited.",
        ],
        "advisories": [
            "A remote access tool being installed is suspicious — but verify install date proximity to incident.",
        ],
        "corroboration": [
            "Run parse_prefetch for the installer executable (setup.exe, msiexec.exe).",
            "Run parse_event_logs for Event 11707 (software installed) or 11724 (software uninstalled).",
        ],
    },

    "parse_sam_hive": {
        "caveats": [
            "SAM hive requires SYSTEM hive key for password hash extraction — this tool only reads account metadata.",
            "Account RID < 1000 are built-in accounts (Administrator = 500, Guest = 501).",
        ],
        "advisories": [
            "A new local account (RID >= 1000, recent creation) is suspicious — corroborate with event logs.",
        ],
        "corroboration": [
            "Run parse_event_logs for Event 4720 (user account created) at the same timestamp.",
            "Run get_hashdump (memory) for actual NTLM hash extraction.",
        ],
    },

    "parse_logon_history": {
        "caveats": [
            "SECURITY hive requires SYSTEM key for full LSA secrets decryption — metadata only without it.",
            "Cached credentials (DCC2) use a slow KDF — cracking is time-intensive.",
            "Maximum of 10 cached domain credentials by default (configurable via GPO).",
        ],
        "advisories": [
            "Presence of a domain account in cached credentials proves PRIOR LOGIN but not necessarily malicious access.",
        ],
        "corroboration": [
            "Run parse_event_logs for Event 4624 Type 3 (network logon) for the same account.",
            "Run get_lsadump (memory) for live LSA secret extraction.",
        ],
    },

    # ── Extended disk forensics ────────────────────────────────────────────────

    "get_fs_statistics": {
        "caveats": [
            "fsstat requires correct partition offset — wrong offset returns garbage or error.",
            "Volume creation time may reflect imaging, not original OS installation.",
        ],
        "advisories": [
            "Use get_partition_table first to obtain the correct sector offset before calling get_fs_statistics.",
        ],
        "corroboration": [
            "Cross-reference last mount time with incident timeline.",
        ],
    },

    "get_image_info": {
        "caveats": [
            "ewfinfo is only available for E01/EWF format images.",
            "mmls may fail on non-standard partition table types (GPT on some ARM images).",
        ],
        "advisories": [
            "If ewfinfo MD5 != computed hash from verify_image_integrity, the image may have been modified post-acquisition.",
        ],
        "corroboration": [
            "Run verify_image_integrity to confirm hash matches acquisition report.",
        ],
    },

    "create_mac_timeline": {
        "caveats": [
            "mactime requires a body file from fls -r -m — it does not parse images directly.",
            "MAC(B) timestamps can all be identical if the OS created/copied the file at the same instant.",
        ],
        "advisories": [
            "MAC timeline entries must be corroborated — a single timestamp event is not conclusive.",
        ],
        "corroboration": [
            "Cross-reference key timeline events with parse_event_logs (process creation, logon).",
            "Run filter_timeline on the super-timeline for the same time window.",
        ],
    },

    "read_raw_block": {
        "caveats": [
            "Raw block reading requires correct offset and block size for the file system.",
            "MBR/VBR analysis requires knowledge of boot record format.",
        ],
        "advisories": [
            "MBR tampering (bootkits) requires corroboration with Secure Boot log and AV/EDR telemetry.",
        ],
        "corroboration": [
            "Cross-reference with get_fs_statistics for block size and MFT location.",
        ],
    },

    "analyze_slack_space": {
        "caveats": [
            "blkls -s may take significant time on large partitions.",
            "String extraction is heuristic — binary data may produce false string hits.",
        ],
        "advisories": [
            "IOCs found in slack space require file system corroboration — they may be from long-deleted files.",
        ],
        "corroboration": [
            "Cross-reference IPs found in slack with lookup_ip_reputation.",
            "Run filter_timeline around the deletion timestamp of the file that owned the cluster.",
        ],
    },

    "verify_image_integrity": {
        "caveats": [
            "Hash computation on large images (>100GB) may take 10+ minutes.",
            "ewfverify is only available for E01 format images.",
        ],
        "advisories": [
            "A hash mismatch means the image CANNOT be trusted as forensically sound — report to case supervisor immediately.",
            "Do NOT continue analysis with a tampered image without documenting the discrepancy.",
        ],
        "corroboration": [
            "Document the expected hash from the acquisition report.",
            "Compare with the hash recorded in get_image_info (ewf_metadata).",
        ],
    },

    # ── Threat intelligence extended ──────────────────────────────────────────

    "lookup_domain_reputation": {
        "caveats": [
            "WHOIS data may be privacy-masked — registrant country is the most reliable field.",
            "Newly registered domains (< 30 days) are common phishing infrastructure.",
            "VT_API_KEY must be set — without it only WHOIS data is returned.",
        ],
        "advisories": [
            "A 0/90 VT detection does NOT mean the domain is clean — new infrastructure has no VT history.",
        ],
        "corroboration": [
            "Run lookup_ip_reputation on all A record IPs for the domain.",
            "Cross-reference with parse_zeek_logs or parse_iis_logs for access frequency.",
        ],
    },

    "search_mitre_technique": {
        "caveats": [
            "RAG results depend on the quality of the seeded MITRE ATT&CK knowledge base.",
            "Technique IDs evolve — verify against current attack.mitre.org.",
        ],
        "advisories": [
            "MITRE technique documentation describes common adversary behavior — not every implementation.",
        ],
        "corroboration": [
            "Cross-reference with tool-level mitre_techniques fields for independent mapping.",
        ],
    },

    "search_ioc_database": {
        "caveats": [
            "RAG IOC database is only as current as the last run_all.py seeding.",
            "Semantic search may surface related but not exact IOC matches.",
        ],
        "advisories": [
            "A RAG match is a SIMILARITY hit, not a definitive IOC match — verify against source.",
        ],
        "corroboration": [
            "Run lookup_hash_reputation or lookup_ip_reputation for definitive VT verdict.",
        ],
    },

    # ── Misc tools that were missing ──────────────────────────────────────────

    "extract_file": {
        "caveats": [
            "icat requires a valid inode number from get_file_listing — incorrect inodes produce garbage.",
            "Deleted files may be partially overwritten — extracted content may be corrupt.",
        ],
        "advisories": [
            "An extracted file must be verified with calculate_file_hashes before analysis.",
        ],
        "corroboration": [
            "Calculate hash and run lookup_hash_reputation.",
            "Run scan_file_with_yara on the extracted file.",
        ],
    },

    "search_deleted_files": {
        "caveats": [
            "fls -d shows deleted directory entries — data blocks may be reallocated.",
            "NTFS MFT records for deleted files are reused — names may persist after data is gone.",
        ],
        "advisories": [
            "A deleted file entry does NOT guarantee the file is recoverable.",
        ],
        "corroboration": [
            "Run carve_files_foremost to attempt file content recovery.",
            "Run parse_mft for timestamp analysis of the deleted entry.",
        ],
    },

    "get_browser_history": {
        "caveats": [
            "Plaso browser history extraction depends on artifact definitions — may not cover all browser types.",
        ],
        "advisories": [
            "Browser history from Plaso should be cross-validated with parse_chrome_history/parse_firefox_history.",
        ],
        "corroboration": [
            "Cross-reference URLs with lookup_domain_reputation.",
        ],
    },

    "list_yara_rule_sets": {
        "caveats": ["Lists available .yar files in yara_rules/ — add custom rules there."],
        "advisories": [],
        "corroboration": ["Run scan_memory_with_yara or scan_file_with_yara with a selected rule set."],
    },

    "finish_analysis": {
        "caveats": [
            "finish_analysis requires a non-empty audit_ids list — findings without audit trail are rejected.",
            "The observation field must contain only tool-observed facts — no inference.",
            "The interpretation field is where analytical conclusions belong.",
        ],
        "advisories": [
            "Do NOT mix observations (what tools showed) with interpretations (what it means) in the same field.",
            "confidence_score < 50 means additional corroboration is needed before reporting.",
        ],
        "corroboration": [
            "Run adversarial_review before calling finish_analysis to challenge your hypothesis.",
            "Run verify_findings to confirm every claim is grounded in raw tool output.",
        ],
    },

    "get_handles": {
        "caveats": [
            "Volatility handles plugin enumerates all open handles — thousands per process is normal.",
            "Handle names may be truncated in memory — full path may not be recoverable.",
        ],
        "advisories": [
            "A process holding a handle to lsass.exe is strongly suspicious (T1003.001) but may be legitimate security software.",
        ],
        "corroboration": [
            "Cross-reference with get_process_list to confirm the handle-holding process is suspicious.",
            "Run parse_event_logs for Event 4656/4663 (object access) if auditing was enabled.",
        ],
    },

    "get_ads_memory": {
        "caveats": [
            "Memory-based ADS detection depends on MFT records being paged into memory.",
            "Results may be incomplete for files not recently accessed.",
        ],
        "advisories": [
            "Corroborate with detect_ads_streams for on-disk ADS detection.",
        ],
        "corroboration": [
            "Run detect_ads_streams for static disk-based ADS detection.",
            "Extract suspicious ADS content with extract_file for analysis.",
        ],
    },

    "get_atoms": {
        "caveats": [
            "Windows atom table is used by GUI frameworks — high atom count is normal.",
            "Malicious atoms often contain encoded payloads or command strings.",
        ],
        "advisories": [
            "Suspicious atom names require correlation with process context to confirm malicious intent.",
        ],
        "corroboration": [
            "Cross-reference with get_process_list for processes that registered the atoms.",
        ],
    },

    "get_sessions": {
        "caveats": [
            "Session 0 is the system session — all services run here.",
            "Multiple sessions may indicate RDP or console switching, not necessarily compromise.",
        ],
        "advisories": [
            "An unexpected session with unusual processes requires cross-referencing with event logs.",
        ],
        "corroboration": [
            "Run parse_event_logs for RDP logon events (4624 Type 10) at session creation times.",
        ],
    },

    "get_clipboard": {
        "caveats": [
            "Clipboard content is volatile — it reflects state at acquisition time only.",
            "Clipboard is cleared on lock/logoff — incident-time content may be gone.",
        ],
        "advisories": [
            "Clipboard passwords or tokens are high-value evidence but require timestamp context.",
        ],
        "corroboration": [
            "Cross-reference clipboard content with parse_event_logs for authentication activity.",
        ],
    },

    "get_cachedump": {
        "caveats": [
            "DCC2 hashes are slow to crack (PBKDF2 with 10,240 iterations).",
            "Maximum 10 cached credentials by default.",
        ],
        "advisories": [
            "Cached credential presence proves prior domain logon, not necessarily current active session.",
        ],
        "corroboration": [
            "Run parse_event_logs for Event 4624 Type 3 for the same accounts.",
        ],
    },

    "get_getsids": {
        "caveats": [
            "SID enumeration requires process token access — some processes may be inaccessible.",
            "Well-known SIDs (S-1-5-18 = SYSTEM, S-1-5-19 = LOCAL SERVICE) are normal for system processes.",
        ],
        "advisories": [
            "A user-mode process holding SYSTEM SID (S-1-5-18) is a privilege escalation indicator (T1134).",
        ],
        "corroboration": [
            "Run get_privileges to see which specific privileges are enabled in the suspicious token.",
            "Run get_process_list to confirm the process parent chain.",
        ],
    },

    "get_mft_memory": {
        "caveats": [
            "In-memory MFT extraction depends on MFT records being paged into memory.",
            "Results are typically a subset of the full on-disk MFT.",
        ],
        "advisories": [
            "Use parse_mft (disk-based) for complete MFT analysis — get_mft_memory is supplementary.",
        ],
        "corroboration": [
            "Cross-reference with parse_mft for complete file system timeline.",
        ],
    },

    "dump_process": {
        "caveats": [
            "Process dumps may be incomplete — some sections are not memory-resident.",
            "Dumped processes are written to EXPORTS_DIR — ensure sufficient disk space.",
            "Anti-analysis malware may detect dump attempts and terminate.",
        ],
        "advisories": [
            "A process dump is for static analysis only — do NOT execute the dump.",
        ],
        "corroboration": [
            "Run get_pe_metadata + detect_capabilities_capa on the dumped process.",
            "Run scan_file_with_yara on the dump.",
            "Calculate hash and run lookup_hash_reputation.",
        ],
    },

    "parse_registry_hive": {
        "caveats": [
            "RECmd.exe requires mono on Linux SIFT.",
            "Registry key paths are case-insensitive on Windows but case-sensitive in this search.",
        ],
        "advisories": [
            "Registry key presence does NOT confirm malicious activity — context and value data matter.",
        ],
        "corroboration": [
            "Run parse_shimcache for execution evidence of the binary referenced in the registry key.",
            "Run parse_event_logs for registry modification events (if Object Access auditing was enabled).",
        ],
    },

    "parse_jump_lists": {
        "caveats": [
            "Jump list AppIDs are application-specific hashes — mapping to application requires AppID database.",
            "Jump lists for removed applications persist until the MRU is purged.",
        ],
        "advisories": [
            "A jump list entry for a sensitive file proves RECENT ACCESS but not necessarily exfiltration.",
        ],
        "corroboration": [
            "Cross-reference with parse_lnk_files for the same file paths.",
            "Run parse_open_save_mru to confirm the file was opened via a dialog.",
        ],
    },

    "read_raw_block": {
        "caveats": [
            "Raw block reading requires correct offset and block size.",
            "MBR/VBR analysis requires knowledge of boot record format.",
        ],
        "advisories": [
            "MBR tampering (bootkits) requires corroboration with Secure Boot log.",
        ],
        "corroboration": [
            "Cross-reference with get_fs_statistics for block size.",
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
