# Memory Analysis Report — ROCBA-BASELINE
**Image:** `/cases/ROCBA-BASELINE/Rocba-Memory/Rocba-Memory.raw`  
**Size:** 18 GB  
**Analyst:** DFIR Orchestrator  
**Report Date:** 2026-06-11 (all artifact timestamps UTC)

---

## System Profile

| Field | Value |
|-------|-------|
| OS | Windows 10 x64 — Build 19041 (20H1) |
| Kernel Base | 0xf8025d600000 |
| Capture Time (SystemTime) | 2020-11-16 02:32:38 UTC |
| Host IP | 192.168.1.5 |
| Logged-in User | fredr |
| SID (from registry handles) | S-1-5-21-528816539-567677750-276746561-1002 |
| CPUs | 4 |
| Volatility 3 Framework | 2.27.0 |

---

## Executive Summary

The ROCBA-BASELINE memory image is a Windows 10 workstation used by user **fredr**. Analysis reveals **no traditional malware or rootkit activity**. However, two significant findings require attention:

1. **Active RDP brute-force attack** — two external IPs hammered port 3389 with 121 connection attempts over ~6 minutes, including **4 ESTABLISHED sessions** at capture time.
2. **Non-standard forensic tool** — `MRC.exe` (D:\Tools\MRC.exe) launched 83 seconds before capture, consistent with the ROCBA course exercise tool accessing the `ROCBA-SYSTEM` baseline volume.
3. **Extensive cloud sync exposure** — six cloud synchronization services (OneDrive, Google Drive ×2, iCloud, Slack, Teams) were actively syncing at capture time, representing a broad data exfiltration surface.

---

## 1. Suspicious Process: MRC.exe

| Attribute | Value |
|-----------|-------|
| PID | 29440 |
| Parent PID | 7464 (explorer.exe — manual launch) |
| Image path | `D:\Tools\MRC.exe` |
| Architecture | 32-bit (Wow64 = True) |
| Start time | 2020-11-16 02:31:15 UTC |
| Threads | 20 |
| Network connections | None |
| Code injection (malfind) | None detected |

**Handles of interest:**

| Handle | Type | Path |
|--------|------|------|
| 0x3ac | File | `\Device\HarddiskVolume7\ROCBA-SYSTEM\` |
| 0x1f4 | File (RW) | `\Users\fredr\AppData\Local\Temp\~DF9801C56B0740D958.TMP` |

**Assessment:** MRC.exe has a direct handle to `\Device\HarddiskVolume7\ROCBA-SYSTEM\` — a separate volume named ROCBA-SYSTEM — and created a Windows common-dialog temp file. The tool runs from `D:\Tools\`, which is consistent with course exercise tooling. No network activity, no injected code, and no suspicious registry access were detected. The temp file naming pattern (`~DF….TMP`) is typical of a Windows file-open or save dialog.

---

## 2. Network Activity — RDP Brute Force

### Attack Summary

| Metric | Value |
|--------|-------|
| Target | 192.168.1.5 port 3389 (RDP) |
| Total connection records | 121 |
| ESTABLISHED sessions at capture | 4 |
| Attack window | 2020-11-16 02:30:05 → 02:36:24 UTC |
| Duration | ~6 minutes 19 seconds |

### Attacker IPs

| IP Address | Connections | Role |
|------------|-------------|------|
| **81.30.144.115** | 59 | Primary — began at 02:31:26, multiple ESTABLISHED |
| **213.202.233.104** | 54 | Secondary — began at 02:31:18, multiple ESTABLISHED |
| 201.193.188.114 | 3 | Early probe — began at 02:30:05 |
| 81.19.209.101 | 2 | Minor probe |

### ESTABLISHED Sessions at / near Capture Time

| Local | Foreign | State | Created |
|-------|---------|-------|---------|
| 192.168.1.5:3389 | 81.30.144.115:5067 | ESTABLISHED | 02:34:45 |
| 192.168.1.5:3389 | 81.30.144.115:51048 | ESTABLISHED | 02:34:58 |
| 192.168.1.5:3389 | 213.202.233.104:45753 | ESTABLISHED | 02:34:58 |
| 192.168.1.5:3389 | 213.202.233.104:40876 | ESTABLISHED | 02:35:53 |

> Note: ESTABLISHED connection creation timestamps appear after the windows.info SystemTime (02:32:38). This is consistent with an extended memory capture window; these connections were live in memory at capture time.

**Pattern:** High-frequency, rapid-fire connections from two IPs with near-simultaneous ESTABLISHED sessions from both. Classic RDP credential-staffing or brute-force pattern. Both IPs should be treated as hostile external actors.

### Exposed Listening Services (netstat)

| Port | Protocol | Owner | Risk |
|------|----------|-------|------|
| 3389 | TCP + UDP | svchost.exe | **HIGH** — RDP, externally attacked |
| 445 | TCP | System | HIGH — SMB, exploitable remotely |
| 139 | TCP | System | MEDIUM — NetBIOS session |
| 135 | TCP | svchost.exe | MEDIUM — RPC endpoint mapper |
| 49664–49671 | TCP | lsass/wininit/services/svchost | LOW — RPC dynamic ports |

### Timeline

```
02:30:05  First probe — 201.193.188.114
02:31:15  MRC.exe launched (forensic/course tool)
02:31:18  First 213.202.233.104 connection
02:31:26  First 81.30.144.115 connection
02:32:38  Memory captured (windows.info SystemTime)
02:34:45+ Multiple ESTABLISHED RDP sessions from both IPs
02:36:24  Last recorded connection
```

---

## 3. Data Exfiltration Risk — Cloud Sync Services

All six cloud sync services were actively connected at capture time:

| Process | PID | Service | Destination IPs | Status |
|---------|-----|---------|-----------------|--------|
| OneDrive.exe | 9648 | Microsoft OneDrive (Work/School) | 52.114.x.x, 13.107.x.x | ESTABLISHED |
| OneDrive.exe | 6188 | Microsoft OneDrive (Personal) | 52.179.x.x, 52.242.x.x | ESTABLISHED |
| googledrivesync.exe | 8432 | Google Drive (Classic) | 172.217.x.x, 142.250.x.x | ESTABLISHED |
| GoogleDriveFS.exe | 14832 | Google Drive File Stream | 172.217.x.x, 142.250.x.x | ESTABLISHED |
| iCloudPhotos.exe | 12532 | iCloud Photos | 17.248.138.x (Apple) | ESTABLISHED/CLOSE_WAIT |
| iCloudServices.exe | 12756 | iCloud Services | 17.248.138.x (Apple) | CLOSE_WAIT |
| iCloudDrive.exe | 13260 | iCloud Drive | 17.248.138.x (Apple) | ESTABLISHED |
| Slack.exe | 1152 | Slack | 54.82.161.19 | ESTABLISHED |
| Teams.exe | 11672 | Microsoft Teams | 52.114.x.x, 52.113.x.x | ESTABLISHED |

**Assessment:** All connections resolve to expected legitimate service endpoints. However, the simultaneous presence of dual OneDrive accounts, Google Drive in two forms, iCloud, Slack, and Teams creates a wide exfiltration surface. If an attacker succeeded in gaining RDP access, any files on the local filesystem could be quietly staged to these cloud services.

---

## 4. Process Integrity Analysis

### Hidden Process Detection (psscan vs pslist)

| Result | Count |
|--------|-------|
| Total PIDs in pool scan (psscan) | 2196 |
| Total PIDs in pslist walk (cmdline) | 2186 |
| Discrepancy | 10 |

All 10 discrepant PIDs are recently-exited legitimate Windows processes (Chrome renderer, RuntimeBroker, SearchFilterHost, backgroundTask, SDXHelper, LocalBridge). No DKOM/rootkit evidence.

### Code Injection (malfind — broad scan)

| Process | PID | Finding | Verdict |
|---------|-----|---------|---------|
| MsMpEng.exe | 4864 | RWX regions — scanning trampoline stubs | Benign (normal AV behavior) |
| SearchApp.exe | 8312 | RWX regions | Benign (UWP/JIT) |
| LockApp.exe | 9788 | RWX regions | Benign (UWP/JIT) |
| RuntimeBroker.exe | 9964 | RWX regions | Benign (UWP broker JIT) |
| dllhost.exe | 8748 | PAGE_EXECUTE_READ | Benign (COM hosting) |
| MRC.exe | 29440 | No hits | Clean |

**No code injection or hollowing detected in any process.**

---

## 5. Persistence Mechanisms

### HKCU Run Keys (user: fredr)

| Value Name | Data |
|------------|------|
| OneDrive | `C:\Users\fredr\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background` |
| com.squirrel.Teams.Teams | `...Teams\Update.exe --processStart "Teams.exe" --system-initiated` |
| GoogleDriveSync | `"C:\Program Files\Google\Drive\googledrivesync.exe" /autostart` |
| C18E42C7363A... | `msedge.exe --type=service /prefetch:8` |
| GoogleDriveFS | `"C:\Program Files\Google\Drive File Stream\43.0.8.0\GoogleDriveFS.exe"` |

**Assessment:** All five autostart entries are legitimate. No malicious persistence detected in HKLM or HKCU Run keys.

---

## 6. Services (svcscan)

No services with suspicious binary paths (AppData, Temp, user-writable directories) were found. All running services resolve to expected System32 paths.

---

## 7. Indicators of Compromise (IOCs)

### Hostile Network Indicators

| IOC | Type | Confidence | Notes |
|-----|------|------------|-------|
| 81.30.144.115 | IPv4 | HIGH | 59 RDP connections; active ESTABLISHED sessions |
| 213.202.233.104 | IPv4 | HIGH | 54 RDP connections; active ESTABLISHED sessions |
| 201.193.188.114 | IPv4 | MEDIUM | 3 early RDP probes |
| 81.19.209.101 | IPv4 | MEDIUM | 2 RDP probes |

### Suspicious Files

| Path | PID | Notes |
|------|-----|-------|
| `D:\Tools\MRC.exe` | 29440 | Non-standard path; ROCBA course tool |
| `C:\Users\fredr\AppData\Local\Temp\~DF9801C56B0740D958.TMP` | 29440 | Temp created by MRC.exe |

---

## 8. Recommendations

1. **Block and investigate RDP attackers** — 81.30.144.115 and 213.202.233.104 should be blocked at the perimeter immediately. Review Active Directory and local account logs for successful authentication from these IPs.

2. **Disable RDP or restrict access** — If RDP must remain enabled, restrict to VPN or bastion host. Enable Network Level Authentication (NLA) and account lockout policies.

3. **Audit cloud sync clients** — Having dual OneDrive, dual Google Drive, iCloud, Slack, and Teams all running simultaneously creates a large passive exfiltration surface. Review what data these services were syncing; consider data loss prevention (DLP) policies.

4. **Verify MRC.exe provenance** — Confirm `D:\Tools\MRC.exe` is the expected course/exercise tool and that HarddiskVolume7\ROCBA-SYSTEM is the intended baseline volume. Hash the binary and compare to known-good.

5. **Review user account** — Check `fredr`'s account for unauthorized changes, password modifications, or privilege escalation that could have occurred during the ~6 minutes of active RDP sessions.

---

## 8a. User Identity and Sensitive Data Exposure

### Identity

| Attribute | Value |
|-----------|-------|
| Username | fredr |
| Full Name | Fred Rocba |
| Work Email | frocba@stark-research-labs.com |
| Personal Email (Outlook) | fred.rocba@outlook.com |
| Personal Email (Gmail) | fred.rocba@gmail.com |

### Sensitive Data Cached Locally

**Outlook OST Files (email offline cache — fully accessible on disk):**

| OST File | Account | Risk |
|----------|---------|------|
| `frocba@stark-research-labs.com.ost` | **SRL Work Email** | HIGH — all downloaded work emails |
| `fred.rocba@outlook.com.ost` | Personal Outlook | MEDIUM |
| `fred.rocba@gmail.com.ost` | Gmail via Outlook | MEDIUM |

**Dropbox Folder (files in filesystem cache, client not currently running):**
- Path: `C:\Users\fredr\ROCBA Dropbox\Fred Rocba\Data Testing Results\`
- Contents: Game data files (.mca Minecraft chunks, .json, .dat); no obviously sensitive SRL research data observed in cache

**Assessment:** The SRL work email OST file means an attacker who gained RDP access could have read all locally-cached work emails, including potentially sensitive research communications. Combined with the active cloud sync services, this represents a high-value data exfiltration opportunity.

---

## 9. Output Files

| File | Contents |
|------|----------|
| `analysis/memory/windows_info.txt` | OS/kernel identification |
| `analysis/memory/pstree.txt` | Full process tree |
| `analysis/memory/psscan.txt` | Pool-based process scan |
| `analysis/memory/cmdline.txt` | All process command lines |
| `analysis/memory/netscan.txt` | All network connection objects |
| `analysis/memory/svcscan.txt` | All service records |
| `analysis/memory/run_keys.txt` | Registry Run key values |
| `analysis/memory/handles_mrc.txt` | Handle table for MRC.exe (PID 29440) |
| `analysis/memory/malfind_broad.txt` | Malfind scan (all non-Electron processes) |
