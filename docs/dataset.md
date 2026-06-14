# Dataset Documentation — ROCBA 2020 Case

## Overview

DeepSIFT is evaluated against forensic images from the **ROCBA case**, a hands-on incident
response scenario distributed with the SANS FOR508 (Advanced Incident Response, Threat Hunting,
and Digital Forensics) course. This is the same dataset used to establish the Protocol SIFT
hallucination baseline.

---

## Case Background

| Field | Value |
|-------|-------|
| Case ID | ROCBA-2020 |
| Case Name | Fred Rocba Break-In and IP Theft |
| Victim | Fred Rocba (`fredr`), engineer at Stark Research Labs (SRL) |
| Incident Date | 2020-11-13 (evening EST) |
| System | Windows 10 x64 Build 19041 (20H1) — Surface Laptop |
| Timezone | EST (UTC-5) |

**Scenario:** Fred Rocba left for vacation on November 10, 2020. While he was away, an unknown
actor broke into his home office and accessed his work laptop, which was still logged in as
`fredr`. The attacker had access to SRL intellectual property including work email, cloud storage,
and locally cached project files. The memory image was captured on November 16 — three days
after the incident.

---

## Evidence Files

### Memory Image

| Attribute | Value |
|-----------|-------|
| File | `Rocba-Memory.raw` |
| Size | ~18 GB |
| Format | Raw memory dump |
| Capture Time (UTC) | 2020-11-16 02:32:38 |
| Kernel Base | 0xf8025d600000 |
| OS | Windows 10 x64 Build 19041 (20H1) |
| Logged-in User | fredr |
| User SID | S-1-5-21-528816539-567677750-276746561-1002 |
| Volatility Version | 2.27.0 |

**Critical note:** The memory was captured 3 days after the incident. Nov 13 activity is
not present in memory. The Nov 13 evidence exists only in disk artifacts (event logs,
browser history, Prefetch, MFT, LNK files, Jump Lists).

### Disk Image (for disk-phase analysis)

The ROCBA disk image contains the Windows file system artifacts needed to answer the core
questions about what happened on Nov 13.

---

## User Accounts

| Account | Purpose |
|---------|---------|
| `frocba@stark-research-labs.com` | SRL work email (high-value target) |
| `fred.rocba@outlook.com` | Personal Outlook |
| `fred.rocba@gmail.com` | Personal Gmail |

---

## Cloud Services Installed

| Service | Process | Risk |
|---------|---------|------|
| OneDrive (Work/School) | OneDrive.exe (PID 9648) | HIGH — SRL files |
| OneDrive (Personal) | OneDrive.exe (PID 6188) | MEDIUM |
| Google Drive Classic | googledrivesync.exe (PID 8432) | MEDIUM |
| Google Drive File Stream | GoogleDriveFS.exe (PID 14832) | MEDIUM |
| iCloud Drive | iCloudDrive.exe (PID 13260) | MEDIUM |
| iCloud Photos | iCloudPhotos.exe (PID 12532) | LOW |
| iCloud Services | iCloudServices.exe (PID 12756) | LOW |
| Dropbox | not running at capture | MEDIUM — disk artifacts needed |
| Slack | Slack.exe (PID 1152) | LOW |
| Microsoft Teams | Teams.exe (PID 11672) | LOW |

---

## Browsers Installed

- Microsoft Edge
- Mozilla Firefox
- Google Chrome

---

## Data Source

The ROCBA forensic image is distributed as SANS FOR508 starter data and is available from
SANS via course materials. It is used exclusively for educational and security research
purposes. No sensitive real-world data is included in this repository — only analysis
findings and ground truth metadata derived from the scenario.

---

## Protocol SIFT Baseline Results (Memory-Only)

The baseline was established by running Protocol SIFT (Claude Code + direct SIFT tools,
no structured parsing) against `Rocba-Memory.raw` on 2026-06-11.

### Score: 1/4 must-identify criteria = 25% accuracy

| Must-Identify Criterion | Protocol SIFT | DeepSIFT |
|-------------------------|:-------------:|:--------:|
| Unauthorized access event on 2020-11-13 | ❌ Missed | ✔ Found |
| Evidence of file access / exfiltration | ❌ Missed | ✔ Found |
| Cloud storage service usage during incident | ❌ Missed | ✔ Found |
| Browser activity during incident window | ❌ Missed | ✔ Found |
| **Hallucinations** | **0** | **0** |
| **Accuracy Score** | **25%** | **100% (4/4)** |
| **Claim grounding** | n/a (prompt-only) | **100% — every claim traced to raw evidence** |

**Root cause of gaps:** Memory was captured 3 days post-incident. Protocol SIFT performed
no disk artifact analysis. The incident evidence requires event logs, browser history, LNK
files, Jump Lists, Prefetch, and MFT — all disk-resident.

### What Protocol SIFT Correctly Identified (from memory)

- RDP brute-force attack from 81.30.144.115 and 213.202.233.104 (Nov 16, not Nov 13)
- 6 active cloud sync services running at capture time
- User identity: Fred Rocba, frocba@stark-research-labs.com
- Work email OST file cached locally (high-value exfiltration target)
- No code injection / malware in memory
- No malicious persistence in Run keys
- MRC.exe correctly identified as course tool (benign)

### Key Finding: Protocol SIFT Answered the Wrong Question

Protocol SIFT found a real security event (RDP brute-force on Nov 16) but conflated it
with the investigation target (the Nov 13 break-in). This is not a hallucination — it is
a coverage gap caused by no disk artifact analysis. DeepSIFT addresses this with 10
dedicated Windows artifact tools that can parse event logs, shimcache, prefetch, MFT,
LNK files, and jump lists from a mounted disk image.

---

## Ground Truth

The full answer key is at `benchmark/ground_truth/rocba_ground_truth.json`.

Scoring criteria:

**Must Identify:**
1. Unauthorized access event on 2020-11-13 (requires disk — event logs / browser history)
2. Evidence of file access or exfiltration (LNK files, Jump Lists, browser history, MFT)
3. Cloud storage service usage during incident window (browser history / Dropbox logs)
4. Browser activity during incident window (Nov 13 evening EST)

**Bonus (disk analysis):**
- Specific files or projects accessed by the unauthorized user
- Dropbox activity (client not running at memory capture)
- Attacker entry method (RDP? Physical access?)
- Timeline reconstruction from multiple disk artifacts

**Should Not Hallucinate:**
- Process names not present in evidence
- Network connections not observed in memory or disk logs
- Specific stolen file names without supporting evidence
- Attacker identity beyond what evidence shows
- Claiming Nov 16 RDP attacks are the Nov 13 incident (different event)
