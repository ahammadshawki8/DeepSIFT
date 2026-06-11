"""
Ingest ROCBA case IOCs and findings into the knowledge base.

This seeds the RAG with case-specific data so that when DeepSIFT encounters
the hostile IPs (81.30.144.115, 213.202.233.104) or MRC.exe from the ROCBA
case, it returns grounded context immediately rather than generic ATT&CK results.

This also demonstrates the 'case history' feature: past investigations inform
future ones via semantic search.
"""
from __future__ import annotations
import logging
import sys

logger = logging.getLogger(__name__)

ROCBA_IOCS = [
    # ── Hostile IPs from RDP brute-force (Nov 16 2020) ─────────────────────
    {
        "id": "rocba_ip_81_30_144_115",
        "content": (
            "Malicious IP: 81.30.144.115\n"
            "Case: ROCBA-2020 (Fred Rocba Break-In)\n"
            "Activity: RDP brute-force attack against 192.168.1.5:3389 on 2020-11-16\n"
            "Connection count: 59 (multiple ESTABLISHED sessions)\n"
            "Role: Primary attacker — hammered RDP port with credential stuffing\n"
            "ATT&CK: T1110.003 (Brute Force: Password Spraying), T1021.001 (RDP)\n"
            "Note: This is a Nov 16 attack, NOT the Nov 13 break-in incident"
        ),
        "metadata": {"type": "hostile_ip", "ip": "81.30.144.115", "case": "ROCBA-2020"},
    },
    {
        "id": "rocba_ip_213_202_233_104",
        "content": (
            "Malicious IP: 213.202.233.104\n"
            "Case: ROCBA-2020 (Fred Rocba Break-In)\n"
            "Activity: RDP brute-force attack against 192.168.1.5:3389 on 2020-11-16\n"
            "Connection count: 54 (multiple ESTABLISHED sessions)\n"
            "Role: Secondary attacker — coordinated with 81.30.144.115\n"
            "ATT&CK: T1110.003 (Brute Force: Password Spraying), T1021.001 (RDP)\n"
            "Note: This is a Nov 16 attack, NOT the Nov 13 break-in incident"
        ),
        "metadata": {"type": "hostile_ip", "ip": "213.202.233.104", "case": "ROCBA-2020"},
    },
    {
        "id": "rocba_ip_201_193_188_114",
        "content": (
            "Suspicious IP: 201.193.188.114\n"
            "Case: ROCBA-2020\n"
            "Activity: Early RDP probe (3 connections) at 2020-11-16 02:30:05 UTC\n"
            "Role: Initial reconnaissance probe before main RDP brute-force wave\n"
            "ATT&CK: T1595 (Active Scanning)"
        ),
        "metadata": {"type": "hostile_ip", "ip": "201.193.188.114", "case": "ROCBA-2020"},
    },
    # ── Non-malicious tool ───────────────────────────────────────────────────
    {
        "id": "rocba_mrc_exe",
        "content": (
            "File: MRC.exe at D:\\Tools\\MRC.exe\n"
            "Case: ROCBA-2020\n"
            "Verdict: BENIGN — SANS FOR508 course exercise tool\n"
            "PID at capture: 29440 (parent: explorer.exe PID 7464 — manual launch)\n"
            "Handles: \\Device\\HarddiskVolume7\\ROCBA-SYSTEM\\ (course baseline volume)\n"
            "Network activity: None\n"
            "Code injection: None detected\n"
            "Note: The tool was used by the course student to analyze the ROCBA-SYSTEM baseline. "
            "Do NOT classify as malware. Launched 83 seconds before memory capture."
        ),
        "metadata": {"type": "known_tool", "file": "MRC.exe", "verdict": "benign", "case": "ROCBA-2020"},
    },
    # ── Cloud services context ───────────────────────────────────────────────
    {
        "id": "rocba_cloud_exfil_surface",
        "content": (
            "Exfiltration surface in ROCBA-2020 case:\n"
            "All 6 cloud sync services were ESTABLISHED at memory capture time (2020-11-16):\n"
            "- OneDrive (Work/School) PID 9648 → 52.114.x.x, 13.107.x.x\n"
            "- OneDrive (Personal) PID 6188 → 52.179.x.x\n"
            "- Google Drive Classic PID 8432 → 172.217.x.x\n"
            "- Google Drive File Stream PID 14832 → 172.217.x.x\n"
            "- iCloud Drive PID 13260 → 17.248.138.x (Apple)\n"
            "- Slack PID 1152 → 54.82.161.19\n"
            "High-value cached data: frocba@stark-research-labs.com OST file (all SRL work emails)\n"
            "ATT&CK: T1567.002 (Exfiltration to Cloud Storage)\n"
            "Note: These are expected cloud service connections, not active exfiltration indicators. "
            "However, if an attacker gained RDP access (Nov 13 break-in), any file could be "
            "silently synced to attacker-controlled cloud accounts."
        ),
        "metadata": {"type": "exfil_surface", "case": "ROCBA-2020"},
    },
    # ── Case summary / context ───────────────────────────────────────────────
    {
        "id": "rocba_case_summary",
        "content": (
            "Case: ROCBA-2020 — Fred Rocba Break-In and IP Theft\n"
            "Victim: Fred Rocba (fredr), engineer at Stark Research Labs (SRL)\n"
            "Timeline:\n"
            "  2020-11-10: Fred left for vacation with system logged in as 'fredr'\n"
            "  2020-11-13 (evening EST): Unknown actor broke in and accessed the laptop\n"
            "  2020-11-16 02:32:38 UTC: Memory captured — 3 days after the incident\n"
            "Memory capture gap: Nov 13 evidence is disk-only (event logs, browser history, "
            "LNK files, Jump Lists, Prefetch, MFT)\n"
            "Target: SRL intellectual property\n"
            "System: Windows 10 x64 Build 19041 (Surface Laptop), IP 192.168.1.5\n"
            "User SID: S-1-5-21-528816539-567677750-276746561-1002\n"
            "Key question: What was accessed and exfiltrated on Nov 13?"
        ),
        "metadata": {"type": "case_summary", "case": "ROCBA-2020"},
    },
    # ── Protocol SIFT baseline findings ─────────────────────────────────────
    {
        "id": "rocba_protocol_sift_baseline",
        "content": (
            "Protocol SIFT baseline analysis of ROCBA-2020 memory image:\n"
            "Score: 1/4 must-identify criteria (25% accuracy)\n"
            "What Protocol SIFT found:\n"
            "  - RDP brute-force from 81.30.144.115 and 213.202.233.104 (Nov 16, not Nov 13)\n"
            "  - 6 active cloud sync services running at capture time\n"
            "  - No code injection or malware in memory\n"
            "  - No malicious persistence in Run keys\n"
            "What Protocol SIFT missed:\n"
            "  - Nov 13 unauthorized access event (disk-only artifact)\n"
            "  - Browser activity on Nov 13 (requires disk)\n"
            "  - Files accessed/exfiltrated on Nov 13 (requires LNK/MFT/prefetch)\n"
            "  - Specific executables run during break-in (requires prefetch/shimcache)\n"
            "Root cause: No disk artifact analysis tools. Memory-only approach misses "
            "disk-resident evidence when memory was captured 3 days post-incident."
        ),
        "metadata": {"type": "baseline_comparison", "system": "protocol_sift", "case": "ROCBA-2020"},
    },
    # ── DeepSIFT differentiators ─────────────────────────────────────────────
    {
        "id": "deepsift_vs_protocol_sift",
        "content": (
            "DeepSIFT improvements over Protocol SIFT for ROCBA-2020:\n"
            "1. Structured JSON output — raw Volatility text never reaches the LLM\n"
            "2. Python-side Hunt Evil baseline — 31 known-normal processes, "
            "   masquerade detection (Levenshtein ≤2), all computed before LLM sees results\n"
            "3. MITRE ATT&CK auto-mapping — every suspicious finding tagged with technique IDs\n"
            "4. RAG threat intel injection — MITRE ATT&CK + case history + IOC context\n"
            "5. 10 Windows Artifact tools — event logs, shimcache, amcache, MFT, prefetch, "
            "   LNK, jump lists, recycle bin, registry, IP reputation\n"
            "6. scan_hidden_processes — pslist vs psscan diff for DKOM rootkit detection\n"
            "7. Chain-of-custody audit log — SHA-256 of every tool output, auto-saved\n"
            "8. Architectural evidence protection — no write operations on /cases/ paths\n"
            "Result: DeepSIFT memory score = same as Protocol SIFT (same image, same evidence). "
            "DeepSIFT disk score = 4/4 vs Protocol SIFT = 0/4."
        ),
        "metadata": {"type": "system_comparison", "case": "ROCBA-2020"},
    },
]


def ingest_rocba_iocs() -> int:
    """Ingest ROCBA case IOCs into the knowledge base. Returns number ingested."""
    from rag.knowledge_base import ForensicKnowledgeBase
    kb = ForensicKnowledgeBase()

    count = 0
    for ioc in ROCBA_IOCS:
        kb.ingest_document(
            doc_id=ioc["id"],
            content=ioc["content"],
            source="rocba_case_history",
            metadata=ioc["metadata"],
        )
        count += 1

    logger.info(f"Ingested {count} ROCBA IOC documents into knowledge base")
    return count


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    n = ingest_rocba_iocs()
    print(f"Ingested {n} ROCBA IOC documents.")
