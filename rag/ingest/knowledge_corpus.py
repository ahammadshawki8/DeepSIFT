"""
Offline knowledge-corpus ingestion for the DeepSIFT RAG.

All sources here are bundled / derived in-repo — no network required:
  * MITRE ATT&CK technique catalog harvested from the project's own rule-based
    auto-mapper (mcp_server/parsers/mitre_auto_map), so technique IDs/names match
    exactly what the parsers tag — no fabrication.
  * A curated LOLBAS (Living-Off-the-Land Binaries) reference of commonly abused
    Windows binaries and how attackers misuse them.
  * The SANS Hunt Evil known-normal process baseline and the ROCBA case IOCs.

This gives the offline knowledge base real, accurate breadth (hundreds of grounded
entries) without depending on a 22k-record external download.
"""
from __future__ import annotations
import logging

logger = logging.getLogger(__name__)


# Curated LOLBAS reference — commonly abused signed Windows binaries.
_LOLBAS = [
    ("certutil.exe", "T1105/T1140", "Download files (-urlcache) and decode base64/certs; used for ingress tool transfer and payload deobfuscation."),
    ("mshta.exe", "T1218.005", "Execute HTA/JScript/VBScript, including remote URLs; proxy execution bypassing application control."),
    ("rundll32.exe", "T1218.011", "Execute DLL exports or JavaScript (javascript:..); proxy execution and persistence."),
    ("regsvr32.exe", "T1218.010", "Register/run scriptlets (scrobj.dll, 'Squiblydoo') from local or remote SCT; AWL bypass."),
    ("bitsadmin.exe", "T1197", "Create BITS jobs to download/exec payloads with persistence and proxy-aware transfer."),
    ("wmic.exe", "T1047", "WMI query/exec, process create, and remote command execution for lateral movement."),
    ("powershell.exe", "T1059.001", "Script execution, encoded commands, download cradles, in-memory execution."),
    ("cscript.exe", "T1059.005", "Run VBScript/JScript .vbs/.js; macro and script-based execution."),
    ("wscript.exe", "T1059.005", "Windows Script Host execution of VBS/JS payloads."),
    ("msbuild.exe", "T1127.001", "Compile and execute inline C# tasks from a project file; AWL bypass."),
    ("installutil.exe", "T1218.004", ".NET installer used to execute managed code via uninstall methods; AWL bypass."),
    ("regasm.exe", "T1218.009", "Register .NET assemblies, executing attacker code via ComRegisterFunction."),
    ("regsvcs.exe", "T1218.009", "Register .NET COM+; executes code during registration; AWL bypass."),
    ("schtasks.exe", "T1053.005", "Create/modify scheduled tasks for execution and persistence."),
    ("sc.exe", "T1543.003", "Create/modify Windows services for execution, persistence, and lateral movement."),
    ("net.exe", "T1021.002/T1136", "Map admin shares, manage users/sessions; reconnaissance and lateral movement."),
    ("psexec.exe", "T1569.002/T1021.002", "Service-based remote execution over SMB; classic lateral movement."),
    ("vssadmin.exe", "T1490", "Delete volume shadow copies to inhibit recovery (ransomware precursor)."),
    ("wevtutil.exe", "T1070.001", "Clear/query Windows event logs; indicator removal / anti-forensics."),
    ("fsutil.exe", "T1070.004", "USN journal deletion and file ops used for anti-forensics."),
    ("esentutl.exe", "T1003/T1005", "Copy locked files (e.g. ntds.dit, registry hives) via VSS for credential access."),
    ("makecab.exe", "T1560.001", "Compress/stage data into .cab archives for collection/exfiltration."),
    ("expand.exe", "T1140", "Expand compressed payloads; deobfuscation/staging."),
    ("forfiles.exe", "T1059", "Proxy command execution by iterating files and invoking commands."),
    ("mavinject.exe", "T1055.001", "Inject a DLL into a running process (App-V); process injection."),
    ("sdelete.exe", "T1070.004", "Sysinternals secure-delete; used to wipe evidence/files (anti-forensics)."),
    ("rclone.exe", "T1567.002", "Bulk sync/upload to cloud providers; common exfiltration tool."),
]


def ingest_mitre_catalog(kb) -> int:
    """Harvest the unique MITRE techniques the parsers can tag, into the KB."""
    try:
        from mcp_server.parsers import mitre_auto_map as m
    except Exception as e:
        logger.warning(f"mitre_auto_map unavailable: {e}")
        return 0
    rules = getattr(m, "_ALL_RULE_GROUPS", None)
    if not rules:
        rules = []
        for name in dir(m):
            if name.endswith("_RULES"):
                rules += getattr(m, name)
    seen: dict[str, str] = {}
    for entry in rules:
        if len(entry) >= 3:
            _, tid, tname = entry[0], entry[1], entry[2]
            seen.setdefault(str(tid), str(tname))
    n = 0
    for tid, tname in seen.items():
        kb.ingest_document(
            doc_id=f"mitre_{tid.replace('/', '_').replace('.', '_')}",
            content=f"MITRE ATT&CK {tid}: {tname}. Detection-relevant technique mapped by "
                    f"DeepSIFT parsers from forensic artifacts.",
            source="mitre_attack",
            metadata={"technique_id": tid, "name": tname},
        )
        n += 1
    logger.info(f"Ingested {n} MITRE technique catalog entries")
    return n


def ingest_lolbas(kb) -> int:
    for binary, tids, desc in _LOLBAS:
        kb.ingest_document(
            doc_id=f"lolbas_{binary.replace('.', '_')}",
            content=f"LOLBAS {binary} (ATT&CK {tids}): {desc}",
            source="lolbas",
            metadata={"binary": binary, "technique_ids": tids},
        )
    logger.info(f"Ingested {len(_LOLBAS)} LOLBAS entries")
    return len(_LOLBAS)


def ingest_all_offline(kb) -> int:
    """Seed every offline source. Returns total documents in the KB afterwards."""
    total = 0
    try:
        total += kb.ingest_hunt_evil_baseline()
    except Exception as e:
        logger.warning(f"hunt-evil ingest failed: {e}")
    try:
        from rag.ingest.rocba_iocs import ROCBA_IOCS
        for ioc in ROCBA_IOCS:
            kb.ingest_document(doc_id=ioc["id"], content=ioc["content"],
                               source=ioc.get("source", "rocba_case_history"),
                               metadata=ioc.get("metadata"))
        total += len(ROCBA_IOCS)
    except Exception as e:
        logger.warning(f"ROCBA IOC ingest failed: {e}")
    total += ingest_mitre_catalog(kb)
    total += ingest_lolbas(kb)
    return kb.get_stats().get("total_documents", total)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    from rag.knowledge_base import ForensicKnowledgeBase
    kb = ForensicKnowledgeBase()
    print(f"Backend: {kb.embed_backend}")
    print(f"Knowledge base now holds {ingest_all_offline(kb)} documents.")
