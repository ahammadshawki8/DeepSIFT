"""Ingest completed investigation findings into the knowledge base for future reference."""
from __future__ import annotations
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def ingest_findings_json(findings_path: str, case_id: str | None = None) -> int:
    """
    Ingest a findings.json produced by finish_analysis into the knowledge base.
    Grows the RAG corpus with real case data over time.
    """
    from rag.knowledge_base import ForensicKnowledgeBase
    kb = ForensicKnowledgeBase()

    with open(findings_path, encoding="utf-8") as f:
        findings = json.load(f)

    _case_id = case_id or Path(findings_path).parent.name
    count = 0

    # Index the summary
    if findings.get("summary"):
        kb.add_case_finding(_case_id, f"Case summary: {findings['summary']}", {"type": "summary"})
        count += 1

    # Index each suspicious process
    for proc in findings.get("suspicious_processes", []):
        kb.add_case_finding(_case_id, f"Suspicious process found: {proc}", {"type": "process_ioc"})
        count += 1

    # Index network IOCs
    for ioc in findings.get("network_iocs", []):
        kb.add_case_finding(_case_id, f"Network IOC: {ioc}", {"type": "network_ioc"})
        count += 1

    # Index MITRE techniques with context
    for technique in findings.get("mitre_techniques", []):
        kb.add_case_finding(_case_id, f"MITRE technique observed: {technique} in case {_case_id}", {"type": "technique"})
        count += 1

    logger.info(f"Ingested {count} items from case {_case_id} into knowledge base")
    return count


def ingest_all_cases(cases_base_dir: str = "./analysis") -> int:
    """Ingest all findings.json files found under cases_base_dir."""
    total = 0
    for findings_file in Path(cases_base_dir).rglob("findings.json"):
        case_id = findings_file.parent.name
        try:
            total += ingest_findings_json(str(findings_file), case_id)
        except Exception as e:
            logger.warning(f"Failed to ingest {findings_file}: {e}")
    return total
