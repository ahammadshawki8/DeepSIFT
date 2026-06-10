"""Ingest threat intelligence feeds (AbuseIPDB bulk export, custom IOC lists) into the knowledge base."""
from __future__ import annotations
import csv
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def ingest_ioc_csv(csv_path: str) -> int:
    """
    Ingest a CSV of IOCs with columns: type, value, description, tags.
    Returns number of IOCs ingested.
    """
    from rag.knowledge_base import ForensicKnowledgeBase
    kb = ForensicKnowledgeBase()

    count = 0
    with open(csv_path, encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ioc_type = row.get("type", "unknown")
            value = row.get("value", "")
            desc = row.get("description", "")
            tags = row.get("tags", "")

            if not value:
                continue

            doc = (
                f"IOC [{ioc_type}]: {value}\n"
                f"Description: {desc}\n"
                f"Tags: {tags}"
            )
            doc_id = f"ioc_{ioc_type}_{value[:50].replace('.', '_').replace('/', '_')}"
            kb.ingest_document(doc_id, doc, source="threat_intel_feed",
                               metadata={"ioc_type": ioc_type, "value": value})
            count += 1

    logger.info(f"Ingested {count} IOCs from {csv_path}")
    return count


def ingest_abuse_ipdb_blacklist(csv_path: str) -> int:
    """
    Ingest AbuseIPDB bulk blacklist CSV (downloadable from AbuseIPDB dashboard).
    Columns: ipAddress,abuseConfidenceScore,countryCode,usageType,isp,domain,totalReports
    """
    from rag.knowledge_base import ForensicKnowledgeBase
    kb = ForensicKnowledgeBase()

    count = 0
    with open(csv_path, encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row.get("ipAddress", "")
            score = row.get("abuseConfidenceScore", "0")
            country = row.get("countryCode", "")
            isp = row.get("isp", "")
            reports = row.get("totalReports", "0")

            if not ip or int(score) < 50:
                continue

            doc = (
                f"Malicious IP: {ip}\n"
                f"Abuse confidence: {score}%\n"
                f"Country: {country}, ISP: {isp}\n"
                f"Total abuse reports: {reports}"
            )
            doc_id = f"abuseipdb_{ip.replace('.', '_')}"
            kb.ingest_document(doc_id, doc, source="abuseipdb_blacklist",
                               metadata={"ip": ip, "abuse_score": score, "country": country})
            count += 1

    logger.info(f"Ingested {count} malicious IPs from AbuseIPDB blacklist")
    return count


def ingest_mitre_groups(mitre_json_path: str) -> int:
    """
    Ingest threat actor group profiles from the MITRE ATT&CK JSON.
    Useful for attributing TTPs to known APT groups.
    """
    from rag.knowledge_base import ForensicKnowledgeBase
    kb = ForensicKnowledgeBase()

    with open(mitre_json_path, encoding="utf-8") as f:
        data = json.load(f)

    count = 0
    for obj in data.get("objects", []):
        if obj.get("type") != "intrusion-set":
            continue

        name = obj.get("name", "")
        aliases = obj.get("aliases", [])
        desc = obj.get("description", "")[:800]

        doc = (
            f"Threat Actor Group: {name}\n"
            f"Aliases: {', '.join(aliases)}\n"
            f"Description: {desc}"
        )
        doc_id = f"apt_{obj.get('id', name).replace('-', '_')}"
        kb.ingest_document(doc_id, doc, source="mitre_groups",
                           metadata={"group_name": name, "aliases": ",".join(aliases)})
        count += 1

    logger.info(f"Ingested {count} threat actor groups")
    return count
