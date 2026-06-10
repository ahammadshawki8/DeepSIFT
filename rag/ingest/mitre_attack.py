"""Download and ingest the MITRE ATT&CK Enterprise framework into the knowledge base."""
from __future__ import annotations
import json
import logging
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

MITRE_CTI_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def download_mitre(output_path: str = "./rag/data/enterprise-attack.json") -> str:
    """Download the MITRE ATT&CK JSON from GitHub. Returns local path."""
    import requests
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    logger.info(f"Downloading MITRE ATT&CK from {MITRE_CTI_URL} ...")
    r = requests.get(MITRE_CTI_URL, stream=True, timeout=60)
    r.raise_for_status()

    with open(output_path, "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            f.write(chunk)

    size_mb = Path(output_path).stat().st_size / 1024 / 1024
    logger.info(f"Downloaded {size_mb:.1f} MB → {output_path}")
    return output_path


def ingest(mitre_json_path: str | None = None) -> int:
    """
    Download (if needed) and ingest MITRE ATT&CK into the knowledge base.
    Returns number of techniques ingested.
    """
    from rag.knowledge_base import ForensicKnowledgeBase

    local_path = mitre_json_path or "./rag/data/enterprise-attack.json"

    if not Path(local_path).exists():
        local_path = download_mitre(local_path)

    kb = ForensicKnowledgeBase()
    count = kb.ingest_mitre_attack(local_path)
    # Also load the Hunt Evil process baseline
    kb.ingest_hunt_evil_baseline()
    return count


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    path = sys.argv[1] if len(sys.argv) > 1 else None
    n = ingest(path)
    print(f"Ingested {n} MITRE ATT&CK techniques into knowledge base.")
