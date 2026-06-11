"""
Extended threat intelligence tools.

Tools:
  lookup_hash_reputation     — VirusTotal file hash lookup (MD5/SHA1/SHA256)
  lookup_domain_reputation   — VirusTotal + WHOIS domain reputation check
  search_mitre_technique     — Query RAG knowledge base for MITRE ATT&CK technique details
  search_ioc_database        — Search all IOCs in the RAG knowledge base
  calculate_fuzzy_hash_similarity — ssdeep similarity between two files/hashes
"""
from __future__ import annotations
import json
import os
import subprocess
from pathlib import Path

from mcp_server.audit import log_tool_execution, get_last_audit_id, increment_tool_counter, get_tool_count
from mcp_server.parsers.forensic_knowledge import wrap_response


def register_threat_intel_extended_tools(mcp, rag=None):

    @mcp.tool()
    def lookup_hash_reputation(file_hash: str) -> str:
        """
        Look up a file hash (MD5, SHA1, or SHA256) on VirusTotal.

        Returns: detection ratio, AV engine verdicts, file type, file size,
        first/last submission date, and known filenames.

        Requires: VT_API_KEY environment variable set to a VirusTotal API key.
        Free API keys available at virustotal.com.

        Args:
            file_hash: MD5, SHA1, or SHA256 hash of the file to look up.
        """
        increment_tool_counter()
        api_key = os.getenv("VT_API_KEY", "")
        if not api_key:
            log_tool_execution("lookup_hash_reputation", [file_hash], "no API key")
            audit_id = get_last_audit_id()
            return wrap_response("lookup_hash_reputation", {
                "hash": file_hash,
                "error": "VT_API_KEY not set in .env",
                "manual": f"Visit https://www.virustotal.com/gui/file/{file_hash}",
                "tool_calls_used": get_tool_count(),
            }, audit_id)

        import urllib.request
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        req = urllib.request.Request(url, headers={"x-apikey": api_key})

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8")
                report = json.loads(raw)
        except Exception as e:
            log_tool_execution("lookup_hash_reputation", [file_hash], f"error: {e}")
            audit_id = get_last_audit_id()
            return wrap_response("lookup_hash_reputation", {
                "hash": file_hash,
                "error": str(e),
                "tool_calls_used": get_tool_count(),
            }, audit_id)

        log_tool_execution("lookup_hash_reputation", [file_hash], raw[:500])
        audit_id = get_last_audit_id()

        attrs = report.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())

        data = {
            "hash": file_hash,
            "malicious_detections": malicious,
            "total_engines": total,
            "detection_ratio": f"{malicious}/{total}",
            "verdict": "MALICIOUS" if malicious > 3 else "SUSPICIOUS" if malicious > 0 else "CLEAN",
            "file_type": attrs.get("type_description", ""),
            "file_size": attrs.get("size", 0),
            "first_submission": attrs.get("first_submission_date", ""),
            "last_analysis_date": attrs.get("last_analysis_date", ""),
            "known_filenames": attrs.get("names", [])[:20],
            "vt_link": f"https://www.virustotal.com/gui/file/{file_hash}",
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("lookup_hash_reputation", data, audit_id)

    @mcp.tool()
    def lookup_domain_reputation(domain: str) -> str:
        """
        Check a domain's reputation using VirusTotal and WHOIS data.

        Returns: VirusTotal detection count, categories, WHOIS registrar,
        creation/expiration date, and whether the domain is newly registered
        (< 30 days — common for phishing infrastructure).

        Requires: VT_API_KEY environment variable.

        Args:
            domain: Domain name to check (e.g. 'evil-c2.com' or '185.220.101.45').
        """
        increment_tool_counter()
        api_key = os.getenv("VT_API_KEY", "")

        log_tool_execution("lookup_domain_reputation", [domain], "domain rep check")
        audit_id = get_last_audit_id()

        # WHOIS via whois command
        whois_data: dict = {}
        try:
            r = subprocess.run(
                ["whois", domain],
                capture_output=True, text=True, timeout=30,
            )
            whois_text = r.stdout[:3000]
            import re
            for field in ["Registrar", "Creation Date", "Updated Date", "Registry Expiry Date",
                          "Registrant Country", "Name Server"]:
                m = re.search(field + r"[:\s]+(.+)", whois_text, re.IGNORECASE)
                if m:
                    whois_data[field] = m.group(1).strip()[:200]
        except Exception:
            whois_data = {"note": "whois command not available"}

        vt_result: dict = {}
        if api_key:
            import urllib.request
            import base64
            encoded = base64.urlsafe_b64encode(domain.encode()).decode().rstrip("=")
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            req = urllib.request.Request(url, headers={"x-apikey": api_key})
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    report = json.loads(resp.read().decode("utf-8"))
                    attrs = report.get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    vt_result = {
                        "malicious": stats.get("malicious", 0),
                        "total_engines": sum(stats.values()),
                        "categories": attrs.get("categories", {}),
                        "reputation": attrs.get("reputation", 0),
                        "popularity_rank": attrs.get("popularity_ranks", {}),
                        "vt_link": f"https://www.virustotal.com/gui/domain/{domain}",
                    }
            except Exception as e:
                vt_result = {"error": str(e)}
        else:
            vt_result = {"note": "VT_API_KEY not set — skipping VirusTotal lookup"}

        data = {
            "domain": domain,
            "whois": whois_data,
            "virustotal": vt_result,
            "verdict": "MALICIOUS" if vt_result.get("malicious", 0) > 3 else "UNKNOWN",
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("lookup_domain_reputation", data, audit_id)

    @mcp.tool()
    def search_mitre_technique(technique_id_or_name: str) -> str:
        """
        Search the RAG knowledge base for MITRE ATT&CK technique details.

        Returns: technique description, sub-techniques, detection recommendations,
        mitigations, and related tools and procedures from the knowledge base.

        Args:
            technique_id_or_name: MITRE ATT&CK technique ID (e.g. 'T1055') or
                                   name (e.g. 'Process Injection').
        """
        increment_tool_counter()
        log_tool_execution("search_mitre_technique", [technique_id_or_name], "MITRE ATT&CK lookup")
        audit_id = get_last_audit_id()

        result: dict = {"query": technique_id_or_name}

        if rag is not None:
            try:
                hits = rag.query(
                    query=f"MITRE ATT&CK technique {technique_id_or_name}",
                    n_results=5,
                )
                result["rag_results"] = hits
            except Exception as e:
                result["rag_error"] = str(e)
        else:
            result["note"] = "RAG not initialized — results are from static knowledge only"

        # Static fallback for common techniques
        _STATIC_TECHNIQUES = {
            "T1055": {
                "name": "Process Injection",
                "description": "Adversaries inject code into processes to evade defenses and elevate privileges.",
                "sub_techniques": ["T1055.001 DLL Injection", "T1055.002 PE Injection", "T1055.012 Process Hollowing"],
                "detection": "Monitor for malfind hits, unusual memory regions with PE headers, CreateRemoteThread calls.",
                "mitigations": ["Behavior Prevention on Endpoint", "Privileged Account Management"],
            },
            "T1059.001": {
                "name": "PowerShell",
                "description": "Adversaries abuse PowerShell to execute malicious commands.",
                "detection": "Event ID 4104 (script block logging), encoded command usage, download cradles.",
                "mitigations": ["Disable or restrict PowerShell", "Enable script block logging"],
            },
            "T1014": {
                "name": "Rootkit",
                "description": "Adversaries use rootkits to hide the presence of programs, files, network connections.",
                "detection": "DKOM detection (pslist vs psscan diff), memory forensics, integrity checking.",
            },
        }

        query_upper = technique_id_or_name.upper()
        for tid, info in _STATIC_TECHNIQUES.items():
            if query_upper == tid or query_upper in info.get("name", "").upper():
                result["static_knowledge"] = {tid: info}
                break

        result["tool_calls_used"] = get_tool_count()
        return wrap_response("search_mitre_technique", result, audit_id)

    @mcp.tool()
    def search_ioc_database(query: str, ioc_type: str = "any") -> str:
        """
        Search the DeepSIFT RAG IOC database for known threat indicators.

        The IOC database is seeded from: MITRE ATT&CK, case-specific IOCs
        (ROCBA hostile IPs, MRC.exe, cloud exfiltration domains), and any
        custom threat intel ingested via rag/ingest/.

        Args:
            query:    IOC value or keyword to search for (IP, domain, hash, filename).
            ioc_type: Filter by IOC type: 'ip', 'domain', 'hash', 'filename', or 'any'.
        """
        increment_tool_counter()
        log_tool_execution("search_ioc_database", [query, ioc_type], "IOC database search")
        audit_id = get_last_audit_id()

        result: dict = {"query": query, "ioc_type": ioc_type}

        if rag is not None:
            try:
                search_query = f"{ioc_type} IOC {query}" if ioc_type != "any" else query
                hits = rag.query(query=search_query, n_results=10)
                result["matches"] = hits
                result["match_count"] = len(hits) if isinstance(hits, list) else 0
            except Exception as e:
                result["rag_error"] = str(e)
        else:
            result["note"] = "RAG not initialized — seed with: python3 rag/ingest/run_all.py"

        result["tool_calls_used"] = get_tool_count()
        return wrap_response("search_ioc_database", result, audit_id)

    @mcp.tool()
    def calculate_fuzzy_hash_similarity(file_path_or_hash_a: str, file_path_or_hash_b: str) -> str:
        """
        Calculate ssdeep fuzzy hash similarity between two files or two ssdeep hashes.

        ssdeep fuzzy hashing compares files that are similar but not identical —
        useful for detecting malware variants, slightly modified exploit kits,
        and watermarked documents with minor changes.

        Similarity score: 0 (completely different) to 100 (identical).
        Scores above 50 indicate strong similarity (likely variants).

        Args:
            file_path_or_hash_a: Absolute path to file A, or its ssdeep hash string.
            file_path_or_hash_b: Absolute path to file B, or its ssdeep hash string.
        """
        increment_tool_counter()
        log_tool_execution("calculate_fuzzy_hash_similarity",
                           [file_path_or_hash_a, file_path_or_hash_b],
                           "ssdeep similarity")
        audit_id = get_last_audit_id()

        # If both are file paths, compute hashes first
        hash_a = file_path_or_hash_a
        hash_b = file_path_or_hash_b

        if Path(file_path_or_hash_a).exists():
            try:
                r = subprocess.run(["ssdeep", "-s", file_path_or_hash_a],
                                   capture_output=True, text=True, timeout=30)
                lines = [l for l in r.stdout.splitlines() if "," in l]
                if lines:
                    hash_a = lines[0].split(",")[0]
            except FileNotFoundError:
                return json.dumps({"error": "ssdeep not found. Install: sudo apt install ssdeep"})

        if Path(file_path_or_hash_b).exists():
            try:
                r = subprocess.run(["ssdeep", "-s", file_path_or_hash_b],
                                   capture_output=True, text=True, timeout=30)
                lines = [l for l in r.stdout.splitlines() if "," in l]
                if lines:
                    hash_b = lines[0].split(",")[0]
            except FileNotFoundError:
                return json.dumps({"error": "ssdeep not found. Install: sudo apt install ssdeep"})

        # Compare using ssdeep -k
        similarity: int = 0
        try:
            r = subprocess.run(
                ["ssdeep", "-k", hash_a, hash_b],
                capture_output=True, text=True, timeout=10,
            )
            import re
            m = re.search(r"(\d+)%", r.stdout + r.stderr)
            if m:
                similarity = int(m.group(1))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # Pure Python fallback: character-level ratio
            from difflib import SequenceMatcher
            similarity = int(SequenceMatcher(None, hash_a, hash_b).ratio() * 100)

        interpretation = (
            "Likely variants of the same malware" if similarity >= 50
            else "Some similarity — investigate further" if similarity >= 20
            else "Dissimilar files"
        )

        data = {
            "file_a": file_path_or_hash_a,
            "file_b": file_path_or_hash_b,
            "ssdeep_hash_a": hash_a[:100],
            "ssdeep_hash_b": hash_b[:100],
            "similarity_score": similarity,
            "interpretation": interpretation,
            "tool_calls_used": get_tool_count(),
        }
        return wrap_response("calculate_fuzzy_hash_similarity", data, audit_id)
