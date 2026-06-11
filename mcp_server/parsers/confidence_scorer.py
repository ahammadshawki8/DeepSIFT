"""
Quantified Confidence Scorer — Priority 2.

Replaces qualitative 'high/medium/low' confidence with a 4-axis 100-point score.
Every finding gets a numeric score that judges can verify and compare.

Axes (inspired by FinSOC, adapted to DeepSIFT's architecture):
  Tool Reliability    (40 pts) — weighted mean reliability of tools called
  Corroboration       (25 pts) — number of independent artifact sources confirming
  IOC Specificity     (25 pts) — detail level of reported IOCs
  MITRE Accuracy      (10 pts) — technique IDs backed by multiple independent sources

Classification tiers:
  90–100  CONFIRMED        — strong multi-source evidence, high specificity
  70–89   HIGH CONFIDENCE  — solid evidence with minor gaps
  50–69   MODERATE         — reasonable evidence, some corroboration missing
  30–49   LOW CONFIDENCE   — limited corroboration, proceed with caution
  0–29    SPECULATIVE      — insufficient evidence; findings should not be reported
"""
from __future__ import annotations


# Per-tool reliability coefficients (0.0–1.0)
# Based on known false-positive rates and forensic literature
TOOL_RELIABILITY: dict[str, float] = {
    # Memory forensics — generally reliable but malfind has FP issues
    "get_process_list":          0.90,
    "scan_hidden_processes":     0.95,
    "find_injected_code":        0.72,  # malfind FP from JIT/CLR is well documented
    "get_running_services":      0.88,
    "get_network_connections":   0.92,
    "get_command_history":       0.95,
    "get_loaded_dlls":           0.88,
    "get_registry_hives":        0.90,
    "get_registry_key":          0.92,
    "get_handles":               0.85,
    "get_privileges":            0.90,
    "get_mutexes":               0.85,
    "get_env_vars":              0.88,
    "get_vad_info":              0.80,
    "get_ldrmodules":            0.90,
    "get_ssdt":                  0.88,
    "get_callbacks":             0.88,
    "get_filescan":              0.85,
    "get_timeliner":             0.88,
    # Windows artifacts — highly reliable (EZ Tools are well-validated)
    "parse_event_logs":          0.95,
    "parse_shimcache":           0.90,
    "parse_amcache":             0.95,
    "parse_prefetch":            0.95,
    "parse_mft":                 0.92,
    "parse_lnk_files":           0.88,
    "parse_jump_lists":          0.85,
    "parse_registry_hive":       0.90,
    "parse_recycle_bin":         0.90,
    "parse_srum":                0.85,
    "parse_usn_journal":         0.88,
    "parse_userassist":          0.90,
    "parse_recentdocs":          0.88,
    "parse_network_history":     0.85,
    "parse_usb_history":         0.88,
    # IP reputation — depends on database coverage
    "lookup_ip_reputation":      0.82,
    # YARA — signature quality varies
    "scan_memory_with_yara":     0.78,
    "scan_file_with_yara":       0.80,
    # Hayabusa — 3,700 Sigma rules, well-validated
    "parse_hayabusa":            0.90,
    # Timeline
    "create_super_timeline":     0.88,
    "filter_timeline":           0.85,
    "get_browser_history":       0.88,
    # Disk
    "get_partition_table":       0.95,
    "get_file_listing":          0.92,
    "extract_file":              0.95,
    "search_deleted_files":      0.90,
    # File analysis
    "get_pe_metadata":           0.90,
    "extract_strings":           0.80,
    "detect_packer":             0.85,
    # Network
    "parse_pcap_summary":        0.88,
    "extract_dns_queries":       0.90,
    "parse_arp_cache":           0.85,
    # Correlation (synthetic — based on inputs)
    "correlate_artifacts":       0.88,
    "adversarial_review":        0.90,
    "verify_findings":           0.95,
}

# Tool categories — used for corroboration counting
# Finding confirmed by tools from 2+ different categories = better corroboration
TOOL_CATEGORIES: dict[str, str] = {
    "get_process_list":      "memory",
    "scan_hidden_processes": "memory",
    "find_injected_code":    "memory",
    "get_running_services":  "memory",
    "get_network_connections":"memory",
    "get_command_history":   "memory",
    "get_loaded_dlls":       "memory",
    "get_registry_hives":    "memory",
    "get_registry_key":      "memory",
    "get_handles":           "memory",
    "get_privileges":        "memory",
    "get_mutexes":           "memory",
    "get_env_vars":          "memory",
    "get_vad_info":          "memory",
    "get_ldrmodules":        "memory",
    "get_ssdt":              "memory",
    "get_callbacks":         "memory",
    "get_filescan":          "memory",
    "get_timeliner":         "memory",
    "parse_event_logs":      "windows_artifacts",
    "parse_shimcache":       "windows_artifacts",
    "parse_amcache":         "windows_artifacts",
    "parse_prefetch":        "windows_artifacts",
    "parse_mft":             "disk",
    "parse_lnk_files":       "windows_artifacts",
    "parse_jump_lists":      "windows_artifacts",
    "parse_registry_hive":   "windows_artifacts",
    "parse_recycle_bin":     "windows_artifacts",
    "parse_srum":            "windows_artifacts",
    "parse_usn_journal":     "disk",
    "parse_userassist":      "windows_artifacts",
    "parse_recentdocs":      "windows_artifacts",
    "parse_network_history": "windows_artifacts",
    "parse_usb_history":     "windows_artifacts",
    "parse_hayabusa":        "windows_artifacts",
    "lookup_ip_reputation":  "threat_intel",
    "scan_memory_with_yara": "yara",
    "scan_file_with_yara":   "yara",
    "create_super_timeline": "timeline",
    "filter_timeline":       "timeline",
    "get_browser_history":   "timeline",
    "get_partition_table":   "disk",
    "get_file_listing":      "disk",
    "extract_file":          "disk",
    "search_deleted_files":  "disk",
    "get_pe_metadata":       "file_analysis",
    "extract_strings":       "file_analysis",
    "detect_packer":         "file_analysis",
    "parse_pcap_summary":    "network",
    "extract_dns_queries":   "network",
    "parse_arp_cache":       "network",
    "correlate_artifacts":   "correlation",
    "adversarial_review":    "correlation",
    "verify_findings":       "verification",
}

_TIER_LABELS = {
    (90, 101): "CONFIRMED",
    (70,  90): "HIGH_CONFIDENCE",
    (50,  70): "MODERATE",
    (30,  50): "LOW_CONFIDENCE",
    (0,   30): "SPECULATIVE",
}


def _tier(score: float) -> str:
    for (lo, hi), label in _TIER_LABELS.items():
        if lo <= score < hi:
            return label
    return "SPECULATIVE"


def calculate_confidence_score(
    audit_ids: list[str],
    findings: dict,
    audit_log_path,
    grounding_score: float = 100.0,
) -> dict:
    """
    Calculate a 4-axis confidence score (0–100 total) for an investigation.

    Args:
        audit_ids:          All audit_ids from the investigation.
        findings:           The findings dict (suspicious_processes, network_iocs, etc.)
        audit_log_path:     Path object to forensic_audit.log.
        grounding_score:    Result from GroundingVerifier (0–100).

    Returns dict with total score, per-axis breakdown, tier label, and recommendations.
    """
    # ── Load tool names from audit log ─────────────────────────────────────────
    tools_called: list[str] = []
    if audit_log_path and audit_log_path.exists():
        for line in audit_log_path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                entry = __import__("json").loads(line)
                if entry.get("audit_id") in audit_ids:
                    tool = entry.get("tool", "")
                    if tool:
                        tools_called.append(tool)
            except Exception:
                pass

    # ── Axis 1: Tool Reliability (40 pts) ─────────────────────────────────────
    reliabilities = [TOOL_RELIABILITY.get(t, 0.75) for t in tools_called]
    if reliabilities:
        mean_reliability = sum(reliabilities) / len(reliabilities)
        tool_reliability_pts = round(mean_reliability * 40, 1)
    else:
        tool_reliability_pts = 0.0

    # ── Axis 2: Corroboration (25 pts) ────────────────────────────────────────
    # Count unique evidence CATEGORIES (not just tools) that contributed
    categories_used = {TOOL_CATEGORIES.get(t, "unknown") for t in tools_called}
    categories_used.discard("unknown")
    categories_used.discard("correlation")
    categories_used.discard("verification")

    n_categories = len(categories_used)
    # 5+ categories = full score, linear below
    corroboration_pts = round(min(n_categories / 5, 1.0) * 25, 1)

    # Bonus: adversarial_review was called (+2 pts, max 25)
    if "adversarial_review" in tools_called:
        corroboration_pts = min(corroboration_pts + 2.0, 25.0)

    # ── Axis 3: IOC Specificity (25 pts) ──────────────────────────────────────
    # Measure how specific the reported IOCs are
    network_iocs = findings.get("network_iocs", [])
    suspicious_procs = findings.get("suspicious_processes", [])
    mitre_techs = findings.get("mitre_techniques", [])

    ioc_score = 0.0
    # Having any IOCs at all: 5 pts
    if network_iocs or suspicious_procs:
        ioc_score += 5.0
    # Specific IP addresses: up to 8 pts
    import re
    ip_pattern = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    ips_found = sum(
        1 for ioc in network_iocs
        if ip_pattern.search(str(ioc))
    )
    ioc_score += min(ips_found * 2.0, 8.0)
    # Specific process names with PIDs: up to 7 pts
    pid_pattern = re.compile(r"\b\d{4,6}\b")
    procs_with_pid = sum(
        1 for p in suspicious_procs
        if pid_pattern.search(str(p))
    )
    ioc_score += min(procs_with_pid * 2.0, 7.0)
    # MITRE techniques reported: up to 5 pts
    ioc_score += min(len(mitre_techs) * 1.0, 5.0)
    ioc_specificity_pts = round(min(ioc_score, 25.0), 1)

    # ── Axis 4: MITRE Accuracy (10 pts) ───────────────────────────────────────
    # Techniques confirmed by 2+ independent categories score higher
    # As a heuristic: if corroboration is high and MITRE tags exist, score high
    if mitre_techs and n_categories >= 2:
        mitre_accuracy_pts = round(min(len(mitre_techs) * 1.5, 10.0), 1)
    elif mitre_techs:
        mitre_accuracy_pts = round(min(len(mitre_techs) * 0.7, 5.0), 1)
    else:
        mitre_accuracy_pts = 0.0

    # ── Grounding adjustment ───────────────────────────────────────────────────
    # Penalise for unverified claims: up to -15 pts if grounding < 100%
    grounding_penalty = round((1.0 - grounding_score / 100.0) * 15.0, 1)

    raw_total = (
        tool_reliability_pts + corroboration_pts +
        ioc_specificity_pts + mitre_accuracy_pts
    )
    total = round(max(0.0, raw_total - grounding_penalty), 1)

    # ── Build recommendations ──────────────────────────────────────────────────
    recommendations: list[str] = []
    if tool_reliability_pts < 30:
        recommendations.append(
            "Call higher-reliability tools (parse_event_logs, parse_amcache, parse_prefetch) "
            "to boost Tool Reliability score."
        )
    if corroboration_pts < 15:
        recommendations.append(
            f"Only {n_categories} evidence category(ies) used — add disk artifact tools "
            "(parse_mft, parse_srum) or network analysis to improve Corroboration."
        )
    if ioc_specificity_pts < 15:
        recommendations.append(
            "IOCs lack specificity — include IP addresses with ports, process names with PIDs, "
            "and explicit MITRE technique IDs."
        )
    if grounding_score < 100:
        recommendations.append(
            f"Grounding score {grounding_score}% — resolve UNVERIFIED claims before "
            "submitting finish_analysis."
        )
    if "adversarial_review" not in tools_called:
        recommendations.append(
            "Call adversarial_review before finish_analysis to validate findings "
            "and earn +2 corroboration points."
        )

    return {
        "total_score": total,
        "tier": _tier(total),
        "breakdown": {
            "tool_reliability":   {"score": tool_reliability_pts, "max": 40,
                                   "detail": f"Mean reliability {round(mean_reliability * 100, 0) if reliabilities else 0}% across {len(tools_called)} tool calls"},
            "corroboration":      {"score": corroboration_pts, "max": 25,
                                   "detail": f"{n_categories} evidence category(ies): {sorted(categories_used)}"},
            "ioc_specificity":    {"score": ioc_specificity_pts, "max": 25,
                                   "detail": f"{len(network_iocs)} network IOCs, {len(suspicious_procs)} processes, {len(mitre_techs)} MITRE techniques"},
            "mitre_accuracy":     {"score": mitre_accuracy_pts, "max": 10,
                                   "detail": f"{len(mitre_techs)} technique(s) mapped"},
            "grounding_penalty":  {"score": -grounding_penalty, "max": 0,
                                   "detail": f"Grounding {grounding_score}%"},
        },
        "grounding_score": grounding_score,
        "tools_called": tools_called,
        "evidence_categories": sorted(categories_used),
        "recommendations": recommendations,
        "tier_thresholds": {
            "CONFIRMED": "90–100",
            "HIGH_CONFIDENCE": "70–89",
            "MODERATE": "50–69",
            "LOW_CONFIDENCE": "30–49",
            "SPECULATIVE": "0–29 (findings suppressed)",
        },
    }
