"""
LangGraph multi-agent forensic orchestrator.

Fan-out architecture: memory, disk, and network agents run in parallel,
results are synthesized, then a final report is generated.
"""
from __future__ import annotations
import json
import logging
from typing import TypedDict, Annotated
import operator

logger = logging.getLogger(__name__)


class ForensicState(TypedDict):
    image_path: str
    case_dir: str
    memory_findings: dict
    disk_findings: dict
    network_findings: dict
    synthesis: dict
    final_report: dict
    iterations: int
    errors: Annotated[list[str], operator.add]
    status: str


MAX_ITERATIONS = 10


class ForensicOrchestrator:
    def __init__(self, rag=None):
        self.rag = rag
        self.graph = self._build_graph()

    def _build_graph(self):
        from langgraph.graph import StateGraph, END

        wf = StateGraph(ForensicState)

        wf.add_node("memory_agent", self._memory_agent)
        wf.add_node("disk_agent", self._disk_agent)
        wf.add_node("network_agent", self._network_agent)
        wf.add_node("synthesis_agent", self._synthesis_agent)
        wf.add_node("report_agent", self._report_agent)

        # Fan-out: all three specialist agents run from start
        wf.set_entry_point("memory_agent")
        wf.add_edge("memory_agent", "disk_agent")
        wf.add_edge("disk_agent", "network_agent")
        wf.add_edge("network_agent", "synthesis_agent")
        wf.add_edge("synthesis_agent", "report_agent")
        wf.add_edge("report_agent", END)

        return wf.compile()

    # ── Specialist agents ────────────────────────────────────────────────

    def _memory_agent(self, state: ForensicState) -> dict:
        """Memory forensics specialist: process list, injected code, network connections."""
        logger.info("[memory_agent] Starting memory analysis")
        findings = {}

        try:
            from mcp_server.tools.volatility import (
                register_volatility_tools,
            )
            # Direct function calls (not via MCP transport) for orchestrator mode
            import json as _json
            from mcp_server.config import VOLATILITY_CMD
            from mcp_server.parsers.pslist_parser import parse_pslist, analyze_processes
            from mcp_server.parsers.netscan_parser import parse_netscan, get_external_ips
            from mcp_server.parsers.malfind_parser import parse_malfind
            from mcp_server.audit import log_tool_execution
            import subprocess

            image = state["image_path"]

            # Process list
            result = subprocess.run(
                VOLATILITY_CMD + ["-f", image, "windows.pslist"],
                capture_output=True, text=True, timeout=300,
            )
            processes = analyze_processes(parse_pslist(result.stdout))
            findings["processes"] = processes
            findings["suspicious_processes"] = [p for p in processes if p["suspicious"]]

            # Injected code
            result = subprocess.run(
                VOLATILITY_CMD + ["-f", image, "windows.malfind"],
                capture_output=True, text=True, timeout=300,
            )
            injections = parse_malfind(result.stdout)
            findings["injections"] = injections
            findings["high_risk_injections"] = [i for i in injections if i.get("risk_level") == "high"]

            # Command lines
            result = subprocess.run(
                VOLATILITY_CMD + ["-f", image, "windows.cmdline"],
                capture_output=True, text=True, timeout=300,
            )
            findings["cmdlines_raw"] = result.stdout[:5000]

            logger.info(
                f"[memory_agent] Done: {len(processes)} processes, "
                f"{len(findings['suspicious_processes'])} suspicious, "
                f"{len(injections)} malfind findings"
            )

        except Exception as e:
            logger.error(f"[memory_agent] Error: {e}")
            findings["error"] = str(e)

        return {
            "memory_findings": findings,
            "iterations": state["iterations"] + 1,
        }

    def _disk_agent(self, state: ForensicState) -> dict:
        """Disk forensics specialist: file timeline, deleted files, prefetch."""
        logger.info("[disk_agent] Disk analysis — stub (requires disk image, not memory image)")
        findings = {
            "note": "Disk agent requires a disk image (.E01, .dd, .vmdk). "
                    "If only a memory image is available, skip to network_agent.",
            "prefetch": [],
            "deleted_files": [],
            "timeline_summary": {},
        }
        return {"disk_findings": findings}

    def _network_agent(self, state: ForensicState) -> dict:
        """Network forensics specialist: connections + IP reputation."""
        logger.info("[network_agent] Starting network analysis")
        findings = {}

        try:
            from mcp_server.config import VOLATILITY_CMD
            from mcp_server.parsers.netscan_parser import parse_netscan, get_external_ips
            import subprocess

            image = state["image_path"]
            result = subprocess.run(
                VOLATILITY_CMD + ["-f", image, "windows.netscan"],
                capture_output=True, text=True, timeout=300,
            )
            connections = parse_netscan(result.stdout)
            external_ips = get_external_ips(connections)
            findings["connections"] = connections
            findings["external_ips"] = external_ips
            findings["suspicious_connections"] = [c for c in connections if c.get("suspicious")]

            logger.info(
                f"[network_agent] Done: {len(connections)} connections, "
                f"{len(external_ips)} external IPs"
            )

        except Exception as e:
            logger.error(f"[network_agent] Error: {e}")
            findings["error"] = str(e)

        return {"network_findings": findings}

    def _synthesis_agent(self, state: ForensicState) -> dict:
        """Cross-correlates memory, disk, and network findings."""
        logger.info("[synthesis_agent] Correlating findings")
        memory = state.get("memory_findings", {})
        disk = state.get("disk_findings", {})
        network = state.get("network_findings", {})

        suspicious_procs = {
            p["pid"]: p["name"]
            for p in memory.get("suspicious_processes", [])
        }
        suspicious_conns = [
            c for c in network.get("suspicious_connections", [])
            if c.get("pid") in suspicious_procs
        ]

        synthesis = {
            "correlated_suspicious_processes": list(suspicious_procs.values()),
            "processes_with_network_activity": [
                {
                    "pid": c["pid"],
                    "process": suspicious_procs.get(c["pid"], "unknown"),
                    "foreign_addr": c["foreign_addr"],
                    "foreign_port": c["foreign_port"],
                    "state": c["state"],
                }
                for c in suspicious_conns
            ],
            "high_risk_injections": memory.get("high_risk_injections", []),
            "external_ips": network.get("external_ips", []),
            "total_suspicious_processes": len(suspicious_procs),
            "total_suspicious_connections": len(suspicious_conns),
        }

        if self.rag and synthesis["external_ips"]:
            for ip in synthesis["external_ips"][:5]:
                context = self.rag.query(f"malicious IP {ip} C2 command and control")
                synthesis.setdefault("threat_intel", {})[ip] = context

        return {"synthesis": synthesis}

    def _report_agent(self, state: ForensicState) -> dict:
        """Generates the final structured report from synthesized findings."""
        logger.info("[report_agent] Generating final report")
        synthesis = state.get("synthesis", {})
        memory = state.get("memory_findings", {})

        report = {
            "case_dir": state.get("case_dir", "."),
            "image_path": state.get("image_path", ""),
            "summary": self._build_summary(synthesis, memory),
            "suspicious_processes": synthesis.get("correlated_suspicious_processes", []),
            "network_iocs": synthesis.get("external_ips", []),
            "high_risk_injections": len(synthesis.get("high_risk_injections", [])),
            "processes_with_c2": synthesis.get("processes_with_network_activity", []),
            "iterations_used": state.get("iterations", 0),
            "status": "complete",
        }

        import json as _json
        from pathlib import Path
        out_dir = Path(state.get("case_dir", ".")) / "analysis"
        out_dir.mkdir(parents=True, exist_ok=True)
        with open(out_dir / "orchestrator_report.json", "w", encoding="utf-8") as f:
            _json.dump(report, f, indent=2, default=str)

        return {"final_report": report, "status": "complete"}

    def _build_summary(self, synthesis: dict, memory: dict) -> str:
        n_procs = synthesis.get("total_suspicious_processes", 0)
        n_conns = synthesis.get("total_suspicious_connections", 0)
        n_inject = len(synthesis.get("high_risk_injections", []))
        ips = synthesis.get("external_ips", [])

        parts = []
        if n_procs:
            parts.append(f"{n_procs} suspicious process(es) detected")
        if n_inject:
            parts.append(f"{n_inject} high-risk memory injection(s) found")
        if n_conns:
            parts.append(f"{n_conns} suspicious network connection(s) observed")
        if ips:
            parts.append(f"External IPs contacted: {', '.join(ips[:5])}")
        if not parts:
            parts.append("No high-confidence indicators identified — manual review recommended")

        return ". ".join(parts) + "."

    # ── Public interface ──────────────────────────────────────────────────

    def investigate(self, image_path: str, case_dir: str = "./analysis") -> dict:
        """Run full multi-agent investigation against a forensic image."""
        initial: ForensicState = {
            "image_path": image_path,
            "case_dir": case_dir,
            "memory_findings": {},
            "disk_findings": {},
            "network_findings": {},
            "synthesis": {},
            "final_report": {},
            "iterations": 0,
            "errors": [],
            "status": "running",
        }
        final_state = self.graph.invoke(initial)
        return final_state.get("final_report", {})


if __name__ == "__main__":
    import argparse
    import sys

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Run DeepSIFT multi-agent investigation")
    parser.add_argument("--image", required=True, help="Path to forensic memory image")
    parser.add_argument("--case-dir", default="./analysis", help="Output directory for findings")
    args = parser.parse_args()

    orchestrator = ForensicOrchestrator()
    report = orchestrator.investigate(args.image, args.case_dir)
    print(json.dumps(report, indent=2, default=str))
