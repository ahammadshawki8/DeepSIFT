"""
DeepSIFT agentic reasoning loop — hypothesis-driven, self-correcting investigation.

Unlike the deterministic LangGraph pipeline (agents/orchestrator.py), this is a true
agent: an LLM forms hypotheses from initial evidence, decides which DeepSIFT MCP tool
to run next, reads the *structured* (parsed, audited) tool output, confirms / disproves /
marks-inconclusive each hypothesis with a confidence score, self-corrects when a result
contradicts a hypothesis or a tool errors, and finally synthesises an attack-chain
narrative. It uses Anthropic native tool-use over the typed MCP tools — the LLM never
sees raw shell output and can never run a raw shell command (the tools are the only
interface, and every tool routes through the architectural command/path guards).

This directly targets the hackathon objective: "think like a senior analyst — sequence
the approach, recognise when something doesn't add up, and self-correct."

Design notes
------------
* LLM is pluggable. The default uses the `anthropic` SDK with ANTHROPIC_API_KEY. Any
  object exposing `.create_message(system, messages, tools)` can be injected (the test
  suite injects a deterministic MockLLM, so the loop logic is verified without a key).
* Tool execution is pluggable too (`tool_runner`). The default drives the real MCP
  server tools; tests inject a fake runner. No tool can be invoked that the MCP server
  did not register, and destructive binaries are blocked in mcp_server.audit.guard_command.
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger("deepsift.reasoning")

MAX_ITERATIONS_DEFAULT = int(os.getenv("AGENT_MAX_ITERATIONS", "25"))
DEFAULT_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")


# ── Hypothesis bookkeeping ──────────────────────────────────────────────────────
@dataclass
class Hypothesis:
    id: int
    statement: str
    status: str = "open"          # open | confirmed | disproved | inconclusive
    confidence: float = 0.0       # 0.0 – 1.0
    evidence: list = field(default_factory=list)   # audit_id / finding references

    def update(self, status: str, confidence: float, evidence: Optional[str] = None):
        self.status = status
        self.confidence = round(float(confidence), 3)
        if evidence:
            self.evidence.append(evidence)


# ── LLM client abstraction ──────────────────────────────────────────────────────
class AnthropicLLM:
    """Thin wrapper over the Anthropic Messages API with native tool-use."""

    def __init__(self, model: str = DEFAULT_MODEL, api_key: Optional[str] = None):
        import anthropic
        key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        if not key or key.startswith("your_key") or key == "sk-ant-...":
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set to a real key. The agentic loop needs an "
                "LLM. Set ANTHROPIC_API_KEY in .env (or inject a custom LLM client)."
            )
        self.client = anthropic.Anthropic(api_key=key)
        self.model = model

    def create_message(self, system: str, messages: list, tools: list) -> dict:
        resp = self.client.messages.create(
            model=self.model, max_tokens=4096, system=system,
            messages=messages, tools=tools,
        )
        # Normalise to a plain dict the loop understands.
        return {
            "stop_reason": resp.stop_reason,
            "content": [
                {"type": b.type, **({"text": b.text} if b.type == "text" else {}),
                 **({"id": b.id, "name": b.name, "input": b.input}
                    if b.type == "tool_use" else {})}
                for b in resp.content
            ],
        }


# ── The agent ───────────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are DeepSIFT, a senior DFIR analyst running an autonomous \
investigation on a SANS SIFT Workstation. You have typed forensic tools (memory, disk, \
Windows artifacts, registry, browser, network, timeline, threat-intel, correlation). \
Every tool returns parsed, audited JSON — never raw shell. You CANNOT run shell commands.

Work like a senior analyst:
1. Start broad with TRIAGE appropriate to the evidence you were given, then form explicit
   HYPOTHESES about what happened. For a memory image, start with the process list. For a
   DISK-ONLY case (no memory image), start with disk/Windows-artifact triage — event logs,
   shellbags, UserAssist, LNK/Jump Lists, USB history, shimcache, browser history, MFT.
2. For each hypothesis, choose the tool that would CONFIRM or DISPROVE it. Do not guess —
   if a tool returns nothing, say so; never invent processes, IPs, files, or timestamps.
3. When evidence contradicts a hypothesis, SELF-CORRECT: revise or disprove it and pivot.
4. Track confidence honestly. Mark findings inconclusive when the evidence is thin.
5. A memory image may be captured AFTER the incident — if so, pivot to disk artifacts
   (event logs, LNK/Jump Lists, browser history, MFT) where the earlier evidence lives.

After each tool result, briefly state: which hypothesis it bears on, and confirm/disprove/
inconclusive with a confidence. When you have enough evidence, call `finish_investigation`
with the full findings and an attack-chain narrative. Be rigorous and honest over complete."""


# A synthetic control tool the agent calls to terminate with structured findings.
FINISH_TOOL = {
    "name": "finish_investigation",
    "description": "Call when the investigation is complete. Provide the final structured findings and the attack-chain narrative.",
    "input_schema": {
        "type": "object",
        "properties": {
            "summary": {"type": "string"},
            "attack_chain": {"type": "array", "items": {"type": "string"},
                              "description": "Ordered narrative steps reconstructing the incident."},
            "suspicious_processes": {"type": "array", "items": {"type": "string"}},
            "network_iocs": {"type": "array", "items": {"type": "string"}},
            "files_accessed": {"type": "array", "items": {"type": "string"}},
            "mitre_techniques": {"type": "array", "items": {"type": "string"}},
            "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        },
        "required": ["summary", "confidence"],
    },
}


class ReasoningAgent:
    def __init__(self, llm=None, tool_runner: Optional[Callable] = None,
                 tools: Optional[list] = None, rag=None,
                 max_iterations: int = MAX_ITERATIONS_DEFAULT):
        self.llm = llm
        self.tool_runner = tool_runner          # (name, args) -> str | dict
        self.tools = tools or []                # Anthropic tool schemas
        self.rag = rag
        self.max_iterations = max_iterations
        self.hypotheses: list[Hypothesis] = []
        self.transcript: list[dict] = []
        self._hid = 0

    # -- hypothesis helpers (also callable by the model via record_hypothesis) ----
    def add_hypothesis(self, statement: str) -> Hypothesis:
        self._hid += 1
        h = Hypothesis(self._hid, statement)
        self.hypotheses.append(h)
        return h

    def _audit(self, event: str, detail: dict):
        self.transcript.append({"t": round(time.time(), 3), "event": event, **detail})
        try:
            from mcp_server.audit import log_tool_execution  # reuse chain-of-custody log
            if event == "tool_call":
                log_tool_execution(f"agent:{detail.get('tool')}",
                                   [detail.get("tool", ""), json.dumps(detail.get("args", {}))],
                                   json.dumps(detail.get("result_preview", ""))[:2000])
        except Exception:
            pass

    # -- main loop ----------------------------------------------------------------
    def investigate(self, image_path: str = "", case_dir: str = "./analysis",
                    evidence_mount: str = "", extra_context: str = "") -> dict:
        """Run an autonomous investigation over whatever evidence is supplied.

        Works for three evidence shapes — memory-only, disk-only, or memory+disk —
        so a disk-only case (no Volatility image) is a first-class autonomous run, not
        a manual fallback. The bootstrap triage step adapts to what is available.
        """
        Path(case_dir).mkdir(parents=True, exist_ok=True)
        all_tools = list(self.tools) + [FINISH_TOOL]

        self._evidence_mount = evidence_mount
        has_memory = bool(image_path)
        has_disk = bool(evidence_mount)

        ctx_lines = []
        if has_memory:
            ctx_lines.append(f"Memory image: {image_path}")
        if has_disk:
            ctx_lines.append(f"Mounted evidence (disk, read-only): {evidence_mount}")
        if not ctx_lines:
            ctx_lines.append("No evidence path supplied — report that no evidence is available.")
        if extra_context:
            ctx_lines.append(extra_context)
        ctx = "\n".join(ctx_lines)

        # Pick the bootstrap step + RAG triage hint to match the evidence type, so a
        # disk-only case starts with disk triage (partitions/artifacts) rather than a
        # memory process list that has no image to run against.
        if has_memory:
            first_step = ("Begin with get_process_list (Hunt Evil baseline triage), then form "
                          "hypotheses and test them. If the memory image was captured after the "
                          "incident, pivot to disk artifacts where the earlier evidence lives.")
            rag_q = "initial triage memory forensics suspicious process baseline"
        else:
            first_step = ("This is a DISK-ONLY case (no memory image). Begin by orienting on the "
                          "mounted evidence: enumerate users/profiles and key artifact locations, "
                          "then triage Windows artifacts — event logs, shellbags, UserAssist, "
                          "LNK / Jump Lists, USB history, shimcache, browser history, MFT. Form "
                          "hypotheses about access/staging/exfiltration and test each with the tool "
                          "that would confirm or disprove it.")
            rag_q = "disk forensics triage windows artifacts lnk shellbags event logs exfiltration"

        if self.rag:
            try:
                hint = self.rag.query(rag_q)
                if hint:
                    ctx += f"\n\nThreat-intel context:\n{hint[:800]}"
            except Exception:
                pass

        messages = [{"role": "user", "content":
                     f"Investigate this evidence for unauthorized access / compromise.\n{ctx}\n"
                     f"{first_step}"}]

        findings: dict = {}
        for i in range(self.max_iterations):
            resp = self.llm.create_message(SYSTEM_PROMPT, messages, all_tools)
            content = resp.get("content", [])
            messages.append({"role": "assistant", "content": self._to_api_content(content)})

            tool_uses = [b for b in content if b.get("type") == "tool_use"]
            if not tool_uses:
                # model produced only text — nudge it to act or finish
                self._audit("reasoning", {"text": _first_text(content)[:500], "iteration": i})
                messages.append({"role": "user", "content":
                                 "Continue: run the next tool to test a hypothesis, or call "
                                 "finish_investigation if you have enough evidence."})
                continue

            tool_results = []
            for tu in tool_uses:
                name, args, tid = tu.get("name"), tu.get("input", {}), tu.get("id")
                if name == "finish_investigation":
                    findings = self._finalize(args, case_dir, image_path)
                    self._audit("finish", {"iteration": i})
                    return findings
                result = self._run_tool(name, args)
                self._audit("tool_call", {"tool": name, "args": args,
                                          "result_preview": str(result)[:300], "iteration": i})
                tool_results.append({"type": "tool_result", "tool_use_id": tid,
                                     "content": str(result)[:12000]})
            messages.append({"role": "user", "content": tool_results})

        # Hit iteration cap without finishing — return best-effort partial.
        logger.warning("Agent reached max_iterations without finish_investigation")
        findings = self._finalize(
            {"summary": "Investigation hit iteration limit; partial findings.",
             "confidence": "low"}, case_dir, image_path, partial=True)
        return findings

    def _run_tool(self, name: str, args: dict):
        if self.tool_runner is None:
            return {"error": "no tool_runner configured"}
        try:
            return self.tool_runner(name, args)
        except Exception as e:           # tool failure → feed back so the model self-corrects
            return {"error": f"{type(e).__name__}: {e}",
                    "hint": "Tool failed — revise the hypothesis or try a different tool."}

    def _finalize(self, args: dict, case_dir: str, image_path: str, partial: bool = False) -> dict:
        report = {
            "image_path": image_path or "(disk-only — no memory image)",
            "evidence_mount": getattr(self, "_evidence_mount", ""),
            "mode": "agentic-reasoning",
            "summary": args.get("summary", ""),
            "attack_chain": args.get("attack_chain", []),
            "suspicious_processes": args.get("suspicious_processes", []),
            "network_iocs": args.get("network_iocs", []),
            "files_accessed": args.get("files_accessed", []),
            "mitre_techniques": args.get("mitre_techniques", []),
            "confidence": args.get("confidence", "low"),
            "hypotheses": [asdict(h) for h in self.hypotheses],
            "iterations_used": len([t for t in self.transcript if t["event"] == "tool_call"]),
            "partial": partial,
            "status": "complete" if not partial else "partial",
        }
        out = Path(case_dir) / "findings_agentic.json"
        with open(out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        with open(Path(case_dir) / "agent_transcript.json", "w", encoding="utf-8") as f:
            json.dump(self.transcript, f, indent=2, default=str)
        logger.info(f"[reasoning_agent] findings -> {out}")
        return report

    @staticmethod
    def _to_api_content(content: list) -> list:
        """Rebuild assistant content blocks for the next API turn."""
        out = []
        for b in content:
            if b.get("type") == "text":
                out.append({"type": "text", "text": b.get("text", "")})
            elif b.get("type") == "tool_use":
                out.append({"type": "tool_use", "id": b.get("id"),
                            "name": b.get("name"), "input": b.get("input", {})})
        return out


def _first_text(content: list) -> str:
    for b in content:
        if b.get("type") == "text":
            return b.get("text", "")
    return ""


# ── Default tool runner over the live MCP server ────────────────────────────────
# Curated high-value investigation tools. Presenting a focused set (vs all 148) keeps
# each LLM request small/cheap and sharpens reasoning; pass core_only=False for everything.
CORE_TOOLS = {
    # Memory triage
    "get_process_list", "scan_hidden_processes", "find_injected_code",
    "get_running_services", "get_network_connections", "get_command_history",
    "get_loaded_dlls",
    # Disk / Windows artifacts (also the disk-only-case core)
    "parse_event_logs", "parse_shimcache", "parse_amcache", "parse_prefetch",
    "parse_mft", "parse_lnk_files", "parse_jump_lists", "parse_registry_hive",
    "parse_shellbags", "parse_userassist", "parse_recentdocs", "parse_usb_history",
    "parse_recycle_bin",
    # Browser / cloud exfil
    "parse_chrome_history", "parse_browser_downloads",
    # Disk imaging / timeline
    "get_partition_table", "get_file_listing", "create_super_timeline", "detect_timestomping",
    # Threat intel + correlation
    "lookup_ip_reputation", "lookup_hash_reputation",
    "search_ioc_database", "search_mitre_technique", "correlate_findings",
}


def build_mcp_tool_runner(core_only: bool = True):
    """Return (tools_schema, runner) driving the registered MCP server tools in-process.

    core_only=True presents a curated ~25-tool investigation set (smaller/cheaper LLM
    requests, sharper reasoning); False exposes all 148 registered tools.
    """
    import asyncio
    import mcp_server.server as s

    tool_objs = _list_tools_sync(s)
    if core_only:
        filtered = [t for t in tool_objs if t.name in CORE_TOOLS]
        tool_objs = filtered or tool_objs

    def _schema(t):
        for attr in ("parameters", "inputSchema", "input_schema"):
            sch = getattr(t, attr, None)
            if isinstance(sch, dict):
                return sch
        return {"type": "object", "properties": {}}

    schemas = [{"name": t.name, "description": (getattr(t, "description", "") or "")[:1024],
                "input_schema": _schema(t)} for t in tool_objs]

    def runner(name: str, args: dict):
        out = asyncio.run(s.mcp.call_tool(name, args))
        c = out[0] if isinstance(out, tuple) else out
        if isinstance(c, list):
            c = c[0]
        return getattr(c, "text", str(c))

    return schemas, runner


def _list_tools_sync(s):
    return s.mcp._tool_manager.list_tools()
