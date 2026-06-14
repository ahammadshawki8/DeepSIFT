"""
Investigation-state (autonomy capture) MCP tools.

When Claude Code itself is the agent driving the MCP server (the primary, no-API-key
path), its *reasoning* — hypotheses, confirm/disprove decisions, confidence, pivots —
otherwise lives only in the chat and is lost. These tools let the agent record that
reasoning SERVER-SIDE, so a Claude Code investigation produces the same auditable
evidence of autonomous, self-correcting analysis that a standalone agent loop would:
a hypothesis ledger with status transitions, each tied to the tool calls (audit_ids)
that confirmed or disproved it.

The ledger is persisted to ANALYSIS_DIR/hypotheses.json and folded into findings.json
by finish_analysis. begin_case_audit() resets it per case.
"""
import json
from datetime import datetime, timezone

from mcp_server.config import ANALYSIS_DIR
from mcp_server.audit import log_tool_execution, get_last_audit_id
from mcp_server.parsers.forensic_knowledge import wrap_response

_VALID_STATUS = {"open", "confirmed", "disproved", "inconclusive"}


def _hyp_path():
    return ANALYSIS_DIR / "hypotheses.json"


def load_hypotheses() -> list[dict]:
    try:
        return json.loads(_hyp_path().read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError):
        return []


def _save(hyps: list[dict]) -> None:
    ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)
    _hyp_path().write_text(json.dumps(hyps, indent=2), encoding="utf-8")


def hypothesis_summary(hyps: list[dict]) -> dict:
    by = {"open": 0, "confirmed": 0, "disproved": 0, "inconclusive": 0}
    corrections = 0
    for h in hyps:
        by[h.get("status", "open")] = by.get(h.get("status", "open"), 0) + 1
        # A genuine self-correction = a DECIDED status (not 'open') was later changed to a
        # different decided status (e.g. inconclusive→disproved, confirmed→disproved).
        # A normal open→confirmed progression is not a correction.
        decided = [e.get("status") for e in h.get("history", []) if e.get("status") != "open"]
        if len(set(decided)) > 1:
            corrections += 1
    return {"total": len(hyps), **by, "self_corrections": corrections}


def register_investigation_state_tools(mcp, rag=None):

    @mcp.tool()
    def record_hypothesis(statement: str, rationale: str = "", mitre_techniques: list = None) -> str:
        """
        Record an explicit investigative HYPOTHESIS before you test it (senior-analyst
        method). Returns a hypothesis id (H1, H2, …) to reference when you confirm or
        disprove it with update_hypothesis. Use this so your reasoning is captured and
        auditable, not just the tool calls.

        Args:
            statement:        The falsifiable claim, e.g. "Classified data was copied to USB".
            rationale:        Why you suspect it / what would confirm or disprove it.
            mitre_techniques: Optional ATT&CK IDs this hypothesis maps to.
        """
        hyps = load_hypotheses()
        hid = f"H{len(hyps) + 1}"
        now = datetime.now(timezone.utc).isoformat()
        h = {
            "id": hid, "statement": statement, "rationale": rationale,
            "mitre_techniques": mitre_techniques or [],
            "status": "open", "confidence": 0.0, "evidence": [],
            "created": now,
            "history": [{"t": now, "status": "open", "confidence": 0.0, "note": "formed"}],
        }
        hyps.append(h)
        _save(hyps)
        log_tool_execution("reasoning:record_hypothesis", [hid, statement],
                           json.dumps({"id": hid, "statement": statement, "rationale": rationale}))
        return wrap_response("record_hypothesis",
                             {"id": hid, "statement": statement, "status": "open",
                              "note": "Test this with the tool that would confirm/disprove it, "
                                      "then call update_hypothesis(id, status, confidence, evidence_audit_ids)."},
                             get_last_audit_id())

    @mcp.tool()
    def update_hypothesis(hypothesis_id: str, status: str, confidence: float,
                          evidence_audit_ids: list = None, note: str = "") -> str:
        """
        Update a hypothesis after testing it — confirm / disprove / mark inconclusive,
        with a confidence (0.0–1.0) and the audit_ids of the tool calls that decided it.
        Recording a status change away from a previous decision captures SELF-CORRECTION.

        Args:
            hypothesis_id:       The id from record_hypothesis (e.g. "H2").
            status:              one of: confirmed | disproved | inconclusive | open
            confidence:          0.0–1.0 — be honest; mark inconclusive when evidence is thin.
            evidence_audit_ids:  audit_id values from the tool calls that support this decision.
            note:                Brief reasoning, esp. if pivoting / correcting a prior view.
        """
        status = (status or "").lower().strip()
        if status not in _VALID_STATUS:
            return json.dumps({"error": f"status must be one of {sorted(_VALID_STATUS)}"})
        try:
            conf = max(0.0, min(1.0, float(confidence)))
        except (TypeError, ValueError):
            return json.dumps({"error": "confidence must be a number 0.0–1.0"})

        hyps = load_hypotheses()
        target = next((h for h in hyps if h.get("id") == hypothesis_id), None)
        if target is None:
            return json.dumps({"error": f"unknown hypothesis_id {hypothesis_id!r}; "
                                        f"known: {[h['id'] for h in hyps]}"})
        now = datetime.now(timezone.utc).isoformat()
        prev_status = target.get("status")
        target["status"] = status
        target["confidence"] = round(conf, 3)
        if evidence_audit_ids:
            target["evidence"] = sorted(set(target.get("evidence", []) + list(evidence_audit_ids)))
        target.setdefault("history", []).append(
            {"t": now, "status": status, "confidence": round(conf, 3), "note": note})
        _save(hyps)

        self_corrected = prev_status not in (None, "open") and prev_status != status
        log_tool_execution("reasoning:update_hypothesis", [hypothesis_id, status, str(conf)],
                           json.dumps({"id": hypothesis_id, "from": prev_status, "to": status,
                                       "confidence": conf, "evidence": evidence_audit_ids, "note": note}))
        return wrap_response("update_hypothesis",
                             {"id": hypothesis_id, "status": status, "confidence": round(conf, 3),
                              "self_corrected": self_corrected,
                              "summary": hypothesis_summary(hyps)},
                             get_last_audit_id())

    @mcp.tool()
    def get_investigation_state() -> str:
        """
        Return the current hypothesis ledger + summary (open/confirmed/disproved/
        inconclusive counts and self-correction count). Use it to review what is still
        open before deciding the next step or calling finish_analysis.
        """
        hyps = load_hypotheses()
        return wrap_response("get_investigation_state",
                             {"hypotheses": hyps, "summary": hypothesis_summary(hyps)},
                             get_last_audit_id())
