"""Autonomy capture: hypothesis ledger records decisions + self-corrections, and is
folded into the examiner view. This is how the Claude-Code-as-agent path proves
autonomous, self-correcting reasoning without an API key."""
import importlib
import json


def _fresh(monkeypatch, tmp_path):
    monkeypatch.setenv("ANALYSIS_DIR", str(tmp_path))
    monkeypatch.setenv("EXPORTS_DIR", str(tmp_path / "exports"))
    import mcp_server.config as cfg
    import mcp_server.audit as audit
    import mcp_server.tools.investigation_state as st
    importlib.reload(cfg)
    importlib.reload(audit)
    importlib.reload(st)
    return st


def test_hypothesis_ledger_records_self_correction(tmp_path, monkeypatch):
    st = _fresh(monkeypatch, tmp_path)

    h1 = st.load_hypotheses()
    assert h1 == []

    # Simulate the agent's recorded reasoning directly via the persistence layer.
    st._save([
        {"id": "H1", "statement": "USB exfil", "status": "confirmed", "confidence": 0.95,
         "evidence": ["a1"], "history": [{"status": "open"}, {"status": "confirmed"}]},
        {"id": "H2", "statement": "email exfil", "status": "disproved", "confidence": 0.9,
         "evidence": ["a2"],
         "history": [{"status": "open"}, {"status": "inconclusive"}, {"status": "disproved"}]},
    ])
    s = st.hypothesis_summary(st.load_hypotheses())
    assert s["total"] == 2
    assert s["confirmed"] == 1 and s["disproved"] == 1
    # H1 open->confirmed is a normal progression (not a correction); H2 reversed a decision
    assert s["self_corrections"] == 1


def test_record_and_update_via_tools(tmp_path, monkeypatch):
    _fresh(monkeypatch, tmp_path)
    from agents.reasoning_agent import build_mcp_tool_runner
    _schemas, run = build_mcp_tool_runner(core_only=False)

    rid = json.loads(run("record_hypothesis", {"statement": "data staged then copied to USB"}))
    assert rid["id"] == "H1" and rid["status"] == "open"

    upd = json.loads(run("update_hypothesis", {
        "hypothesis_id": "H1", "status": "confirmed", "confidence": 0.9,
        "evidence_audit_ids": ["dsift-x"]}))
    assert upd["status"] == "confirmed" and upd["self_corrected"] is False

    state = json.loads(run("get_investigation_state", {}))
    assert state["summary"]["confirmed"] == 1
    # unknown id is rejected, not silently accepted
    bad = json.loads(run("update_hypothesis", {"hypothesis_id": "H9", "status": "confirmed",
                                               "confidence": 0.5}))
    assert "error" in bad


def test_record_hypothesis_is_idempotent(tmp_path, monkeypatch):
    """Re-recording the same statement must NOT append a duplicate (which would make a
    genuine single-arc ledger look like a scripted one). Regression guard."""
    _fresh(monkeypatch, tmp_path)
    from agents.reasoning_agent import build_mcp_tool_runner
    _schemas, run = build_mcp_tool_runner(core_only=False)

    a = json.loads(run("record_hypothesis", {"statement": "Data copied to removable USB"}))
    b = json.loads(run("record_hypothesis", {"statement": "  data copied to REMOVABLE usb "}))  # same, noisy
    assert a["id"] == "H1" and b["id"] == "H1"          # same id returned, no H2 created
    state = json.loads(run("get_investigation_state", {}))
    assert state["summary"]["total"] == 1
    # a genuinely different hypothesis still gets a new id
    c = json.loads(run("record_hypothesis", {"statement": "Anti-forensic tooling was used"}))
    assert c["id"] == "H2"
