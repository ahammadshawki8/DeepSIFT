"""Real case-analysis integration tests — run ACTUAL forensic tools against the
mounted ROCBA evidence and assert known-true facts. No mocks.

Skipped automatically when the evidence isn't mounted, so the suite stays portable.
Run explicitly:  pytest tests/test_integration_rocba.py -v
"""
import json
import asyncio
from pathlib import Path
import pytest

EVID = Path("/mnt/evidence")
SYSTEM_HIVE = EVID / "Windows/System32/config/SYSTEM"
RECENT = EVID / "Users/fredr/AppData/Roaming/Microsoft/Windows/Recent"

pytestmark = pytest.mark.skipif(
    not EVID.exists() or not SYSTEM_HIVE.exists(),
    reason="ROCBA disk evidence not mounted at /mnt/evidence",
)


def _call(name, args):
    import mcp_server.server as s
    out = asyncio.run(s.mcp.call_tool(name, args))
    c = out[0] if isinstance(out, tuple) else out
    if isinstance(c, list):
        c = c[0]
    return json.loads(c.text)


def test_shimcache_real_entries():
    d = _call("parse_shimcache", {"system_hive_path": str(SYSTEM_HIVE)})
    dd = d.get("data", d)
    assert dd.get("total_shimcache_entries", 0) >= 400      # image really has ~527
    assert "audit_id" in d                                   # chain-of-custody id present


def test_lnk_reveals_usb_exfil_of_srl_files():
    if not RECENT.exists():
        pytest.skip("Recent folder not present")
    d = _call("parse_lnk_files", {"lnk_dir": str(RECENT)})
    blob = json.dumps(d).lower()
    # the real incident: SRL project files copied to an external F: drive
    assert "f:" in blob
    assert "srl" in blob or "megaforce" in blob or "blue thunder" in blob


def test_mcp_server_registers_full_toolset():
    import mcp_server.server as s
    tools = s.mcp._tool_manager.list_tools()
    assert len(tools) >= 140                                 # 148 typed tools
    names = {t.name for t in tools}
    assert {"get_process_list", "parse_event_logs", "parse_shimcache"} <= names


def test_guardrail_blocks_destructive_real():
    from mcp_server.audit import guard_command
    with pytest.raises(PermissionError):
        guard_command(["rm", "-rf", "/cases/ROCBA"])
