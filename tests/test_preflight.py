"""Preflight/self-check: structured environment report + honest operational count."""
from mcp_server.preflight import check_dependencies, format_report


def test_report_structure_and_counts():
    rep = check_dependencies()
    total = rep["dependency_groups_total"]
    assert total >= 8
    assert rep["dependency_groups_available"] + rep["dependency_groups_unavailable"] == total
    assert rep["verdict"] in ("ALL_OPERATIONAL", "PARTIAL")
    # every group record carries an actionable install hint + representative tools
    for d in rep["available"] + rep["unavailable"]:
        assert d["label"] and d["install_hint"] and d["representative_tools"]
    # pure-Python families are always reported operational
    assert rep["python_only_always_available"]


def test_format_report_renders():
    rep = check_dependencies()
    text = format_report(rep)
    assert "preflight" in text.lower()
    assert "Operational dependency groups" in text
