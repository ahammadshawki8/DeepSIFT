"""Architectural command guardrail tests."""
import pytest
from mcp_server.audit import guard_command, guard_output_path


def test_blocks_destructive_binaries():
    for bad in (["rm", "-rf", "/cases"], ["dd", "if=/dev/zero"], ["wget", "http://x"],
                ["curl", "http://x"], ["ssh", "h"], ["nc", "-l"], ["shred", "x"], ["mkfs", "x"]):
        with pytest.raises(PermissionError):
            guard_command(bad)


def test_blocks_shell_string_and_redirection():
    with pytest.raises(PermissionError):
        guard_command("rm -rf /")            # shell string form
    with pytest.raises(PermissionError):
        guard_command(["vol", "-f", "x", ">", "/cases/out"])   # redirection token


def test_allows_legit_forensic_commands():
    guard_command(["/opt/volatility3/bin/vol", "-f", "/cases/x.raw", "windows.pslist"])
    guard_command(["dotnet", "/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll", "-d", "/mnt/x"])
    guard_command(["fls", "-r", "-o", "2048", "/cases/disk.E01"])


def test_evidence_write_guard():
    with pytest.raises(PermissionError):
        guard_output_path("/cases/ROCBA/out.csv")
    # exports under cwd are fine
    guard_output_path("./exports/x.csv")
