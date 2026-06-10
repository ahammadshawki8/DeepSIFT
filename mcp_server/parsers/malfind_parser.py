"""Parse Volatility 3 windows.malfind output into structured injection findings."""
from __future__ import annotations
import re

# PE magic bytes that indicate a loaded executable in memory
_PE_MAGIC = re.compile(r"\b4d\s*5a\b", re.IGNORECASE)  # MZ header in hex dump

# Memory protection flags that allow execution (high suspicion when private + exec)
EXECUTABLE_PROTECTIONS = {
    "PAGE_EXECUTE",
    "PAGE_EXECUTE_READ",
    "PAGE_EXECUTE_READWRITE",
    "PAGE_EXECUTE_WRITECOPY",
}

HIGH_RISK_PROTECTIONS = {
    "PAGE_EXECUTE_READWRITE",   # RWX — classic shellcode/injected PE
    "PAGE_EXECUTE_WRITECOPY",
}


def parse_malfind(raw_output: str) -> list[dict]:
    """
    Parse `vol -f image windows.malfind` output.

    Volatility 3 malfind columns:
        PID  Process  Start VPN  End VPN  Tag  Protection  CommitCharge  PrivateMemory  File output
    Followed by hexdump and disassembly blocks.
    """
    findings: list[dict] = []
    header_found = False
    current: dict | None = None
    hex_lines: list[str] = []
    disasm_lines: list[str] = []
    in_hex = False
    in_disasm = False

    for line in raw_output.splitlines():
        stripped = line.strip()

        if not stripped or stripped.startswith("Volatility") or stripped.startswith("Progress"):
            continue

        if "PID" in stripped and "Process" in stripped and "Protection" in stripped:
            header_found = True
            continue

        if not header_found:
            continue

        # Detect hex dump section (starts with 0x address)
        if re.match(r"^0x[0-9a-fA-F]+\s+[0-9a-fA-F\s]+", stripped):
            if current is not None:
                in_hex = True
                in_disasm = False
                hex_lines.append(stripped)
            continue

        # Detect disassembly section (starts with address followed by instruction)
        if re.match(r"^0x[0-9a-fA-F]+\s+\S+\s+\S+", stripped) and not in_hex:
            if current is not None:
                in_disasm = True
                disasm_lines.append(stripped)
            continue

        # New finding row — save previous if any
        parts = stripped.split()
        if len(parts) >= 6 and parts[0].isdigit():
            if current is not None:
                current["hexdump"] = "\n".join(hex_lines)
                current["disassembly"] = "\n".join(disasm_lines)
                _classify_finding(current)
                findings.append(current)

            hex_lines = []
            disasm_lines = []
            in_hex = False
            in_disasm = False

            try:
                current = {
                    "pid": int(parts[0]),
                    "process": parts[1],
                    "start_vpn": parts[2],
                    "end_vpn": parts[3],
                    "tag": parts[4],
                    "protection": parts[5],
                    "commit_charge": parts[6] if len(parts) > 6 else "unknown",
                    "private_memory": parts[7] if len(parts) > 7 else "unknown",
                    "file_output": parts[8] if len(parts) > 8 else "Disabled",
                    "hexdump": "",
                    "disassembly": "",
                    "injection_type": "unknown",
                    "has_pe_header": False,
                    "risk_level": "medium",
                    "ioc_flags": [],
                }
            except (ValueError, IndexError):
                current = None
        elif in_hex and stripped:
            hex_lines.append(stripped)
        elif in_disasm and stripped:
            disasm_lines.append(stripped)

    # Don't forget the last finding
    if current is not None:
        current["hexdump"] = "\n".join(hex_lines)
        current["disassembly"] = "\n".join(disasm_lines)
        _classify_finding(current)
        findings.append(current)

    return findings


def _classify_finding(finding: dict) -> None:
    """Classify the injection type and risk level based on protection flags and content."""
    flags: list[str] = []
    protection = finding.get("protection", "")
    hexdump = finding.get("hexdump", "")

    # Check for PE header (MZ) in hexdump
    # Strip leading address (0x...) from hex dump lines, then extract byte pairs
    hex_stripped = re.sub(r"0x[0-9a-fA-F]+\s+", " ", hexdump)
    # Find all hex byte pairs and re-join
    hex_bytes = " ".join(re.findall(r"\b[0-9a-fA-F]{2}\b", hex_stripped[:1000]))
    has_pe = bool(re.search(r"4d\s*5a", hex_bytes, re.IGNORECASE))
    finding["has_pe_header"] = bool(has_pe)

    if has_pe:
        if protection in HIGH_RISK_PROTECTIONS:
            finding["injection_type"] = "reflective_dll_injection"
            flags.append("PE header (MZ) found in RWX memory region — likely reflective DLL injection")
        else:
            finding["injection_type"] = "process_hollowing_candidate"
            flags.append("PE header found in executable memory — possible process hollowing or DLL injection")
    elif protection in HIGH_RISK_PROTECTIONS:
        finding["injection_type"] = "shellcode"
        flags.append("RWX memory with no PE header — likely shellcode")
    elif protection in EXECUTABLE_PROTECTIONS:
        finding["injection_type"] = "suspicious_exec_region"
        flags.append(f"Executable private memory region with protection: {protection}")

    if finding.get("private_memory") in ("1", "True", True):
        flags.append("PrivateMemory=True — not backed by a file on disk")

    # Risk classification
    if finding["injection_type"] in ("reflective_dll_injection", "shellcode"):
        finding["risk_level"] = "high"
    elif finding["injection_type"] in ("process_hollowing_candidate",):
        finding["risk_level"] = "high"
    else:
        finding["risk_level"] = "medium"

    finding["ioc_flags"] = flags
