/*
  DeepSIFT — suspicious_strings.yar
  Generic suspicious strings for initial memory/disk triage.
  MITRE: T1059.001, T1003, T1071, T1070
*/

rule CmdEncodedPowerShell {
    meta:
        description = "PowerShell encoded command execution"
        reference = "T1059.001"
    strings:
        $ps = "powershell" nocase
        $b1 = " -enc " nocase
        $b2 = " -EncodedCommand " nocase
        $b3 = " -e " nocase
        $b4 = " -nop " nocase
        $b5 = " -noprofile " nocase
    condition:
        $ps and (any of ($b*))
}

rule CredentialDumpingStrings {
    meta:
        description = "Credential dumping tool strings (Mimikatz, WCE, fgdump)"
        reference = "T1003"
    strings:
        $a1 = "sekurlsa" nocase
        $a2 = "lsadump" nocase
        $a3 = "mimikatz" nocase
        $a4 = "wce.exe" nocase
        $a5 = "fgdump" nocase
        $a6 = "procdump" nocase
        $a7 = "privilege::debug" nocase
    condition:
        any of them
}

rule LolBinAbuse {
    meta:
        description = "Living-off-the-land binary abuse patterns"
        reference = "T1218"
    strings:
        $a1 = "certutil -decode" nocase
        $a2 = "certutil -urlcache" nocase
        $a3 = "bitsadmin /transfer" nocase
        $a4 = "regsvr32 /s /n /u /i:" nocase
        $a5 = "wmic process call create" nocase
        $a6 = "rundll32 javascript:" nocase
        $a7 = "mshta vbscript:" nocase
    condition:
        any of them
}

rule PersistenceStrings {
    meta:
        description = "Common persistence command strings"
        reference = "T1547.001"
    strings:
        $a1 = "net user /add" nocase
        $a2 = "net localgroup administrators" nocase
        $a3 = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $a4 = "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $a5 = "schtasks /create" nocase
        $a6 = "sc create" nocase
        $a7 = "New-ScheduledTask" nocase
    condition:
        any of them
}

rule AntiForensicStrings {
    meta:
        description = "Anti-forensic and log-clearing commands"
        reference = "T1070"
    strings:
        $a1 = "wevtutil cl" nocase
        $a2 = "Clear-EventLog" nocase
        $a3 = "vssadmin delete shadows" nocase
        $a4 = "bcdedit /set" nocase
        $a5 = "fsutil usn deletejournal" nocase
        $a6 = "Remove-Item -Recurse" nocase
    condition:
        any of them
}

rule RDPLateralMovement {
    meta:
        description = "RDP lateral movement strings"
        reference = "T1021.001"
    strings:
        $a1 = "mstsc /v:" nocase
        $a2 = "cmdkey /add" nocase
        $a3 = "xfreerdp" nocase
        $a4 = "/port:3389" nocase
    condition:
        any of them
}
