/*
  DeepSIFT — packers.yar
  PE packer and protector detection: UPX, MPRESS, Themida, etc.
  MITRE: T1027.002
*/

rule UPX_Packed {
    meta:
        description = "UPX packer sections present"
        reference = "T1027.002"
        packer = "UPX"
    strings:
        $s1 = "UPX0"
        $s2 = "UPX1"
        $s3 = "UPX!"
        $s4 = "This file is packed with the UPX executable packer" nocase
    condition:
        2 of them
}

rule MPRESS_Packed {
    meta:
        description = "MPRESS packer section signatures"
        reference = "T1027.002"
        packer = "MPRESS"
    strings:
        $a = ".MPRESS1"
        $b = ".MPRESS2"
    condition:
        any of them
}

rule PECompact_Packed {
    meta:
        description = "PECompact packer signature"
        reference = "T1027.002"
        packer = "PECompact"
    strings:
        $a = "PEC2"
        $b = "PECompact2"
    condition:
        any of them
}

rule Themida_WinLicense {
    meta:
        description = "Themida or WinLicense protector strings"
        reference = "T1027.002"
        packer = "Themida"
    strings:
        $a = "themida" nocase
        $b = "winlicense" nocase
        $c = "oreans" nocase
    condition:
        any of them
}

rule NSPack_Packed {
    meta:
        description = "NSPack packer signature"
        reference = "T1027.002"
        packer = "NSPack"
    strings:
        $a = ".nsp0"
        $b = ".nsp1"
        $c = "NSPack"
    condition:
        any of them
}

rule EncodedPowerShell_Dropper {
    meta:
        description = "Binary containing base64-encoded PowerShell (possible dropper)"
        reference = "T1059.001"
    strings:
        $ps = "powershell" nocase
        $b64_dollarsign = "JAB"  // base64("$")
        $b64_mz = "TVqQ"         // base64("MZ") — embedded PE
        $b64_pe = "TVpQ"         // alternate base64 MZ
    condition:
        $ps and (any of ($b64*))
}

rule VirtualProtect_Injection_Prep {
    meta:
        description = "VirtualProtect + WriteProcessMemory — packer/loader pattern"
        reference = "T1055"
    strings:
        $a1 = "VirtualProtect" nocase
        $a2 = "WriteProcessMemory" nocase
        $a3 = "VirtualAlloc" nocase
        $a4 = "CreateRemoteThread" nocase
    condition:
        3 of them
}
