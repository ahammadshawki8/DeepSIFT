/*
  DeepSIFT — rats.yar
  Remote Access Trojan (RAT) detection: Cobalt Strike, njRAT, AsyncRAT, etc.
  MITRE: T1219, T1071, T1055
*/

rule CobaltStrike_Beacon {
    meta:
        description = "Cobalt Strike Beacon indicators"
        reference = "T1219"
        family = "CobaltStrike"
    strings:
        $a1 = "Cobalt Strike" nocase
        $a2 = "cobaltstrike" nocase
        $a3 = "beacon.dll" nocase
        $a4 = "ReflectiveDll" nocase
        $a5 = "METERPRETER" nocase
        $a6 = "beacon_id" nocase
        $a7 = "sleeptime" nocase
    condition:
        any of them
}

rule CobaltStrike_TeamServer {
    meta:
        description = "Cobalt Strike team server artifact strings"
        reference = "T1219"
    strings:
        $a1 = "Malleable C2" nocase
        $a2 = "teamserver" nocase
        $a3 = "c2lint" nocase
    condition:
        any of them
}

rule Metasploit_Meterpreter {
    meta:
        description = "Metasploit Meterpreter payload strings"
        reference = "T1219"
    strings:
        $a1 = "meterpreter" nocase
        $a2 = "reverse_tcp" nocase
        $a3 = "reverse_http" nocase
        $a4 = "bind_tcp" nocase
        $a5 = "PAYLOAD_UUID" nocase
        $a6 = "ReflectiveLoader" nocase
    condition:
        any of them
}

rule njRAT_Indicators {
    meta:
        description = "njRAT / Bladabindi RAT indicator strings"
        reference = "T1219"
        family = "njRAT"
    strings:
        $a1 = "njRAT" nocase
        $a2 = "HvncPlugin" nocase
        $a3 = "lol|" nocase
        $a4 = "njq8" nocase
    condition:
        any of them
}

rule AsyncRAT_Indicators {
    meta:
        description = "AsyncRAT indicator strings"
        reference = "T1219"
        family = "AsyncRAT"
    strings:
        $a1 = "AsyncClient" nocase
        $a2 = "AsyncRAT" nocase
        $a3 = "Install_Folder" nocase
        $a4 = "Pastebin" nocase
        $a5 = "Listeners" nocase
    condition:
        2 of them
}

rule RemcosRAT_Indicators {
    meta:
        description = "Remcos RAT indicator strings"
        reference = "T1219"
        family = "Remcos"
    strings:
        $a1 = "REMCOS" nocase
        $a2 = "Remcos-Pro" nocase
        $a3 = "Breaking-Security" nocase
    condition:
        any of them
}

rule QuasarRAT_Indicators {
    meta:
        description = "Quasar RAT indicator strings"
        reference = "T1219"
        family = "Quasar"
    strings:
        $a1 = "QuasarRAT" nocase
        $a2 = "Quasar.Client" nocase
        $a3 = "qRat" nocase
    condition:
        any of them
}

rule Generic_C2_Strings {
    meta:
        description = "Generic C2 framework communication strings"
        reference = "T1071"
    strings:
        $a1 = "User-Agent: Mozilla/5.0" nocase
        $a2 = "cmd.exe /c whoami" nocase
        $a3 = "ipconfig /all" nocase
        $a4 = "net view /domain" nocase
    condition:
        2 of them
}
