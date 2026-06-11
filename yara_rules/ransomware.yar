/*
  DeepSIFT — ransomware.yar
  Ransomware family detection: ransom notes, shadow deletion, known families.
  MITRE: T1486, T1490
*/

rule Ransomware_Note_Generic {
    meta:
        description = "Generic ransomware note strings"
        reference = "T1486"
    strings:
        $a1 = "YOUR FILES ARE ENCRYPTED" nocase
        $a2 = "YOUR PERSONAL FILES HAVE BEEN ENCRYPTED" nocase
        $a3 = "HOW TO DECRYPT" nocase
        $a4 = "HOW TO RESTORE YOUR FILES" nocase
        $a5 = "DECRYPT INSTRUCTIONS" nocase
        $a6 = "RECOVER YOUR FILES" nocase
        $a7 = "TO DECRYPT YOUR FILES" nocase
    condition:
        any of them
}

rule Ransomware_Payment_Demand {
    meta:
        description = "Ransomware payment demand — Bitcoin + Tor"
        reference = "T1486"
    strings:
        $a1 = "bitcoin" nocase
        $a2 = "tor browser" nocase
        $a3 = ".onion" nocase
        $a4 = "BTC" nocase
        $a5 = "Monero" nocase
        $a6 = "XMR" nocase
    condition:
        2 of them
}

rule Ransomware_Shadow_Deletion {
    meta:
        description = "Shadow copy deletion — pre-encryption step"
        reference = "T1490"
    strings:
        $a1 = "vssadmin delete shadows /all /quiet" nocase
        $a2 = "wmic shadowcopy delete" nocase
        $a3 = "bcdedit /set {default} recoveryenabled No" nocase
        $a4 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase
        $a5 = "wbadmin delete catalog -quiet" nocase
    condition:
        any of them
}

rule Ransomware_Ryuk {
    meta:
        description = "Ryuk ransomware indicators"
        reference = "T1486"
        family = "Ryuk"
    strings:
        $a1 = "RyukReadMe" nocase
        $a2 = "RYUK" nocase
        $a3 = "No system is safe" nocase
        $a4 = "Balance of Shadow Universe" nocase
    condition:
        any of them
}

rule Ransomware_WannaCry {
    meta:
        description = "WannaCry ransomware indicators"
        reference = "T1486"
        family = "WannaCry"
    strings:
        $a1 = "WANACRY!" nocase
        $a2 = "WannaCrypt" nocase
        $a3 = "wanna decryptor" nocase
        $a4 = "taskdl.exe" nocase
        $a5 = "@WanaDecryptor@" nocase
    condition:
        any of them
}

rule Ransomware_Conti {
    meta:
        description = "Conti ransomware indicators"
        reference = "T1486"
        family = "Conti"
    strings:
        $a1 = "CONTI NEWS" nocase
        $a2 = "contirecovery" nocase
        $a3 = "RECOVER-FILES.txt" nocase
    condition:
        any of them
}
