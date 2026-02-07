/*
    Ransomware Detection Rules
    Detects ransomware families and behaviors
*/

rule Ransomware_LockBit {
    meta:
        description = "Detects LockBit ransomware"
        severity = "critical"
        mitre = "T1486"
        author = "SOC Investigator"
        malware = "LockBit"
    strings:
        $s1 = "LockBit" ascii wide nocase
        $s2 = "lockbit" ascii wide nocase
        $s3 = ".lockbit" ascii wide nocase
        $s4 = "Restore-My-Files.txt" ascii wide nocase
        $s5 = "LockBit_Ransomware" ascii wide nocase
        $note = "All your important files" ascii wide nocase
    condition:
        2 of them
}

rule Ransomware_Conti {
    meta:
        description = "Detects Conti ransomware"
        severity = "critical"
        mitre = "T1486"
        author = "SOC Investigator"
        malware = "Conti"
    strings:
        $s1 = "CONTI" ascii wide
        $s2 = ".CONTI" ascii wide
        $s3 = "conti_v" ascii wide nocase
        $s4 = "R3ADM3.txt" ascii wide nocase
        $s5 = "CONTI_README" ascii wide nocase
        $mutex = "hsfjuukjzloqu28oajh727190" ascii wide
    condition:
        2 of them
}

rule Ransomware_REvil {
    meta:
        description = "Detects REvil/Sodinokibi ransomware"
        severity = "critical"
        mitre = "T1486"
        author = "SOC Investigator"
        malware = "REvil"
    strings:
        $s1 = "REvil" ascii wide nocase
        $s2 = "Sodinokibi" ascii wide nocase
        $s3 = "sodin" ascii wide nocase
        $s4 = "-readme.txt" ascii wide nocase
        $s5 = "DECRYPT_" ascii wide
        $cfg = { 7B 22 70 6B 22 3A }
    condition:
        2 of ($s*) or $cfg
}

rule Ransomware_BlackCat {
    meta:
        description = "Detects BlackCat/ALPHV ransomware"
        severity = "critical"
        mitre = "T1486"
        author = "SOC Investigator"
        malware = "BlackCat"
    strings:
        $s1 = "BlackCat" ascii wide nocase
        $s2 = "ALPHV" ascii wide nocase
        $s3 = "RECOVER-" ascii wide nocase
        $s4 = "access_token" ascii wide
        $rust1 = "rustc" ascii wide
        $rust2 = ".rlib" ascii wide
    condition:
        2 of ($s*) or (any of ($rust*) and any of ($s*))
}

rule Ransomware_Ryuk {
    meta:
        description = "Detects Ryuk ransomware"
        severity = "critical"
        mitre = "T1486"
        author = "SOC Investigator"
        malware = "Ryuk"
    strings:
        $s1 = "RYUK" ascii wide
        $s2 = ".RYK" ascii wide
        $s3 = "RyukReadMe" ascii wide nocase
        $s4 = "UNIQUE_ID_DO_NOT_REMOVE" ascii wide
        $s5 = "hermes" ascii wide nocase
        $note = "balance of shadow" ascii wide nocase
    condition:
        2 of them
}

rule Ransomware_Maze {
    meta:
        description = "Detects Maze ransomware"
        severity = "critical"
        mitre = "T1486"
        author = "SOC Investigator"
        malware = "Maze"
    strings:
        $s1 = "MAZE" ascii wide
        $s2 = "ChaCha" ascii wide
        $s3 = "DECRYPT-FILES" ascii wide nocase
        $s4 = "maze.co" ascii wide nocase
        $cfg = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 }
    condition:
        2 of ($s*) or $cfg
}

rule Ransomware_DarkSide {
    meta:
        description = "Detects DarkSide ransomware"
        severity = "critical"
        mitre = "T1486"
        author = "SOC Investigator"
        malware = "DarkSide"
    strings:
        $s1 = "DarkSide" ascii wide nocase
        $s2 = "darkside" ascii wide nocase
        $s3 = "README.txt" ascii wide
        $s4 = ".darkside" ascii wide
        $cfg = "config.ini" ascii wide
    condition:
        2 of them
}

rule Ransomware_Hive {
    meta:
        description = "Detects Hive ransomware"
        severity = "critical"
        mitre = "T1486"
        author = "SOC Investigator"
        malware = "Hive"
    strings:
        $s1 = "hive" ascii wide nocase
        $s2 = ".hive" ascii wide
        $s3 = "HOW_TO_DECRYPT" ascii wide nocase
        $s4 = "hive.onion" ascii wide nocase
        $go = "go.buildid" ascii wide
    condition:
        2 of ($s*) or ($go and any of ($s*))
}

rule Ransomware_WannaCry {
    meta:
        description = "Detects WannaCry/WCry ransomware"
        severity = "critical"
        mitre = "T1486"
        author = "SOC Investigator"
        malware = "WannaCry"
    strings:
        $s1 = "WannaCry" ascii wide nocase
        $s2 = "WanaCrypt0r" ascii wide nocase
        $s3 = "WANACRY" ascii wide
        $s4 = "wcry" ascii wide nocase
        $s5 = "@WanaDecryptor@" ascii wide
        $s6 = ".WNCRY" ascii wide
        $killsw = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea" ascii wide
    condition:
        2 of them
}

rule Ransomware_Phobos {
    meta:
        description = "Detects Phobos ransomware"
        severity = "critical"
        mitre = "T1486"
        author = "SOC Investigator"
        malware = "Phobos"
    strings:
        $s1 = "Phobos" ascii wide nocase
        $s2 = ".phobos" ascii wide
        $s3 = "info.txt" ascii wide
        $s4 = "info.hta" ascii wide
        $s5 = ".eking" ascii wide
        $s6 = ".eight" ascii wide
        $s7 = ".help" ascii wide
    condition:
        3 of them
}

rule Ransomware_Generic_Behavior {
    meta:
        description = "Detects generic ransomware behavior patterns"
        severity = "high"
        mitre = "T1486"
        author = "SOC Investigator"
    strings:
        $crypto1 = "CryptEncrypt" ascii wide
        $crypto2 = "CryptGenKey" ascii wide
        $crypto3 = "CryptImportKey" ascii wide
        $crypto4 = "BCryptEncrypt" ascii wide
        $del1 = "vssadmin delete shadows" ascii wide nocase
        $del2 = "wmic shadowcopy delete" ascii wide nocase
        $del3 = "bcdedit /set" ascii wide nocase
        $del4 = "wbadmin delete" ascii wide nocase
        $enum1 = "FindFirstFile" ascii wide
        $enum2 = "FindNextFile" ascii wide
        $ext = ".encrypted" ascii wide nocase
    condition:
        (2 of ($crypto*) and any of ($del*)) or (any of ($del*) and any of ($enum*) and $ext)
}

rule Ransomware_Encryption_Extensions {
    meta:
        description = "Detects files with ransomware encryption extensions"
        severity = "medium"
        mitre = "T1486"
        author = "SOC Investigator"
    strings:
        $ext1 = ".locked" ascii wide nocase
        $ext2 = ".encrypted" ascii wide nocase
        $ext3 = ".crypto" ascii wide nocase
        $ext4 = ".crypt" ascii wide nocase
        $ext5 = ".enc" ascii wide nocase
        $ext6 = ".crypted" ascii wide nocase
        $ext7 = ".pay2key" ascii wide nocase
        $ext8 = ".ransom" ascii wide nocase
        $ext9 = ".lockfile" ascii wide nocase
        $ext10 = ".cerber" ascii wide nocase
        $instructions = "readme" ascii wide nocase
        $decrypt = "decrypt" ascii wide nocase
    condition:
        3 of ($ext*) and ($instructions or $decrypt)
}

rule Ransomware_Note_Generic {
    meta:
        description = "Detects generic ransomware note content"
        severity = "critical"
        mitre = "T1486"
        author = "SOC Investigator"
    strings:
        $btc1 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii wide
        $btc2 = /bc1[a-zA-HJ-NP-Z0-9]{25,89}/ ascii wide
        $xmr = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii wide
        $msg1 = "files have been encrypted" ascii wide nocase
        $msg2 = "pay the ransom" ascii wide nocase
        $msg3 = "bitcoin" ascii wide nocase
        $msg4 = "decrypt" ascii wide nocase
        $msg5 = "private key" ascii wide nocase
        $tor = ".onion" ascii wide nocase
    condition:
        (any of ($btc*, $xmr) and 2 of ($msg*)) or ($tor and 2 of ($msg*))
}
