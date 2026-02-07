/*
    Hacking Tools and Offensive Security Tools Detection
    Detects common penetration testing and hacking tools
*/

rule HackTool_LaZagne {
    meta:
        description = "Detects LaZagne password recovery tool"
        severity = "high"
        mitre = "T1555"
        author = "SOC Investigator"
    strings:
        $s1 = "lazagne" ascii wide nocase
        $s2 = "softwares.windows" ascii wide nocase
        $s3 = "softwares.browsers" ascii wide nocase
        $s4 = "moduleNames" ascii wide
        $s5 = "constant.py" ascii wide
        $s6 = "credman" ascii wide nocase
    condition:
        3 of them
}

rule HackTool_Rubeus {
    meta:
        description = "Detects Rubeus Kerberos attack tool"
        severity = "critical"
        mitre = "T1558"
        author = "SOC Investigator"
    strings:
        $s1 = "Rubeus" ascii wide
        $s2 = "asktgt" ascii wide nocase
        $s3 = "asktgs" ascii wide nocase
        $s4 = "kerberoast" ascii wide nocase
        $s5 = "s4u" ascii wide nocase
        $s6 = "renew" ascii wide nocase
        $s7 = "ptt" ascii wide nocase
        $s8 = "dump" ascii wide nocase
        $s9 = "tgtdeleg" ascii wide nocase
    condition:
        $s1 or 3 of them
}

rule HackTool_SharpHound {
    meta:
        description = "Detects SharpHound BloodHound collector"
        severity = "high"
        mitre = "T1087"
        author = "SOC Investigator"
    strings:
        $s1 = "SharpHound" ascii wide nocase
        $s2 = "BloodHound" ascii wide nocase
        $s3 = "CollectionMethod" ascii wide
        $s4 = "LDAP://" ascii wide nocase
        $s5 = "Sharphound2" ascii wide nocase
        $s6 = "ACL" ascii wide
        $s7 = "Trusts" ascii wide
    condition:
        2 of them
}

rule HackTool_Impacket {
    meta:
        description = "Detects Impacket tools"
        severity = "high"
        mitre = "T1021,T1003"
        author = "SOC Investigator"
    strings:
        $s1 = "impacket" ascii wide nocase
        $s2 = "secretsdump" ascii wide nocase
        $s3 = "wmiexec" ascii wide nocase
        $s4 = "smbexec" ascii wide nocase
        $s5 = "psexec" ascii wide nocase
        $s6 = "atexec" ascii wide nocase
        $s7 = "dcomexec" ascii wide nocase
        $py = "python" ascii wide nocase
    condition:
        $py and 2 of ($s*)
}

rule HackTool_CrackMapExec {
    meta:
        description = "Detects CrackMapExec pentesting tool"
        severity = "high"
        mitre = "T1021"
        author = "SOC Investigator"
    strings:
        $s1 = "crackmapexec" ascii wide nocase
        $s2 = "cme" ascii wide nocase
        $s3 = "CME" ascii wide
        $s4 = "--shares" ascii wide
        $s5 = "--sessions" ascii wide
        $s6 = "--loggedon" ascii wide
        $s7 = "--pass-pol" ascii wide
    condition:
        3 of them
}

rule HackTool_PsExec {
    meta:
        description = "Detects PsExec remote execution tool"
        severity = "medium"
        mitre = "T1021.002"
        author = "SOC Investigator"
    strings:
        $s1 = "PsExec" ascii wide nocase
        $s2 = "psexesvc" ascii wide nocase
        $s3 = "Sysinternals" ascii wide
        $s4 = "PSEXESVC" ascii wide
        $s5 = "\\\\pipe\\" ascii wide nocase
        $svc = "\\ADMIN$\\" ascii wide nocase
    condition:
        2 of ($s*) and $svc
}

rule HackTool_Nmap {
    meta:
        description = "Detects Nmap network scanner"
        severity = "low"
        mitre = "T1046"
        author = "SOC Investigator"
    strings:
        $s1 = "Nmap" ascii wide nocase
        $s2 = "nmap-services" ascii wide nocase
        $s3 = "nmap-os-db" ascii wide nocase
        $s4 = "nse_main.lua" ascii wide nocase
        $s5 = "Starting Nmap" ascii wide nocase
        $s6 = "Nmap done" ascii wide nocase
    condition:
        3 of them
}

rule HackTool_Masscan {
    meta:
        description = "Detects Masscan port scanner"
        severity = "low"
        mitre = "T1046"
        author = "SOC Investigator"
    strings:
        $s1 = "masscan" ascii wide nocase
        $s2 = "mass scan" ascii wide nocase
        $s3 = "--rate" ascii wide
        $s4 = "--ports" ascii wide
        $s5 = "syn-cookie" ascii wide nocase
    condition:
        3 of them
}

rule HackTool_Hashcat {
    meta:
        description = "Detects Hashcat password cracking tool"
        severity = "medium"
        mitre = "T1110.002"
        author = "SOC Investigator"
    strings:
        $s1 = "hashcat" ascii wide nocase
        $s2 = "opencl" ascii wide nocase
        $s3 = ".hcstat" ascii wide nocase
        $s4 = ".hccapx" ascii wide nocase
        $s5 = "Candidates.#" ascii wide
        $s6 = "Hardware.Mon" ascii wide
    condition:
        3 of them
}

rule HackTool_JohnTheRipper {
    meta:
        description = "Detects John the Ripper password cracker"
        severity = "medium"
        mitre = "T1110.002"
        author = "SOC Investigator"
    strings:
        $s1 = "John the Ripper" ascii wide nocase
        $s2 = "john.pot" ascii wide nocase
        $s3 = "john.conf" ascii wide nocase
        $s4 = "john.log" ascii wide nocase
        $s5 = "single crack" ascii wide nocase
        $s6 = "wordlist mode" ascii wide nocase
    condition:
        3 of them
}

rule HackTool_Hydra {
    meta:
        description = "Detects Hydra brute force tool"
        severity = "medium"
        mitre = "T1110.001"
        author = "SOC Investigator"
    strings:
        $s1 = "hydra" ascii wide nocase
        $s2 = "xhydra" ascii wide nocase
        $s3 = "THC-HYDRA" ascii wide nocase
        $s4 = "-l login" ascii wide nocase
        $s5 = "-P password" ascii wide nocase
        $s6 = "Hydra starting" ascii wide nocase
    condition:
        3 of them
}

rule HackTool_Responder {
    meta:
        description = "Detects Responder LLMNR/NBT-NS poisoner"
        severity = "high"
        mitre = "T1557"
        author = "SOC Investigator"
    strings:
        $s1 = "Responder" ascii wide
        $s2 = "NBT-NS" ascii wide
        $s3 = "LLMNR" ascii wide
        $s4 = "WPAD" ascii wide
        $s5 = "poisoner" ascii wide nocase
        $s6 = "SpooferIP" ascii wide
    condition:
        3 of them
}

rule HackTool_Empire {
    meta:
        description = "Detects Empire/PowerShell Empire framework"
        severity = "critical"
        mitre = "T1059.001"
        author = "SOC Investigator"
    strings:
        $s1 = "Empire" ascii wide
        $s2 = "PowerShellEmpire" ascii wide nocase
        $s3 = "Invoke-Empire" ascii wide nocase
        $s4 = "Stager" ascii wide
        $s5 = "Listener" ascii wide
        $s6 = "empire.db" ascii wide nocase
    condition:
        3 of them
}

rule HackTool_PowerSploit {
    meta:
        description = "Detects PowerSploit offensive PowerShell toolkit"
        severity = "high"
        mitre = "T1059.001"
        author = "SOC Investigator"
    strings:
        $s1 = "PowerSploit" ascii wide nocase
        $s2 = "Invoke-Mimikatz" ascii wide nocase
        $s3 = "Invoke-TokenManipulation" ascii wide nocase
        $s4 = "Invoke-CredentialInjection" ascii wide nocase
        $s5 = "Invoke-DllInjection" ascii wide nocase
        $s6 = "Invoke-ReflectivePEInjection" ascii wide nocase
        $s7 = "PowerView" ascii wide nocase
        $s8 = "PowerUp" ascii wide nocase
    condition:
        2 of them
}

rule HackTool_Covenant {
    meta:
        description = "Detects Covenant C2 framework"
        severity = "critical"
        mitre = "T1071"
        author = "SOC Investigator"
    strings:
        $s1 = "Covenant" ascii wide
        $s2 = "Grunt" ascii wide
        $s3 = "GruntHTTP" ascii wide
        $s4 = "GruntSMB" ascii wide
        $s5 = "Listener" ascii wide
        $s6 = "covenant.dev" ascii wide nocase
    condition:
        3 of them
}

rule HackTool_Sliver {
    meta:
        description = "Detects Sliver C2 framework"
        severity = "critical"
        mitre = "T1071"
        author = "SOC Investigator"
    strings:
        $s1 = "sliver" ascii wide nocase
        $s2 = "implant" ascii wide nocase
        $s3 = "beacon" ascii wide nocase
        $s4 = "mtls" ascii wide nocase
        $s5 = "wireguard" ascii wide nocase
        $s6 = "sliverkey" ascii wide nocase
    condition:
        3 of them
}

rule HackTool_SharpCollection {
    meta:
        description = "Detects Sharp offensive tools collection"
        severity = "high"
        mitre = "T1059"
        author = "SOC Investigator"
    strings:
        $s1 = "Seatbelt" ascii wide nocase
        $s2 = "SharpUp" ascii wide nocase
        $s3 = "SharpDPAPI" ascii wide nocase
        $s4 = "SharpWMI" ascii wide nocase
        $s5 = "SharpView" ascii wide nocase
        $s6 = "SharpChrome" ascii wide nocase
        $s7 = "SharpRDP" ascii wide nocase
        $s8 = "SharpDump" ascii wide nocase
    condition:
        2 of them
}
