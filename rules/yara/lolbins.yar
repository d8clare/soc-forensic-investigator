/*
    Living Off The Land Binaries (LOLBins) Detection
    Detects abuse of legitimate Windows binaries
*/

rule LOLBin_Certutil_Download {
    meta:
        description = "Detects certutil.exe used for downloading"
        severity = "high"
        mitre = "T1105,T1140"
    strings:
        $cmd1 = "certutil" ascii wide nocase
        $dl1 = "-urlcache" ascii wide nocase
        $dl2 = "-split" ascii wide nocase
        $dl3 = "http" ascii wide nocase
    condition:
        $cmd1 and any of ($dl*)
}

rule LOLBin_Certutil_Decode {
    meta:
        description = "Detects certutil.exe used for decoding"
        severity = "high"
        mitre = "T1140"
    strings:
        $cmd1 = "certutil" ascii wide nocase
        $dec1 = "-decode" ascii wide nocase
        $dec2 = "-decodehex" ascii wide nocase
    condition:
        $cmd1 and any of ($dec*)
}

rule LOLBin_Mshta_Execution {
    meta:
        description = "Detects mshta.exe abuse"
        severity = "high"
        mitre = "T1218.005"
    strings:
        $cmd = "mshta" ascii wide nocase
        $s1 = "javascript:" ascii wide nocase
        $s2 = "vbscript:" ascii wide nocase
        $s3 = "http" ascii wide nocase
        $s4 = "about:" ascii wide nocase
    condition:
        $cmd and any of ($s*)
}

rule LOLBin_Regsvr32_Execution {
    meta:
        description = "Detects regsvr32.exe abuse (Squiblydoo)"
        severity = "high"
        mitre = "T1218.010"
    strings:
        $cmd = "regsvr32" ascii wide nocase
        $s1 = "/s" ascii wide nocase
        $s2 = "/u" ascii wide nocase
        $s3 = "/i:" ascii wide nocase
        $s4 = "scrobj.dll" ascii wide nocase
        $s5 = "http" ascii wide nocase
    condition:
        $cmd and 2 of ($s*)
}

rule LOLBin_Rundll32_Execution {
    meta:
        description = "Detects suspicious rundll32.exe usage"
        severity = "medium"
        mitre = "T1218.011"
    strings:
        $cmd = "rundll32" ascii wide nocase
        $s1 = "javascript:" ascii wide nocase
        $s2 = "shell32.dll,ShellExec_RunDLL" ascii wide nocase
        $s3 = "url.dll,FileProtocolHandler" ascii wide nocase
        $s4 = "zipfldr.dll,RouteTheCall" ascii wide nocase
        $s5 = "advpack.dll,LaunchINFSection" ascii wide nocase
        $s6 = "ieadvpack.dll,LaunchINFSection" ascii wide nocase
        $s7 = "pcwutl.dll,LaunchApplication" ascii wide nocase
        $s8 = "dfshim.dll" ascii wide nocase
    condition:
        $cmd and any of ($s*)
}

rule LOLBin_Bitsadmin_Download {
    meta:
        description = "Detects bitsadmin.exe download abuse"
        severity = "high"
        mitre = "T1197"
    strings:
        $cmd = "bitsadmin" ascii wide nocase
        $s1 = "/transfer" ascii wide nocase
        $s2 = "/addfile" ascii wide nocase
        $s3 = "/create" ascii wide nocase
        $s4 = "http" ascii wide nocase
    condition:
        $cmd and 2 of ($s*)
}

rule LOLBin_Wmic_Execution {
    meta:
        description = "Detects wmic.exe process execution"
        severity = "medium"
        mitre = "T1047"
    strings:
        $cmd = "wmic" ascii wide nocase
        $s1 = "process call create" ascii wide nocase
        $s2 = "/node:" ascii wide nocase
        $s3 = "os get" ascii wide nocase
        $s4 = "qfe get" ascii wide nocase
        $s5 = "useraccount" ascii wide nocase
    condition:
        $cmd and any of ($s*)
}

rule LOLBin_Cscript_Wscript {
    meta:
        description = "Detects cscript/wscript with suspicious args"
        severity = "medium"
        mitre = "T1059.005"
    strings:
        $cmd1 = "cscript" ascii wide nocase
        $cmd2 = "wscript" ascii wide nocase
        $s1 = "//E:jscript" ascii wide nocase
        $s2 = "//E:vbscript" ascii wide nocase
        $s3 = "//B" ascii wide nocase
        $s4 = "http" ascii wide nocase
    condition:
        any of ($cmd*) and any of ($s*)
}

rule LOLBin_Msiexec_Download {
    meta:
        description = "Detects msiexec.exe downloading MSI from URL"
        severity = "high"
        mitre = "T1218.007"
    strings:
        $cmd = "msiexec" ascii wide nocase
        $s1 = "/i" ascii wide nocase
        $s2 = "/q" ascii wide nocase
        $s3 = "http" ascii wide nocase
    condition:
        $cmd and $s3 and any of ($s1, $s2)
}

rule LOLBin_Forfiles_Execution {
    meta:
        description = "Detects forfiles.exe command execution"
        severity = "medium"
        mitre = "T1202"
    strings:
        $cmd = "forfiles" ascii wide nocase
        $s1 = "/c" ascii wide nocase
        $s2 = "cmd" ascii wide nocase
        $s3 = "powershell" ascii wide nocase
    condition:
        $cmd and $s1 and any of ($s2, $s3)
}

rule LOLBin_Pcalua_Execution {
    meta:
        description = "Detects pcalua.exe proxy execution"
        severity = "high"
        mitre = "T1202"
    strings:
        $cmd = "pcalua" ascii wide nocase
        $s1 = "-a" ascii wide nocase
    condition:
        $cmd and $s1
}

rule LOLBin_Cmstp_Bypass {
    meta:
        description = "Detects CMSTP.exe UAC bypass"
        severity = "critical"
        mitre = "T1218.003"
    strings:
        $cmd = "cmstp" ascii wide nocase
        $s1 = "/ni" ascii wide nocase
        $s2 = "/s" ascii wide nocase
        $s3 = ".inf" ascii wide nocase
    condition:
        $cmd and 2 of ($s*)
}

rule LOLBin_Installutil_Bypass {
    meta:
        description = "Detects InstallUtil.exe execution bypass"
        severity = "high"
        mitre = "T1218.004"
    strings:
        $cmd = "installutil" ascii wide nocase
        $s1 = "/logfile=" ascii wide nocase
        $s2 = "/LogToConsole=false" ascii wide nocase
        $s3 = "/U" ascii wide nocase
    condition:
        $cmd and any of ($s*)
}

rule LOLBin_Regasm_Regsvcs {
    meta:
        description = "Detects regasm/regsvcs execution"
        severity = "high"
        mitre = "T1218.009"
    strings:
        $cmd1 = "regasm" ascii wide nocase
        $cmd2 = "regsvcs" ascii wide nocase
        $s1 = "/U" ascii wide nocase
    condition:
        any of ($cmd*) and $s1
}

rule LOLBin_Odbcconf_Execution {
    meta:
        description = "Detects odbcconf.exe DLL execution"
        severity = "high"
        mitre = "T1218.008"
    strings:
        $cmd = "odbcconf" ascii wide nocase
        $s1 = "/a" ascii wide nocase
        $s2 = "regsvr" ascii wide nocase
        $s3 = ".dll" ascii wide nocase
    condition:
        $cmd and 2 of ($s*)
}

rule LOLBin_Ieexec_Download {
    meta:
        description = "Detects ieexec.exe download execution"
        severity = "high"
        mitre = "T1105"
    strings:
        $cmd = "ieexec" ascii wide nocase
        $s1 = "http" ascii wide nocase
    condition:
        $cmd and $s1
}

rule LOLBin_Msconfig_Execution {
    meta:
        description = "Detects msconfig.exe command execution"
        severity = "medium"
        mitre = "T1218"
    strings:
        $cmd = "msconfig" ascii wide nocase
        $s1 = "-5" ascii wide nocase
    condition:
        $cmd and $s1
}

rule LOLBin_Infdefaultinstall {
    meta:
        description = "Detects InfDefaultInstall.exe abuse"
        severity = "high"
        mitre = "T1218"
    strings:
        $cmd = "infdefaultinstall" ascii wide nocase
        $s1 = ".inf" ascii wide nocase
    condition:
        $cmd and $s1
}

rule LOLBin_SyncAppvPublishingServer {
    meta:
        description = "Detects SyncAppvPublishingServer PowerShell execution"
        severity = "high"
        mitre = "T1218"
    strings:
        $cmd = "SyncAppvPublishingServer" ascii wide nocase
        $s1 = "powershell" ascii wide nocase
        $s2 = "Start-Process" ascii wide nocase
    condition:
        $cmd and any of ($s*)
}
