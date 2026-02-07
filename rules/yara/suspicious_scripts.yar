/*
    Suspicious Scripts and Documents Detection
    Detects malicious scripts, documents, and file anomalies
*/

rule Suspicious_VBS_Script {
    meta:
        description = "Detects suspicious VBScript patterns"
        severity = "high"
        mitre = "T1059.005"
        author = "SOC Investigator"
    strings:
        $vbs1 = "WScript.Shell" ascii wide nocase
        $vbs2 = "Scripting.FileSystemObject" ascii wide nocase
        $vbs3 = "ADODB.Stream" ascii wide nocase
        $vbs4 = "Msxml2.XMLHTTP" ascii wide nocase
        $vbs5 = "Shell.Application" ascii wide nocase
        $exec1 = ".Run" ascii wide nocase
        $exec2 = ".Exec" ascii wide nocase
        $exec3 = "ShellExecute" ascii wide nocase
        $obf1 = "Chr(" ascii wide nocase
        $obf2 = "ChrW(" ascii wide nocase
        $obf3 = "&" ascii wide
    condition:
        2 of ($vbs*) and any of ($exec*) or (4 of ($obf*) and any of ($vbs*))
}

rule Suspicious_JS_Script {
    meta:
        description = "Detects suspicious JavaScript patterns"
        severity = "high"
        mitre = "T1059.007"
        author = "SOC Investigator"
    strings:
        $js1 = "WScript.Shell" ascii wide nocase
        $js2 = "ActiveXObject" ascii wide nocase
        $js3 = "Scripting.FileSystemObject" ascii wide nocase
        $js4 = "ADODB.Stream" ascii wide nocase
        $js5 = "eval(" ascii wide nocase
        $js6 = "new Function(" ascii wide nocase
        $http1 = "XMLHTTP" ascii wide nocase
        $http2 = "ServerXMLHTTP" ascii wide nocase
        $obf1 = "fromCharCode" ascii wide nocase
        $obf2 = "charCodeAt" ascii wide nocase
        $obf3 = "unescape" ascii wide nocase
        $obf4 = "\\x" ascii wide
        $obf5 = "\\u00" ascii wide
    condition:
        2 of ($js*) or (any of ($js*) and any of ($http*)) or (3 of ($obf*) and any of ($js*))
}

rule Suspicious_HTA_Application {
    meta:
        description = "Detects suspicious HTA application"
        severity = "high"
        mitre = "T1218.005"
        author = "SOC Investigator"
    strings:
        $hta1 = "<HTA:APPLICATION" ascii wide nocase
        $vbs1 = "<script" ascii wide nocase
        $vbs2 = "VBScript" ascii wide nocase
        $vbs3 = "JScript" ascii wide nocase
        $shell1 = "WScript.Shell" ascii wide nocase
        $shell2 = "Shell.Application" ascii wide nocase
        $cmd = "cmd.exe" ascii wide nocase
        $ps = "powershell" ascii wide nocase
    condition:
        $hta1 and any of ($vbs*) and (any of ($shell*) or $cmd or $ps)
}

rule Suspicious_BAT_Script {
    meta:
        description = "Detects suspicious batch script patterns"
        severity = "medium"
        mitre = "T1059.003"
        author = "SOC Investigator"
    strings:
        $bat1 = "@echo off" ascii wide nocase
        $bat2 = "setlocal" ascii wide nocase
        $susp1 = "powershell" ascii wide nocase
        $susp2 = "certutil" ascii wide nocase
        $susp3 = "bitsadmin" ascii wide nocase
        $susp4 = "mshta" ascii wide nocase
        $susp5 = "regsvr32" ascii wide nocase
        $susp6 = "rundll32" ascii wide nocase
        $susp7 = "wscript" ascii wide nocase
        $susp8 = "cscript" ascii wide nocase
        $del1 = "del /f" ascii wide nocase
        $del2 = "rd /s /q" ascii wide nocase
        $net1 = "net user" ascii wide nocase
        $net2 = "net localgroup" ascii wide nocase
    condition:
        ($bat1 or $bat2) and (2 of ($susp*) or (any of ($del*) and any of ($susp*)) or any of ($net*))
}

rule Suspicious_LNK_File {
    meta:
        description = "Detects suspicious LNK shortcut"
        severity = "high"
        mitre = "T1547.009"
        author = "SOC Investigator"
    strings:
        $lnk_magic = { 4C 00 00 00 01 14 02 00 }
        $cmd1 = "cmd.exe" ascii wide nocase
        $cmd2 = "powershell" ascii wide nocase
        $cmd3 = "mshta" ascii wide nocase
        $cmd4 = "wscript" ascii wide nocase
        $cmd5 = "cscript" ascii wide nocase
        $cmd6 = "rundll32" ascii wide nocase
        $cmd7 = "regsvr32" ascii wide nocase
        $http = "http" ascii wide nocase
        $hidden = "WindowStyle" ascii wide nocase
    condition:
        $lnk_magic at 0 and (any of ($cmd*) and ($http or $hidden))
}

rule Malicious_Office_Macro {
    meta:
        description = "Detects malicious Office document with macros"
        severity = "high"
        mitre = "T1566.001"
        author = "SOC Investigator"
    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $zip = { 50 4B 03 04 }
        $vba1 = "vbaProject" ascii wide nocase
        $vba2 = "_VBA_PROJECT" ascii wide nocase
        $auto1 = "AutoOpen" ascii wide nocase
        $auto2 = "Auto_Open" ascii wide nocase
        $auto3 = "Document_Open" ascii wide nocase
        $auto4 = "Workbook_Open" ascii wide nocase
        $shell1 = "Shell" ascii wide
        $shell2 = "WScript" ascii wide nocase
        $shell3 = "PowerShell" ascii wide nocase
        $shell4 = "cmd" ascii wide nocase
        $dl1 = "URLDownloadToFile" ascii wide nocase
        $dl2 = "XMLHTTP" ascii wide nocase
        $dl3 = "WebClient" ascii wide nocase
    condition:
        ($ole at 0 or $zip at 0) and any of ($vba*) and any of ($auto*) and (any of ($shell*) or any of ($dl*))
}

rule Suspicious_ISO_IMG {
    meta:
        description = "Detects suspicious ISO/IMG file with executables"
        severity = "medium"
        mitre = "T1553.005"
        author = "SOC Investigator"
    strings:
        $iso1 = "CD001" ascii
        $iso2 = { 00 43 44 30 30 31 }
        $exe = ".exe" ascii wide nocase
        $dll = ".dll" ascii wide nocase
        $lnk = ".lnk" ascii wide nocase
        $bat = ".bat" ascii wide nocase
        $cmd = ".cmd" ascii wide nocase
        $ps1 = ".ps1" ascii wide nocase
        $vbs = ".vbs" ascii wide nocase
    condition:
        any of ($iso*) and 2 of ($exe, $dll, $lnk, $bat, $cmd, $ps1, $vbs)
}

rule Obfuscated_PowerShell {
    meta:
        description = "Detects heavily obfuscated PowerShell"
        severity = "high"
        mitre = "T1027"
        author = "SOC Investigator"
    strings:
        $ps1 = "powershell" ascii wide nocase
        $tick1 = "`" ascii wide
        $tick2 = "'+'" ascii wide
        $tick3 = "'+" ascii wide
        $char1 = "[char]" ascii wide nocase
        $char2 = "[convert]" ascii wide nocase
        $replace = "-replace" ascii wide nocase
        $join = "-join" ascii wide nocase
        $split = "-split" ascii wide nocase
        $reverse = "[array]::reverse" ascii wide nocase
        $format = "-f " ascii wide
        $iex1 = "iex" ascii wide nocase
        $iex2 = "invoke-expression" ascii wide nocase
    condition:
        $ps1 and (3 of ($tick*) or (2 of ($char*, $replace, $join, $split, $reverse, $format) and any of ($iex*)))
}

rule Suspicious_PDF {
    meta:
        description = "Detects suspicious PDF with JavaScript or embedded objects"
        severity = "medium"
        mitre = "T1566.001"
        author = "SOC Investigator"
    strings:
        $pdf = "%PDF" ascii
        $js1 = "/JavaScript" ascii nocase
        $js2 = "/JS" ascii
        $action1 = "/OpenAction" ascii
        $action2 = "/AA" ascii
        $action3 = "/Launch" ascii
        $embed1 = "/EmbeddedFile" ascii
        $embed2 = "/Filespec" ascii
        $uri = "/URI" ascii
    condition:
        $pdf at 0 and (any of ($js*) or ($action3 and any of ($action*)) or ($uri and any of ($action*)) or any of ($embed*))
}

rule Encoded_Executable {
    meta:
        description = "Detects Base64 encoded executable"
        severity = "high"
        mitre = "T1027"
        author = "SOC Investigator"
    strings:
        // Base64 encoded MZ header variations
        $b64_mz1 = "TVqQAAMAAAA" ascii wide
        $b64_mz2 = "TVpQAAIAAAA" ascii wide
        $b64_mz3 = "TVoAAAAAAAA" ascii wide
        $b64_mz4 = "TVpBAAEAAAA" ascii wide
        $b64_mz5 = "TVpTAE1T" ascii wide
        // Hex encoded MZ
        $hex_mz = "4D5A" ascii wide nocase
    condition:
        any of them
}

rule Suspicious_Scheduled_Task_XML {
    meta:
        description = "Detects suspicious scheduled task XML"
        severity = "medium"
        mitre = "T1053.005"
        author = "SOC Investigator"
    strings:
        $xml = "<?xml" ascii wide nocase
        $task = "<Task" ascii wide nocase
        $exec1 = "<Exec>" ascii wide nocase
        $exec2 = "<Command>" ascii wide nocase
        $susp1 = "powershell" ascii wide nocase
        $susp2 = "cmd.exe" ascii wide nocase
        $susp3 = "mshta" ascii wide nocase
        $susp4 = "wscript" ascii wide nocase
        $susp5 = "cscript" ascii wide nocase
        $susp6 = "rundll32" ascii wide nocase
        $susp7 = "-enc" ascii wide nocase
        $susp8 = "-nop" ascii wide nocase
        $susp9 = "http" ascii wide nocase
    condition:
        $xml and $task and any of ($exec*) and 2 of ($susp*)
}

rule Suspicious_Registry_File {
    meta:
        description = "Detects suspicious .reg file"
        severity = "medium"
        mitre = "T1112"
        author = "SOC Investigator"
    strings:
        $reg = "Windows Registry Editor" ascii wide nocase
        $run1 = "\\Run" ascii wide nocase
        $run2 = "\\RunOnce" ascii wide nocase
        $shell1 = "\\Shell\\Open\\Command" ascii wide nocase
        $shell2 = "\\Shell\\Explorer\\Command" ascii wide nocase
        $susp1 = "powershell" ascii wide nocase
        $susp2 = "cmd.exe" ascii wide nocase
        $susp3 = "mshta" ascii wide nocase
        $susp4 = "http" ascii wide nocase
        $disable1 = "DisableAntiSpyware" ascii wide nocase
        $disable2 = "DisableRealtimeMonitoring" ascii wide nocase
    condition:
        $reg and ((any of ($run*, $shell*) and any of ($susp*)) or any of ($disable*))
}
