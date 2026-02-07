/*
    Persistence Mechanism Detection
*/

rule Persistence_Registry_Run {
    meta:
        description = "Detects registry Run key persistence"
        severity = "medium"
        mitre = "T1547.001"
    strings:
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $reg2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $reg3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices" ascii wide nocase
        $reg4 = "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $api1 = "RegSetValueEx" ascii wide
        $api2 = "RegCreateKeyEx" ascii wide
    condition:
        any of ($reg*) and any of ($api*)
}

rule Persistence_Scheduled_Task {
    meta:
        description = "Detects scheduled task creation"
        severity = "medium"
        mitre = "T1053.005"
    strings:
        $s1 = "schtasks" ascii wide nocase
        $s2 = "/create" ascii wide nocase
        $s3 = "/sc" ascii wide nocase
        $s4 = "/tn" ascii wide nocase
        $s5 = "/tr" ascii wide nocase
        $xml1 = "<Task" ascii wide nocase
        $xml2 = "<Exec>" ascii wide nocase
    condition:
        ($s1 and 3 of ($s*)) or ($xml1 and $xml2)
}

rule Persistence_Service_Creation {
    meta:
        description = "Detects Windows service creation"
        severity = "medium"
        mitre = "T1543.003"
    strings:
        $s1 = "sc create" ascii wide nocase
        $s2 = "sc config" ascii wide nocase
        $s3 = "New-Service" ascii wide nocase
        $api1 = "CreateService" ascii wide
        $api2 = "OpenSCManager" ascii wide
        $api3 = "ChangeServiceConfig" ascii wide
    condition:
        any of ($s*) or 2 of ($api*)
}

rule Persistence_WMI_Subscription {
    meta:
        description = "Detects WMI event subscription persistence"
        severity = "high"
        mitre = "T1546.003"
    strings:
        $s1 = "__EventFilter" ascii wide nocase
        $s2 = "__EventConsumer" ascii wide nocase
        $s3 = "__FilterToConsumerBinding" ascii wide nocase
        $s4 = "CommandLineEventConsumer" ascii wide nocase
        $s5 = "ActiveScriptEventConsumer" ascii wide nocase
        $s6 = "Set-WmiInstance" ascii wide nocase
        $s7 = "Create-WMIEventSubscription" ascii wide nocase
    condition:
        2 of them
}

rule Persistence_COM_Hijack {
    meta:
        description = "Detects COM object hijacking"
        severity = "high"
        mitre = "T1546.015"
    strings:
        $s1 = "InprocServer32" ascii wide nocase
        $s2 = "LocalServer32" ascii wide nocase
        $s3 = "TreatAs" ascii wide nocase
        $s4 = "CLSID" ascii wide nocase
        $api = "RegSetValueEx" ascii wide
    condition:
        2 of ($s*) and $api
}

rule Persistence_AppInit_DLL {
    meta:
        description = "Detects AppInit_DLLs persistence"
        severity = "high"
        mitre = "T1546.010"
    strings:
        $s1 = "AppInit_DLLs" ascii wide nocase
        $s2 = "LoadAppInit_DLLs" ascii wide nocase
        $s3 = "Microsoft\\Windows NT\\CurrentVersion\\Windows" ascii wide nocase
    condition:
        2 of them
}

rule Persistence_Image_File_Execution {
    meta:
        description = "Detects Image File Execution Options hijack"
        severity = "high"
        mitre = "T1546.012"
    strings:
        $s1 = "Image File Execution Options" ascii wide nocase
        $s2 = "Debugger" ascii wide nocase
        $s3 = "GlobalFlag" ascii wide nocase
        $s4 = "IFEO" ascii wide nocase
    condition:
        2 of them
}

rule Persistence_DLL_Side_Loading {
    meta:
        description = "Detects DLL side-loading indicators"
        severity = "medium"
        mitre = "T1574.002"
    strings:
        $s1 = "LoadLibrary" ascii wide
        $s2 = "GetProcAddress" ascii wide
        $path1 = "\\AppData\\Local\\" ascii wide nocase
        $path2 = "\\AppData\\Roaming\\" ascii wide nocase
        $path3 = "\\ProgramData\\" ascii wide nocase
        $path4 = "\\Temp\\" ascii wide nocase
    condition:
        all of ($s*) and any of ($path*)
}

rule Persistence_Startup_Folder {
    meta:
        description = "Detects startup folder persistence"
        severity = "medium"
        mitre = "T1547.001"
    strings:
        $s1 = "\\Start Menu\\Programs\\Startup" ascii wide nocase
        $s2 = "\\Startup\\" ascii wide nocase
        $s3 = "shell:startup" ascii wide nocase
        $s4 = "shell:common startup" ascii wide nocase
        $api = "SHGetFolderPath" ascii wide
    condition:
        any of ($s*) or $api
}

rule Persistence_Screensaver {
    meta:
        description = "Detects screensaver hijacking"
        severity = "medium"
        mitre = "T1546.002"
    strings:
        $s1 = "SCRNSAVE.EXE" ascii wide nocase
        $s2 = "Control Panel\\Desktop" ascii wide nocase
        $s3 = ".scr" ascii wide nocase
    condition:
        2 of them
}

rule Persistence_Netsh_Helper {
    meta:
        description = "Detects Netsh helper DLL persistence"
        severity = "high"
        mitre = "T1546.007"
    strings:
        $s1 = "netsh" ascii wide nocase
        $s2 = "add helper" ascii wide nocase
        $s3 = "\\Microsoft\\NetSh" ascii wide nocase
    condition:
        2 of them
}

rule Persistence_Time_Provider {
    meta:
        description = "Detects Time Provider persistence"
        severity = "high"
        mitre = "T1547.003"
    strings:
        $s1 = "W32Time" ascii wide nocase
        $s2 = "TimeProviders" ascii wide nocase
        $s3 = "DllName" ascii wide nocase
    condition:
        all of them
}

rule Persistence_Print_Monitor {
    meta:
        description = "Detects Print Monitor persistence"
        severity = "high"
        mitre = "T1547.010"
    strings:
        $s1 = "Monitors" ascii wide nocase
        $s2 = "Print" ascii wide nocase
        $s3 = "Driver" ascii wide nocase
        $path = "SYSTEM\\CurrentControlSet\\Control\\Print" ascii wide nocase
    condition:
        $path and 2 of ($s*)
}

rule Persistence_LSA_Security_Package {
    meta:
        description = "Detects LSA Security Package persistence"
        severity = "critical"
        mitre = "T1547.005"
    strings:
        $s1 = "Security Packages" ascii wide nocase
        $s2 = "Authentication Packages" ascii wide nocase
        $path = "SYSTEM\\CurrentControlSet\\Control\\Lsa" ascii wide nocase
    condition:
        $path and any of ($s*)
}

rule Persistence_Password_Filter {
    meta:
        description = "Detects Password Filter DLL persistence"
        severity = "critical"
        mitre = "T1556.002"
    strings:
        $s1 = "Notification Packages" ascii wide nocase
        $path = "SYSTEM\\CurrentControlSet\\Control\\Lsa" ascii wide nocase
        $api = "PasswordChangeNotify" ascii wide
    condition:
        ($path and $s1) or $api
}
