/*
    Data Exfiltration and Staging Detection
*/

rule Exfil_Archive_Creation {
    meta:
        description = "Detects archive creation for data staging"
        severity = "medium"
        mitre = "T1560.001"
    strings:
        $s1 = "7z.exe" ascii wide nocase
        $s2 = "7za.exe" ascii wide nocase
        $s3 = "rar.exe" ascii wide nocase
        $s4 = "WinRAR" ascii wide nocase
        $s5 = "zip" ascii wide nocase
        $s6 = "Compress-Archive" ascii wide nocase
        $s7 = "tar" ascii wide nocase
        $arg1 = " a " ascii wide
        $arg2 = "-p" ascii wide
        $arg3 = "-r" ascii wide
    condition:
        any of ($s*) and any of ($arg*)
}

rule Exfil_Cloud_Storage {
    meta:
        description = "Detects cloud storage exfiltration"
        severity = "high"
        mitre = "T1567.002"
    strings:
        $s1 = "mega.nz" ascii wide nocase
        $s2 = "dropbox.com" ascii wide nocase
        $s3 = "drive.google.com" ascii wide nocase
        $s4 = "onedrive.live.com" ascii wide nocase
        $s5 = "box.com" ascii wide nocase
        $s6 = "mediafire.com" ascii wide nocase
        $s7 = "sendspace.com" ascii wide nocase
        $s8 = "wetransfer.com" ascii wide nocase
        $s9 = "anonfiles.com" ascii wide nocase
        $s10 = "file.io" ascii wide nocase
        $api1 = "upload" ascii wide nocase
        $api2 = "transfer" ascii wide nocase
    condition:
        any of ($s*) and any of ($api*)
}

rule Exfil_DNS_Tunneling {
    meta:
        description = "Detects DNS tunneling indicators"
        severity = "high"
        mitre = "T1048.003"
    strings:
        $s1 = "dnscat" ascii wide nocase
        $s2 = "dns2tcp" ascii wide nocase
        $s3 = "iodine" ascii wide nocase
        $s4 = "dnstunnel" ascii wide nocase
        $long_dns = /[a-zA-Z0-9]{50,}\./ ascii
    condition:
        any of ($s*) or $long_dns
}

rule Exfil_HTTP_POST {
    meta:
        description = "Detects HTTP POST exfiltration patterns"
        severity = "medium"
        mitre = "T1048.001"
    strings:
        $s1 = "POST" ascii wide
        $s2 = "multipart/form-data" ascii wide nocase
        $s3 = "Content-Disposition: form-data" ascii wide nocase
        $s4 = "application/octet-stream" ascii wide nocase
        $api1 = "HttpSendRequest" ascii wide
        $api2 = "InternetWriteFile" ascii wide
        $api3 = "WinHttpSendRequest" ascii wide
    condition:
        ($s1 and any of ($s2, $s3, $s4)) or 2 of ($api*)
}

rule Exfil_Email {
    meta:
        description = "Detects email-based exfiltration"
        severity = "medium"
        mitre = "T1048.003"
    strings:
        $smtp1 = "smtp.gmail.com" ascii wide nocase
        $smtp2 = "smtp.outlook.com" ascii wide nocase
        $smtp3 = "smtp.mail.yahoo.com" ascii wide nocase
        $s1 = "SmtpClient" ascii wide nocase
        $s2 = "Send-MailMessage" ascii wide nocase
        $s3 = "attachment" ascii wide nocase
        $api = "MAPISendMail" ascii wide
    condition:
        (any of ($smtp*) and $s3) or $s1 or $s2 or $api
}

rule Exfil_FTP {
    meta:
        description = "Detects FTP exfiltration"
        severity = "medium"
        mitre = "T1048.003"
    strings:
        $s1 = "ftp://" ascii wide nocase
        $s2 = "FtpWebRequest" ascii wide nocase
        $s3 = "put " ascii wide nocase
        $api1 = "FtpPutFile" ascii wide
        $api2 = "InternetConnect" ascii wide
    condition:
        $s1 or $s2 or ($s3 and any of ($api*))
}

rule Exfil_Clipboard {
    meta:
        description = "Detects clipboard data theft"
        severity = "medium"
        mitre = "T1115"
    strings:
        $api1 = "GetClipboardData" ascii wide
        $api2 = "OpenClipboard" ascii wide
        $api3 = "CloseClipboard" ascii wide
        $ps1 = "Get-Clipboard" ascii wide nocase
        $ps2 = "[Windows.Clipboard]" ascii wide nocase
    condition:
        2 of ($api*) or any of ($ps*)
}

rule Exfil_Screen_Capture {
    meta:
        description = "Detects screen capture functionality"
        severity = "medium"
        mitre = "T1113"
    strings:
        $api1 = "BitBlt" ascii wide
        $api2 = "GetDesktopWindow" ascii wide
        $api3 = "GetWindowDC" ascii wide
        $api4 = "CreateCompatibleBitmap" ascii wide
        $ps1 = "CopyFromScreen" ascii wide nocase
        $ps2 = "[System.Drawing.Graphics]" ascii wide nocase
    condition:
        3 of ($api*) or any of ($ps*)
}

rule Exfil_Audio_Capture {
    meta:
        description = "Detects audio capture functionality"
        severity = "medium"
        mitre = "T1123"
    strings:
        $api1 = "waveInOpen" ascii wide
        $api2 = "waveInStart" ascii wide
        $api3 = "mciSendString" ascii wide
        $s1 = "record" ascii wide nocase
        $s2 = "microphone" ascii wide nocase
    condition:
        2 of ($api*) or (any of ($s*) and any of ($api*))
}

rule Exfil_Video_Capture {
    meta:
        description = "Detects webcam/video capture"
        severity = "medium"
        mitre = "T1125"
    strings:
        $api1 = "capCreateCaptureWindow" ascii wide
        $api2 = "capDriverConnect" ascii wide
        $s1 = "webcam" ascii wide nocase
        $s2 = "camera" ascii wide nocase
        $s3 = "DirectShow" ascii wide nocase
    condition:
        any of ($api*) or 2 of ($s*)
}

rule Exfil_Browser_Data {
    meta:
        description = "Detects browser data theft"
        severity = "high"
        mitre = "T1555.003"
    strings:
        $path1 = "\\Google\\Chrome\\User Data" ascii wide nocase
        $path2 = "\\Mozilla\\Firefox\\Profiles" ascii wide nocase
        $path3 = "\\Microsoft\\Edge\\User Data" ascii wide nocase
        $file1 = "Login Data" ascii wide
        $file2 = "Cookies" ascii wide
        $file3 = "Web Data" ascii wide
        $file4 = "History" ascii wide
        $api = "CryptUnprotectData" ascii wide
    condition:
        any of ($path*) and (any of ($file*) or $api)
}

rule Exfil_Keylog_Buffer {
    meta:
        description = "Detects keylogger buffer patterns"
        severity = "high"
        mitre = "T1056.001"
    strings:
        $s1 = "[ENTER]" ascii wide
        $s2 = "[TAB]" ascii wide
        $s3 = "[BACKSPACE]" ascii wide
        $s4 = "[CTRL]" ascii wide
        $s5 = "[SHIFT]" ascii wide
        $s6 = "[CAPSLOCK]" ascii wide
        $s7 = "[ESC]" ascii wide
    condition:
        4 of them
}
