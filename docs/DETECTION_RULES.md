# Detection Rules Documentation

## Overview

SOC Forensic Investigator uses multiple detection engines:

1. **Built-in Behavioral Rules** - Core risk engine with MITRE mapping
2. **Sigma Rules** - Community detection rules (YAML)
3. **YARA Rules** - Pattern matching for malware
4. **Threat Intelligence** - External IOC feeds

---

## Built-in Behavioral Rules

### Configuration File
`config/risk_rules.json`

### Rule Structure

```json
{
  "process_rules": {
    "malicious_keywords": {
      "patterns": ["mimikatz", "cobalt", "psexec"],
      "score": 50,
      "severity": "critical",
      "mitre_techniques": ["T1003", "T1059"]
    }
  }
}
```

### Rule Categories

#### Process Rules
| Rule | Detects | MITRE |
|------|---------|-------|
| `malicious_keywords` | Known attack tools | T1003, T1059 |
| `encoded_commands` | Base64/encoded PowerShell | T1059.001, T1027 |
| `office_spawn_shell` | Office spawning cmd/powershell | T1566.001 |
| `unsigned_system_binaries` | Unsigned DLLs in system32 | T1036 |
| `credential_access` | LSASS access patterns | T1003 |
| `amsi_bypass` | AMSI bypass attempts | T1562.001 |
| `defender_evasion` | Defender tampering | T1562.001 |
| `ransomware_indicators` | Encryption patterns | T1486 |
| `lateral_movement` | PsExec, WMI remote | T1021 |
| `discovery_commands` | Recon commands | T1082, T1083 |
| `uac_bypass` | UAC bypass techniques | T1548.002 |
| `lolbins` | Living-off-the-land binaries | T1218 |

#### Network Rules
| Rule | Detects | MITRE |
|------|---------|-------|
| `suspicious_ports` | C2 ports (4444, 8888, etc.) | T1571 |
| `c2_framework_ports` | Cobalt Strike, Metasploit | T1071 |
| `tor_ports` | Tor network connections | T1090.003 |
| `irc_ports` | IRC botnet C2 | T1071.001 |
| `winrm_connection` | Remote management | T1021.006 |

#### Event Rules
| Rule | Detects | MITRE |
|------|---------|-------|
| `log_clearing` | Event IDs 1102, 104 | T1070.001 |
| `user_creation` | Event ID 4720 | T1136.001 |
| `service_install` | Event ID 7045 | T1543.003 |
| `scheduled_task` | Event ID 4698 | T1053.005 |

#### Anti-Forensics Rules
| Rule | Detects | MITRE |
|------|---------|-------|
| `shadow_copy_deletion` | vssadmin delete shadows | T1490 |
| `timestomping` | File time manipulation | T1070.006 |
| `av_tampering` | Defender exclusions | T1562.001 |
| `evidence_destruction` | Secure delete tools | T1070.004 |

#### Kerberos Attack Rules
| Rule | Detects | MITRE |
|------|---------|-------|
| `kerberoasting` | TGS requests with RC4 | T1558.003 |
| `asrep_roasting` | AS-REP without pre-auth | T1558.004 |
| `golden_ticket` | Forged TGT | T1558.001 |

#### Brute Force Rules
| Rule | Detects | MITRE |
|------|---------|-------|
| `failed_logons` | 5+ failures per user | T1110.001 |
| `password_spraying` | Same IP, multiple users | T1110.003 |

### Adding Custom Rules

Edit `config/risk_rules.json`:

```json
{
  "process_rules": {
    "my_custom_rule": {
      "patterns": ["suspicious-tool.exe", "bad-script.ps1"],
      "score": 45,
      "severity": "high",
      "mitre_techniques": ["T1059"],
      "description": "Custom detection for specific threat"
    }
  }
}
```

---

## Sigma Rules

### Location
- `rules/sigma/` - Custom rules
- `config/sigma_rules/` - Built-in rules

### Supported Rule Types
- Process creation
- Network connections
- File events
- Registry events
- PowerShell events

### Example Sigma Rule

```yaml
title: Suspicious PowerShell Download Cradle
id: 3b6ab547-8ec2-4991-b9d2-2b06702a48d7
status: experimental
description: Detects PowerShell download cradle patterns
author: SOC Team
date: 2026/01/15
references:
    - https://attack.mitre.org/techniques/T1059/001/
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\powershell.exe'
        - Image|endswith: '\pwsh.exe'
    selection_cli:
        CommandLine|contains:
            - 'Invoke-WebRequest'
            - 'Invoke-RestMethod'
            - 'wget '
            - 'curl '
            - 'Net.WebClient'
            - 'DownloadString'
            - 'DownloadFile'
    condition: selection_img and selection_cli
falsepositives:
    - Legitimate software updates
    - Admin scripts
level: medium
tags:
    - attack.execution
    - attack.t1059.001
    - attack.command_and_control
    - attack.t1105
```

### Importing Sigma Rules

1. Download from [SigmaHQ](https://github.com/SigmaHQ/sigma)
2. Place `.yml` files in `rules/sigma/`
3. Restart dashboard to load

### Sigma Conversion

The engine automatically converts Sigma rules to internal format. Supported modifiers:
- `contains`
- `startswith`
- `endswith`
- `re` (regex)

---

## YARA Rules

### Location
`rules/yara/`

### Built-in Rule Sets

| File | Purpose |
|------|---------|
| `malware_generic.yar` | Common malware patterns |
| `ransomware.yar` | Ransomware indicators |
| `hacktools.yar` | Penetration testing tools |
| `lolbins.yar` | Suspicious LOLBin usage |
| `persistence.yar` | Persistence mechanisms |
| `cryptominers.yar` | Cryptocurrency miners |
| `exfiltration.yar` | Data exfiltration tools |
| `apt_malware.yar` | APT-related patterns |
| `suspicious_scripts.yar` | Obfuscated scripts |

### Example YARA Rule

```yara
rule Mimikatz_Memory_Strings
{
    meta:
        description = "Detects Mimikatz in memory or files"
        author = "SOC Team"
        severity = "critical"
        mitre = "T1003"

    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide nocase
        $s2 = "sekurlsa::wdigest" ascii wide nocase
        $s3 = "lsadump::sam" ascii wide nocase
        $s4 = "lsadump::dcsync" ascii wide nocase
        $s5 = "kerberos::golden" ascii wide nocase
        $s6 = "privilege::debug" ascii wide nocase

        $pdb = "mimikatz.pdb" ascii
        $author = "gentilkiwi" ascii wide

    condition:
        2 of ($s*) or $pdb or $author
}
```

### YARA Rule Metadata

Use these metadata fields for dashboard integration:

| Field | Purpose |
|-------|---------|
| `description` | Finding description |
| `severity` | critical/high/medium/low |
| `mitre` | MITRE technique ID |
| `author` | Rule author |
| `reference` | URL to more info |

---

## Whitelist Configuration

### Location
`config/whitelist.json`

### Purpose
Reduce false positives for known-good activity in your environment.

### Structure

```json
{
  "processes": {
    "known_good_lolbins": {
      "description": "LOLBins with valid enterprise use",
      "patterns": [
        {
          "process": "powershell.exe",
          "parent": "sccm",
          "cmdline_not": ["-enc", "bypass"],
          "reason": "SCCM management scripts"
        },
        {
          "process": "certutil.exe",
          "parent": "msiexec.exe",
          "reason": "Certificate installation during software install"
        }
      ]
    },
    "known_good_encoded": {
      "description": "Legitimate encoded PowerShell",
      "patterns": [
        {
          "cmdline_contains": ["ConfigMgr", "SCCM"],
          "parent": "CcmExec.exe",
          "reason": "SCCM client operations"
        }
      ]
    },
    "system_processes": {
      "description": "System paths with reduced scoring",
      "paths": [
        "C:\\Windows\\System32\\",
        "C:\\Program Files\\",
        "C:\\Program Files (x86)\\"
      ]
    }
  },
  "network": {
    "known_good_ports": {
      "description": "Expected network services",
      "patterns": [
        {
          "port": 8080,
          "process": "java.exe",
          "reason": "Internal web application"
        }
      ]
    },
    "internal_ranges": {
      "description": "Internal IP ranges (reduced scoring)",
      "ranges": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
      "score_modifier": 0.5
    }
  },
  "dns": {
    "known_good_domains": {
      "description": "Trusted domains",
      "patterns": [
        ".microsoft.com",
        ".windows.com",
        ".office365.com",
        ".yourcompany.com"
      ]
    },
    "enterprise_services": {
      "description": "Enterprise SaaS",
      "patterns": [
        ".salesforce.com",
        ".servicenow.com"
      ]
    }
  }
}
```

### Score Modifiers

| Modifier | Effect |
|----------|--------|
| 0.0 | Completely whitelist (no score) |
| 0.2 | 80% reduction |
| 0.5 | 50% reduction |
| 1.0 | No modification |

---

## Scoring System

### Score Calculation

1. Each finding has a base score (0-100)
2. Category weights are applied
3. Whitelist modifiers reduce scores
4. Categories have maximum caps
5. Global score capped at 100

### Category Weights

```json
{
  "category_weights": {
    "credential_access": 1.5,
    "ransomware": 1.5,
    "malicious_process": 1.3,
    "default": 1.0
  }
}
```

### Category Caps

```json
{
  "category_max_scores": {
    "credential_access": 30,
    "ransomware": 30,
    "malicious_process": 25,
    "default": 15
  }
}
```

### Severity Thresholds

| Score | Severity |
|-------|----------|
| 70+ | Critical |
| 50-69 | High |
| 25-49 | Medium |
| 10-24 | Low |
| 0-9 | Info |

---

## Threat Intelligence

### Supported Feeds

| Feed | Type | Configuration |
|------|------|---------------|
| VirusTotal | Hash/Domain/IP | API key required |
| AbuseIPDB | IP reputation | API key required |
| Emerging Threats | IP blocklist | Built-in |

### Adding API Keys

1. Go to Settings in dashboard
2. Enter API keys
3. Keys are encrypted with Windows DPAPI

### Custom IOC Lists

Add to `config/threat_intel/`:

```json
{
  "malicious_ips": [
    "1.2.3.4",
    "5.6.7.8"
  ],
  "malicious_domains": [
    "evil.com",
    "malware.net"
  ],
  "malicious_hashes": [
    "abc123...",
    "def456..."
  ]
}
```

---

## Testing Rules

### Test Sigma Rule
```python
from core.sigma_engine import SigmaEngine

engine = SigmaEngine("rules/sigma/")
test_event = {
    "Image": "C:\\Windows\\System32\\powershell.exe",
    "CommandLine": "powershell -enc SGVsbG8gV29ybGQ="
}
matches = engine.match_process(test_event)
for m in matches:
    print(f"Rule: {m.rule_name}, Severity: {m.severity}")
```

### Test YARA Rule
```python
from core.yara_engine import YaraEngine

engine = YaraEngine("rules/yara/")
matches = engine.scan_file("suspect.exe")
for m in matches:
    print(f"Rule: {m.rule_name}")
```

### Test Risk Engine
```python
from core.risk_engine import RiskEngine
import pandas as pd

engine = RiskEngine("config/risk_rules.json")
process = pd.Series({
    "name": "powershell.exe",
    "cmdline": "powershell -enc SGVsbG8=",
    "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
})
score = engine.assess_process(process)
print(f"Score: {score}, Findings: {len(engine.all_findings)}")
```
