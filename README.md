# SOC Forensic Investigator

A USB-portable, production-ready SOC forensic dashboard for Windows incident response and threat hunting.

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28+-red.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## Features

### Evidence Collection (`collector.py`)
- **Live System Data**: Processes, network connections, ARP cache, DNS cache
- **Persistence Mechanisms**: Registry autoruns, scheduled tasks, services, WMI subscriptions, startup folders
- **Execution Artifacts**: Prefetch, UserAssist, Shimcache, PowerShell history, Jump Lists
- **Browser Forensics**: Chrome/Edge/Firefox history, cookies, downloads (with DPAPI decryption)
- **File System**: Recent files, USB artifacts, shellbags
- **Event Logs**: Security, System, PowerShell, Sysmon events
- **Memory**: RAM dump support (with DumpIt)
- **Registry Hives**: Backup of SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT

### Dashboard Analysis (`dashboard.py`)
- **Risk Scoring**: Bounded, weighted scoring with MITRE ATT&CK integration
- **Multi-Engine Detection**:
  - Built-in behavioral rules
  - Sigma rule support (YAML)
  - YARA rule scanning
  - Threat intelligence feeds
- **14 Investigation Tabs**: Home, Findings, Timeline, Processes, Network, Persistence, Execution, Files, USB, Logs, Software, Browser, MITRE, Integrity
- **Pivot & Correlate**: Cross-artifact correlation engine
- **Export**: HTML/JSON reports with chain of custody

### Security Hardening
- PBKDF2-HMAC-SHA256 authentication (100k iterations)
- Rate limiting (5 failed attempts = 5 min lockout)
- Session timeout
- SQL injection prevention
- Windows DPAPI for API key encryption

### Detection Capabilities
| Category | MITRE Techniques |
|----------|------------------|
| Credential Access | T1003, T1558 (Kerberos) |
| Defense Evasion | T1070 (Anti-Forensics), T1562 (Disable Security) |
| Persistence | T1547, T1546 (WMI), T1053 (Tasks) |
| Lateral Movement | T1021, T1550 |
| Execution | T1059 (PowerShell/CMD), T1204 |
| Discovery | T1082, T1083, T1087 |
| Brute Force | T1110.001, T1110.003 (Password Spraying) |

## Installation

### Requirements
- Windows 10/11 or Windows Server 2016+
- Python 3.9+
- Administrator privileges (for collection)

### Quick Start

```powershell
# Clone the repository
git clone https://github.com/YOUR_USERNAME/soc-forensic-investigator.git
cd soc-forensic-investigator

# Install dependencies
pip install -r requirements.txt

# Run evidence collection (as Administrator)
python collector.py

# Start the dashboard
streamlit run dashboard.py
```

### USB Portable Setup

1. Copy the entire folder to a USB drive
2. Run `run_collector.bat` (as Administrator) to collect evidence
3. Run `run_dashboard.bat` to analyze on any machine

## Usage

### Collecting Evidence

```powershell
# Run as Administrator
python collector.py
```

This creates an `Evidence_HOSTNAME_TIMESTAMP` folder containing:
- JSON files for each artifact type
- Registry hive backups
- RAM dump (if DumpIt.exe is in tools/)
- Collection audit log

### Analyzing Evidence

```powershell
streamlit run dashboard.py
```

1. Select an evidence folder from the sidebar
2. Review the risk score and top findings on Home tab
3. Navigate through tabs to investigate specific artifacts
4. Use Search tab to pivot across all evidence
5. Export report when investigation is complete

### Configuration

Edit `config/risk_rules.json` to customize:
- Detection patterns and scores
- Severity thresholds
- Category weights

Add entries to `config/whitelist.json` to reduce false positives.

## Project Structure

```
soc-forensic-investigator/
├── collector.py          # Evidence collection script
├── dashboard.py          # Main Streamlit dashboard
├── requirements.txt      # Python dependencies
├── run_collector.bat     # Windows batch launcher
├── run_dashboard.bat     # Dashboard launcher
├── core/
│   ├── risk_engine.py    # Risk scoring with MITRE mapping
│   ├── sigma_engine.py   # Sigma rule matching
│   ├── yara_engine.py    # YARA scanning
│   ├── threat_intel.py   # Threat intelligence
│   ├── pivot_engine.py   # Cross-artifact correlation
│   ├── data_loader.py    # JSON loading utilities
│   ├── database.py       # SQLite operations
│   └── security.py       # Encryption utilities
├── tabs/
│   ├── home.py           # Overview and case info
│   ├── findings.py       # Risk findings display
│   ├── timeline.py       # Event timeline
│   ├── processes.py      # Process analysis
│   ├── network.py        # Network connections
│   ├── persistence.py    # Persistence mechanisms
│   ├── execution.py      # Execution artifacts
│   ├── files.py          # File system analysis
│   ├── usb.py            # USB device history
│   ├── logs.py           # Event log viewer
│   ├── software.py       # Installed software
│   ├── browser.py        # Browser forensics
│   ├── mitre.py          # MITRE ATT&CK mapping
│   ├── integrity.py      # Hash verification
│   └── search.py         # Global search & pivot
├── components/
│   ├── auth.py           # Authentication
│   ├── quick_actions.py  # Copy/Flag/IOC actions
│   ├── pivot_modal.py    # Correlation display
│   └── export_report.py  # Report generation
├── config/
│   ├── risk_rules.json   # Detection rules
│   ├── whitelist.json    # False positive reduction
│   └── theme.py          # UI theming
├── rules/
│   ├── sigma/            # Sigma detection rules
│   └── yara/             # YARA rules
└── tools/
    └── DumpIt.exe        # (Optional) RAM acquisition
```

## Detection Rules

### Adding Sigma Rules

Place `.yml` files in `rules/sigma/`:

```yaml
title: Suspicious PowerShell Download
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'Invoke-WebRequest'
            - 'wget'
            - 'curl'
    condition: selection
level: medium
```

### Adding YARA Rules

Place `.yar` files in `rules/yara/`:

```yara
rule Mimikatz_Strings {
    strings:
        $s1 = "sekurlsa::logonpasswords" nocase
        $s2 = "lsadump::sam" nocase
    condition:
        any of them
}
```

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+F` | Focus search |
| `1-9` | Jump to tab |
| `?` | Show help |
| `Esc` | Close modal |

## API Keys (Optional)

For threat intelligence lookups, add API keys via the Settings tab:
- VirusTotal
- AbuseIPDB
- Shodan

Keys are encrypted using Windows DPAPI.

## Timestamps

All timestamps in collected evidence are normalized to **UTC** with the format:
```
YYYY-MM-DD HH:MM:SS UTC
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - See LICENSE file for details.

## Disclaimer

This tool is intended for authorized security testing, incident response, and forensic analysis only. Users are responsible for ensuring they have proper authorization before collecting evidence from any system.

## Credits

Developed for SOC analysts and incident responders.

- MITRE ATT&CK Framework: https://attack.mitre.org/
- Sigma Rules: https://github.com/SigmaHQ/sigma
- YARA: https://virustotal.github.io/yara/
