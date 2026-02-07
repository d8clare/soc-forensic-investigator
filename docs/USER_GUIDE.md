# User Guide

## Overview

SOC Forensic Investigator is a comprehensive forensic analysis platform designed for SOC analysts and incident responders. This guide covers how to use the dashboard effectively.

---

## Quick Start

### 1. Collect Evidence
```powershell
# Run as Administrator on the target system
python collector.py
```

This creates an `Evidence_HOSTNAME_TIMESTAMP` folder containing all collected artifacts.

### 2. Launch Dashboard
```powershell
streamlit run dashboard.py
```

### 3. Select Evidence Folder
Use the sidebar dropdown to select an evidence folder for analysis.

---

## Dashboard Tabs

### Home
**Purpose**: Overview of the investigation case

**Features**:
- Risk score gauge (0-100)
- Top findings summary
- Collection metadata (hostname, timestamp, collector version)
- Case notes input

**Workflow**: Start here to get an overview before diving into specific artifacts.

---

### Findings
**Purpose**: All detected security issues ranked by severity

**Features**:
- Findings sorted by risk score
- MITRE ATT&CK technique tags
- Evidence details in expandable sections
- Confidence indicators (High/Medium/Low)
- Whitelist status for false positive management

**Columns**:
| Column | Description |
|--------|-------------|
| Severity | Critical/High/Medium/Low/Info |
| Category | Type of finding (e.g., "Encoded Command") |
| Description | What was detected |
| Score | Risk points (0-100 scale) |
| MITRE | Associated ATT&CK technique IDs |

---

### Timeline
**Purpose**: Chronological view of all events

**Features**:
- Interactive timeline visualization
- Filter by event type
- Zoom and pan controls
- Click events for details

**Use Cases**:
- Reconstruct attack timeline
- Identify initial access time
- Correlate events across artifacts

---

### Processes
**Purpose**: Analyze running and historical processes

**Subtabs**:
- **Live Processes**: Snapshot at collection time
- **Process Tree**: Parent-child relationships
- **Suspicious**: Flagged processes only

**Key Columns**:
| Column | Description |
|--------|-------------|
| Name | Process executable name |
| PID | Process ID |
| PPID | Parent process ID |
| User | Account running the process |
| Command Line | Full command with arguments |
| Path | Executable location |
| Signature | Code signing status |

**Red Flags**:
- Unsigned binaries in system folders
- Encoded PowerShell commands
- Office apps spawning cmd/powershell
- Processes from temp/downloads folders

---

### Network
**Purpose**: Analyze network connections and DNS

**Subtabs**:
- **Connections**: Active TCP/UDP connections
- **ARP Cache**: MAC address mappings
- **DNS Cache**: Recent DNS lookups
- **BITS Jobs**: Background transfer jobs
- **Hosts File**: Static DNS entries

**Risk Indicators**:
- Connections to known C2 ports (4444, 8888, etc.)
- Tor network connections
- Connections from suspicious processes
- High-entropy domain names (possible DGA)

---

### Persistence
**Purpose**: Identify persistence mechanisms

**Subtabs**:
- **Registry**: Autorun keys (Run, RunOnce, etc.)
- **Tasks**: Scheduled tasks
- **Services**: Windows services
- **WMI**: WMI event subscriptions
- **Startup**: Startup folder contents

**MITRE Mapping**:
| Mechanism | Technique |
|-----------|-----------|
| Registry Run Keys | T1547.001 |
| Scheduled Tasks | T1053.005 |
| Services | T1543.003 |
| WMI Subscriptions | T1546.003 |

---

### Execution
**Purpose**: Evidence of program execution

**Subtabs**:
- **UserAssist**: GUI program execution (ROT13 encoded)
- **Prefetch**: Application prefetch files
- **Shimcache**: Application compatibility cache
- **PowerShell**: PowerShell command history
- **LNK Files**: Shortcut file analysis

**Forensic Value**:
- Proves a program was executed
- Provides execution timestamps
- Shows execution count (UserAssist)

---

### Files
**Purpose**: Recent file system activity

**Subtabs**:
- **Recent Files**: Files in user folders (Desktop, Downloads, Temp)
- **Jump Lists**: Recent documents per application
- **Shellbags**: Folder access history

**Filters**:
- By extension (exe, ps1, zip, etc.)
- By location
- By date range
- Suspicious only

---

### USB
**Purpose**: USB device connection history

**Features**:
- Device serial numbers
- First/last connection times
- Vendor and product IDs
- Volume names

**MITRE Mapping**: T1091 (Replication Through Removable Media)

---

### Logs
**Purpose**: Windows Event Log analysis

**Features**:
- Security events (logons, privilege use)
- System events (service changes)
- PowerShell events (script blocks)
- Sysmon events (if installed)

**Key Event IDs**:
| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4688 | Process creation |
| 4720 | User account created |
| 1102 | Audit log cleared |
| 7045 | Service installed |

---

### Software
**Purpose**: Installed software inventory

**Features**:
- Installed programs list
- Version information
- Install dates
- Publisher details

**Use Cases**:
- Identify unauthorized software
- Find vulnerable versions
- Detect remote access tools

---

### Browser
**Purpose**: Web browser forensics

**Subtabs**:
- **History**: Browsing history (Chrome, Edge, Firefox)
- **Cookies**: Stored cookies
- **Downloads**: Downloaded files

**Analysis**:
- Suspicious domain visits
- Malware download sources
- Credential phishing sites

---

### MITRE
**Purpose**: ATT&CK framework mapping

**Features**:
- Detected techniques visualization
- Tactic grouping
- Links to ATT&CK documentation
- Coverage heatmap

---

### Integrity
**Purpose**: Evidence integrity verification

**Subtabs**:
- **File Hashes**: SHA256 of all collected files
- **Verify Hash**: Check if a hash exists in evidence
- **Manifest**: Generate chain of custody document
- **Registry Hives**: Backed up registry files

---

### Search
**Purpose**: Global search and pivot

**Modes**:
- **Search**: Find keywords across all artifacts
- **Pivot**: Cross-reference indicators (IPs, hashes, users)
- **Notes**: Investigation notes
- **Export**: Generate reports

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+F` | Focus search box |
| `1-9` | Jump to tab by number |
| `?` | Show help modal |
| `Esc` | Close modals |

---

## Quick Actions

Right-click or use action buttons on any indicator:

- **Copy**: Copy value to clipboard
- **Search**: Search across all evidence
- **Add IOC**: Add to custom IOC list
- **Flag**: Mark for follow-up

Flagged items appear in the sidebar for easy reference.

---

## Exporting Results

### HTML Report
1. Go to Search tab → Export mode
2. Click "Generate HTML Report"
3. Report includes findings, timeline, and evidence summary

### JSON Export
1. Go to Search tab → Export mode
2. Click "Export JSON"
3. Machine-readable format for integration

### Chain of Custody
1. Go to Integrity tab → Manifest
2. Fill in case details
3. Generate and download manifest

---

## Tips for Analysts

### Investigation Workflow
1. **Start at Home**: Check risk score and top findings
2. **Review Findings**: Prioritize by severity
3. **Timeline Analysis**: Establish attack chronology
4. **Pivot on IOCs**: Use Search tab to correlate
5. **Document**: Add notes as you investigate
6. **Export**: Generate report for documentation

### Common Investigation Patterns

**Malware Execution**:
1. Check Execution tab (Prefetch, Shimcache)
2. Find the file in Files tab
3. Check process tree for parent
4. Look for network connections
5. Check persistence mechanisms

**Lateral Movement**:
1. Check Network connections to port 445/135/5985
2. Review Logs for Event 4624 Type 3
3. Check for PsExec/WMI execution
4. Review scheduled tasks

**Data Exfiltration**:
1. Check Network for large transfers
2. Review Browser downloads
3. Check BITS jobs
4. Look for archive creation in Processes

### Reducing False Positives
1. Check the whitelist status of findings
2. Review the evidence context
3. Add patterns to `config/whitelist.json`
4. Use the Flag feature to mark confirmed issues
