# Evidence Collector Documentation

## Overview

The collector (`collector.py`) is a comprehensive forensic triage tool that gathers volatile and non-volatile evidence from Windows systems. It runs as a single Python script with no external dependencies beyond the standard library and pywin32.

---

## Running the Collector

### Basic Usage
```powershell
# Must run as Administrator
python collector.py
```

### Output
Creates folder: `Evidence_HOSTNAME_YYYYMMDD_HHMMSS/`

---

## Collection Phases

The collector runs through 12 phases in order:

### Phase 1: RAM Dump (Optional)
- **Tool**: DumpIt.exe (must be in `tools/` folder)
- **Output**: `memory.dmp`
- **Size**: Equal to system RAM

### Phase 2: Live Data
| Artifact | File | Description |
|----------|------|-------------|
| Processes | `processes.json` | Running processes with command lines |
| Network | `network_connections.json` | Active TCP/UDP connections |
| ARP Cache | `arp_cache.json` | IP to MAC mappings |
| Hosts File | `hosts_file.json` | Static DNS entries |

### Phase 3: Persistence
| Artifact | File | Description |
|----------|------|-------------|
| Registry Autoruns | `registry_autoruns.json` | Run, RunOnce, Services keys |
| Scheduled Tasks | `scheduled_tasks.json` | All scheduled tasks |
| Services | `services.json` | Windows services |
| WMI Persistence | `wmi_persistence.json` | WMI event subscriptions |
| Startup Folders | `startup_files.json` | Startup folder contents |

### Phase 4: Execution Artifacts
| Artifact | File | Description |
|----------|------|-------------|
| Prefetch | `prefetch.json` | Application prefetch data |
| UserAssist | `userassist.json` | GUI program execution |
| Shimcache | `shimcache.json` | Application compatibility cache |
| PowerShell History | `powershell_history.json` | Command history per user |
| Jump Lists | `jump_lists.json` | Recent documents per app |
| LNK Files | `lnk_files.json` | Shortcut analysis |

### Phase 5: USB Artifacts
| Artifact | File | Description |
|----------|------|-------------|
| USB History | `usb_history.json` | Connected USB devices |
| Volume Shadow | `volume_shadow.json` | VSS information |

### Phase 6: Filesystem
| Artifact | File | Description |
|----------|------|-------------|
| Recent Files | `recent_files.json` | Files in user folders |
| Shellbags | `shellbags.json` | Folder access history |
| MFT | `$MFT` | Master File Table (raw) |

### Phase 7: Event Logs
| Artifact | File | Description |
|----------|------|-------------|
| All Events | `all_events.json` | Security, System, PowerShell, Sysmon |

### Phase 8: Browser Data
| Artifact | File | Description |
|----------|------|-------------|
| Chrome/Edge History | `browser_history.json` | Browsing history |
| Firefox History | `firefox_history.json` | Firefox browsing history |
| Chrome/Edge Cookies | `browser_cookies.json` | Stored cookies |
| Firefox Cookies | `firefox_cookies.json` | Firefox cookies |
| Downloads | `browser_downloads.json` | All browser downloads |

### Phase 9: Network Artifacts
| Artifact | File | Description |
|----------|------|-------------|
| DNS Cache | `dns_cache.json` | Cached DNS queries |
| BITS Jobs | `bits_jobs.json` | Background transfers |
| RDP Cache | `rdp_cache.json` | RDP bitmap cache info |

### Phase 10: Registry Hives
| Artifact | Folder | Description |
|----------|--------|-------------|
| SAM | `registry_hives/` | User accounts |
| SYSTEM | `registry_hives/` | System configuration |
| SOFTWARE | `registry_hives/` | Installed software |
| SECURITY | `registry_hives/` | Security policies |
| NTUSER.DAT | `registry_hives/` | Per-user settings |

### Phase 11: Additional Data
| Artifact | File | Description |
|----------|------|-------------|
| SRUM | `srum_data.json` | System Resource Usage Monitor |
| Installed Software | `installed_software.json` | Programs list |

### Phase 12: Finalization
| Artifact | File | Description |
|----------|------|-------------|
| File Hashes | `file_hashes.json` | SHA256 of all files |
| Audit Log | `audit_log.json` | Collection metadata |
| Index | `index.html` | HTML file browser |

---

## Configuration

Edit the `CollectorConfig` class to customize collection:

```python
@dataclass
class CollectorConfig:
    collect_ram: bool = True           # Collect RAM dump
    collect_mft: bool = True           # Collect $MFT
    collect_srum: bool = True          # Collect SRUM database
    process_signature_check: bool = True  # Verify code signatures
    max_file_hash_size_mb: int = 10    # Max file size to hash
    recent_files_days: int = 30        # Days for recent files
    max_browser_history: int = 500     # Max browser entries
    max_event_logs: int = 3000         # Max event log entries
```

---

## Timestamps

All timestamps are in **UTC** format:
```
YYYY-MM-DD HH:MM:SS UTC
```

Example: `2026-02-07 14:30:00 UTC`

This ensures consistency across time zones during multi-site investigations.

---

## DPAPI Decryption

The collector includes DPAPI decryption for:
- Chrome/Edge cookies
- Chrome/Edge saved passwords (if enabled)
- Browser local storage encryption keys

This requires running as the user context or with appropriate privileges.

---

## Error Handling

Errors are logged to `errors.log` in the output folder. Common issues:

| Error | Cause | Solution |
|-------|-------|----------|
| Access Denied | Not admin | Run as Administrator |
| $MFT extraction failed | Raw disk access | Use external tool (RawCopy) |
| DPAPI decryption failed | User context | Run as logged-in user |
| PowerShell timeout | Complex query | Increase timeout in code |

---

## Output Structure

```
Evidence_HOSTNAME_20260207_143000/
├── processes.json
├── network_connections.json
├── arp_cache.json
├── hosts_file.json
├── registry_autoruns.json
├── scheduled_tasks.json
├── services.json
├── wmi_persistence.json
├── startup_files.json
├── prefetch.json
├── userassist.json
├── shimcache.json
├── powershell_history.json
├── jump_lists.json
├── lnk_files.json
├── usb_history.json
├── recent_files.json
├── shellbags.json
├── all_events.json
├── browser_history.json
├── firefox_history.json
├── browser_cookies.json
├── firefox_cookies.json
├── browser_downloads.json
├── dns_cache.json
├── bits_jobs.json
├── installed_software.json
├── file_hashes.json
├── audit_log.json
├── collection.log
├── errors.log
├── index.html
├── registry_hives/
│   ├── SAM
│   ├── SYSTEM
│   ├── SOFTWARE
│   ├── SECURITY
│   └── NTUSER_username.DAT
└── memory.dmp (if DumpIt available)
```

---

## Performance

Typical collection times:

| System Type | Time | Evidence Size |
|-------------|------|---------------|
| Workstation | 2-5 min | 50-200 MB |
| Server | 5-15 min | 200-500 MB |
| With RAM dump | +5-10 min | +8-32 GB |

---

## Security Considerations

### Data Sensitivity
Evidence folders contain sensitive data:
- Password hashes (registry hives)
- Browser cookies and history
- User activity patterns

**Recommendation**: Encrypt evidence folders during transport.

### Chain of Custody
The `audit_log.json` provides:
- Collection start/end times
- Collector version
- Hostname and user
- Phase timings

Use the Integrity tab to generate formal chain of custody documents.

---

## Extending the Collector

### Adding New Artifacts

1. Create a collection method:
```python
def collect_new_artifact(self):
    phase_start = self.log_phase("New Artifact...")

    data = []
    # Collection logic here

    self.save_json("new_artifact.json", data)
    self.log_phase_complete("New Artifact", phase_start)
```

2. Add to `run_collection()`:
```python
def run_collection(self):
    # ... existing phases ...
    self.collect_new_artifact()
    # ...
```

3. Update dashboard `evidence_cache.py` to load the new file.

### Adding New Detection

1. Add assessment method to `risk_engine.py`
2. Call it from `dashboard.py` in `analyze_evidence()`
3. Add MITRE technique mapping
