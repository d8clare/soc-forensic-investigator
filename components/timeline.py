"""
Unified forensic timeline component - Professional Investigation View.
Aggregates events from multiple sources with filtering and analysis.
"""
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timedelta

import streamlit as st
import pandas as pd

from core.data_loader import sanitize_dataframe


class ForensicTimeline:
    """
    Professional forensic timeline that aggregates events from multiple sources.
    """

    def __init__(self, risky_artifacts: Set[str] = None):
        """Initialize timeline with optional risky artifacts for highlighting."""
        self.events: List[Dict[str, Any]] = []
        self.type_filters: List[str] = []
        self.risky_artifacts = risky_artifacts or set()

    def add_event_logs(self, events: List[Dict]):
        """Add Windows event log entries."""
        if not events:
            return self

        # Event ID descriptions for common security events
        event_descriptions = {
            1102: "Security audit log was cleared",
            104: "System log was cleared",
            4624: "Successful logon",
            4625: "Failed logon attempt",
            4634: "Logoff",
            4648: "Explicit credential logon",
            4672: "Special privileges assigned",
            4688: "New process created",
            4698: "Scheduled task created",
            4699: "Scheduled task deleted",
            4700: "Scheduled task enabled",
            4720: "User account created",
            4722: "User account enabled",
            4724: "Password reset attempt",
            4725: "User account disabled",
            4726: "User account deleted",
            4728: "Member added to security group",
            4732: "Member added to local group",
            4738: "User account changed",
            4776: "Credential validation",
            7034: "Service crashed",
            7035: "Service control sent",
            7036: "Service state changed",
            7040: "Service start type changed",
            7045: "Service installed",
        }

        for e in events:
            timestamp = e.get("Time")
            if not timestamp:
                continue

            event_id = e.get('Id', 0)
            level = e.get('LevelDisplayName', 'Info')
            log_name = e.get('LogName', '')
            provider = e.get('ProviderName', '')

            # Get clean description
            raw_msg = str(e.get('Message', ''))

            # Use predefined description if available
            if event_id in event_descriptions:
                description = event_descriptions[event_id]
            elif raw_msg and not raw_msg.startswith('[Error]') and 'Id = {' not in raw_msg:
                # Clean up the message - take first line only
                first_line = raw_msg.split('\n')[0].strip()
                # Remove common noise prefixes
                if first_line.startswith('The '):
                    first_line = first_line[4:]
                description = first_line[:150]
            else:
                # Fallback to log name and provider
                description = f"{log_name}: {provider}" if provider else log_name or f"Event {event_id}"

            # Determine if risky
            is_risky = event_id in [1102, 104, 4720, 7045, 4698, 4624, 4625]

            self.events.append({
                "Timestamp": timestamp,
                "Type": "Event Log",
                "Source": f"Event {event_id}",
                "Description": f"[{level}] {description}",
                "Risky": is_risky
            })

        if "Event Log" not in self.type_filters:
            self.type_filters.append("Event Log")
        return self

    def add_browser_history(self, history: List[Dict]):
        """Add browser history entries."""
        if not history:
            return self

        for h in history:
            timestamp = h.get("Time")
            if not timestamp:
                continue

            url = str(h.get('URL', ''))
            is_risky = any(kw in url.lower() for kw in ['admin', 'login', 'password', 'credential'])

            self.events.append({
                "Timestamp": timestamp,
                "Type": "Browser",
                "Source": h.get('Browser', 'Unknown'),
                "Description": f"Visited: {url[:100]}",
                "Risky": is_risky
            })

        if "Browser" not in self.type_filters:
            self.type_filters.append("Browser")
        return self

    def add_usb_events(self, usb_events: List[Dict]):
        """Add USB connection events."""
        if not usb_events:
            return self

        for u in usb_events:
            timestamp = u.get("Time")
            if not timestamp:
                continue

            self.events.append({
                "Timestamp": timestamp,
                "Type": "USB",
                "Source": u.get('Type', 'Device'),
                "Description": f"USB: {u.get('Device', 'Unknown device')}",
                "Risky": True  # USB events are always notable
            })

        if "USB" not in self.type_filters:
            self.type_filters.append("USB")
        return self

    def add_file_events(self, files: List[Dict]):
        """Add file system events."""
        if not files:
            return self

        for f in files:
            timestamp = f.get("created") or f.get("modified")
            if not timestamp:
                continue

            path = str(f.get('path', ''))
            is_risky = any(kw in path.lower() for kw in ['temp', 'appdata', 'downloads', '.exe', '.ps1', '.bat', '.vbs'])

            self.events.append({
                "Timestamp": timestamp,
                "Type": "File",
                "Source": "File System",
                "Description": f"File: {path[:100]}",
                "Risky": is_risky
            })

        if "File" not in self.type_filters:
            self.type_filters.append("File")
        return self

    def add_process_events(self, processes: List[Dict]):
        """Add process creation events."""
        if not processes:
            return self

        for p in processes:
            timestamp = p.get('create_time')
            if not timestamp:
                continue

            name = p.get('name', 'Unknown')
            pid = p.get('pid', 0)
            parent = p.get('parent_name', '')
            cmdline = p.get('cmdline', '')
            if isinstance(cmdline, list):
                cmdline = " ".join(cmdline)

            # Check if suspicious
            suspicious_names = ['powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'certutil', 'bitsadmin']
            is_risky = any(s in name.lower() for s in suspicious_names) or name.lower() in self.risky_artifacts

            self.events.append({
                "Timestamp": timestamp,
                "Type": "Process",
                "Source": f"PID {pid}",
                "Description": f"{name} (Parent: {parent}) | {str(cmdline)[:80]}",
                "Risky": is_risky
            })

        if "Process" not in self.type_filters:
            self.type_filters.append("Process")
        return self

    def add_prefetch(self, prefetch: List[Dict]):
        """Add prefetch execution events."""
        if not prefetch:
            return self

        for p in prefetch:
            timestamp = p.get('LastRun')
            if not timestamp:
                continue

            name = p.get('Name', '').replace('.pf', '')
            suspicious = ['POWERSHELL', 'CMD', 'WSCRIPT', 'CSCRIPT', 'MSHTA', 'CERTUTIL', 'PSEXEC']
            is_risky = any(s in name.upper() for s in suspicious)

            self.events.append({
                "Timestamp": timestamp,
                "Type": "Prefetch",
                "Source": "Execution",
                "Description": f"Executed: {name}",
                "Risky": is_risky
            })

        if "Prefetch" not in self.type_filters:
            self.type_filters.append("Prefetch")
        return self

    def add_userassist(self, userassist: List[Dict]):
        """Add UserAssist GUI execution events."""
        if not userassist:
            return self

        for u in userassist:
            timestamp = u.get('LastRun')
            if not timestamp or '1601-01-01' in str(timestamp):
                continue

            program = u.get('Program', '')
            run_count = u.get('RunCount', 0)

            self.events.append({
                "Timestamp": timestamp,
                "Type": "UserAssist",
                "Source": "GUI Exec",
                "Description": f"Launched: {program[:80]} (Count: {run_count})",
                "Risky": False
            })

        if "UserAssist" not in self.type_filters:
            self.type_filters.append("UserAssist")
        return self

    def add_lnk_files(self, lnk_files: List[Dict]):
        """Add LNK file access events."""
        if not lnk_files:
            return self

        for lnk in lnk_files:
            timestamp = lnk.get('LastAccess')
            if not timestamp:
                continue

            name = lnk.get('Name', '')
            target = lnk.get('Target', '')

            is_risky = any(kw in target.lower() for kw in ['temp', 'appdata', '.exe', '.ps1', '.bat'])

            self.events.append({
                "Timestamp": timestamp,
                "Type": "LNK",
                "Source": "Shortcut",
                "Description": f"{name} → {target[:60]}",
                "Risky": is_risky
            })

        if "LNK" not in self.type_filters:
            self.type_filters.append("LNK")
        return self

    def add_software_installs(self, software: List[Dict]):
        """Add software installation events."""
        if not software:
            return self

        for s in software:
            install_date = s.get('InstallDate')
            if not install_date or not s.get('DisplayName'):
                continue

            # Parse YYYYMMDD format
            try:
                if len(str(install_date)) == 8:
                    timestamp = datetime.strptime(str(install_date), '%Y%m%d')
                else:
                    continue
            except:
                continue

            name = s.get('DisplayName', 'Unknown')
            publisher = s.get('Publisher', 'Unknown')

            self.events.append({
                "Timestamp": timestamp,
                "Type": "Software",
                "Source": "Install",
                "Description": f"Installed: {name} ({publisher})",
                "Risky": False
            })

        if "Software" not in self.type_filters:
            self.type_filters.append("Software")
        return self

    def add_cookies(self, cookies: List[Dict]):
        """Add browser cookie events."""
        if not cookies:
            return self

        for c in cookies:
            timestamp = c.get('Created') or c.get('LastAccess')
            if not timestamp:
                continue

            domain = c.get('Host', c.get('Domain', 'Unknown'))
            name = c.get('Name', '')

            self.events.append({
                "Timestamp": timestamp,
                "Type": "Cookie",
                "Source": "Browser",
                "Description": f"Cookie: {domain} ({name[:30]})",
                "Risky": False
            })

        if "Cookie" not in self.type_filters:
            self.type_filters.append("Cookie")
        return self

    def add_shimcache(self, shimcache: List[Dict]):
        """Add Shimcache execution evidence."""
        if not shimcache:
            return self

        suspicious_paths = ['temp', 'appdata\\local\\temp', 'downloads', 'recycle', 'programdata']
        suspicious_names = ['mimikatz', 'psexec', 'procdump', 'lazagne', 'ncat', 'powercat', 'rubeus']

        for s in shimcache:
            # Shimcache doesn't have execution timestamp, use position as indicator
            path = s.get('path', '')
            if not path:
                continue

            filename = path.split('\\')[-1].lower() if '\\' in path else path.lower()
            is_risky = (
                any(p in path.lower() for p in suspicious_paths) or
                any(n in filename for n in suspicious_names)
            )

            self.events.append({
                "Timestamp": None,  # Shimcache has no timestamp
                "Type": "Shimcache",
                "Source": "Execution",
                "Description": f"Evidence: {path[:100]}",
                "Risky": is_risky,
                "NoTimestamp": True
            })

        if "Shimcache" not in self.type_filters:
            self.type_filters.append("Shimcache")
        return self

    def add_jump_lists(self, jump_lists: List[Dict]):
        """Add Jump List file access events."""
        if not jump_lists:
            return self

        for j in jump_lists:
            timestamp = j.get('AccessTime', j.get('access_time'))
            if not timestamp:
                continue

            path = j.get('TargetPath', j.get('target_path', j.get('path', '')))
            app = j.get('Application', j.get('application', 'Unknown'))

            is_risky = any(kw in str(path).lower() for kw in ['temp', '.exe', '.ps1', '.bat', '.vbs', 'downloads'])

            self.events.append({
                "Timestamp": timestamp,
                "Type": "JumpList",
                "Source": str(app)[:20],
                "Description": f"Accessed: {path[:80]}",
                "Risky": is_risky
            })

        if "JumpList" not in self.type_filters:
            self.type_filters.append("JumpList")
        return self

    def add_shellbags(self, shellbags: List[Dict]):
        """Add Shellbag folder access events."""
        if not shellbags:
            return self

        for s in shellbags:
            timestamp = s.get('AccessTime', s.get('access_time', s.get('last_accessed')))
            if not timestamp:
                continue

            path = s.get('Path', s.get('path', s.get('folder_path', '')))
            folder_type = s.get('FolderType', s.get('Source', ''))

            is_risky = any(kw in str(path).lower() for kw in ['temp', 'recycle', 'appdata', 'programdata'])

            self.events.append({
                "Timestamp": timestamp,
                "Type": "Shellbag",
                "Source": str(folder_type)[:15],
                "Description": f"Folder: {path[:80]}",
                "Risky": is_risky
            })

        if "Shellbag" not in self.type_filters:
            self.type_filters.append("Shellbag")
        return self

    def add_bits_jobs(self, bits: List[Dict]):
        """Add BITS transfer job events."""
        if not bits:
            return self

        for b in bits:
            timestamp = b.get('CreationTime')
            if not timestamp:
                continue

            name = b.get('DisplayName', 'Unknown') or 'Unknown'
            files = b.get('Files', '') or ''
            local = b.get('LocalFiles', '') or ''
            state = b.get('JobState', '') or ''

            # BITS downloads are always notable
            is_risky = any(ext in str(local).lower() for ext in ['.exe', '.dll', '.ps1', '.bat', '.msi'])

            self.events.append({
                "Timestamp": timestamp,
                "Type": "BITS",
                "Source": str(state),
                "Description": f"{name}: {str(files)[:60]} → {str(local)[:40]}",
                "Risky": is_risky or True  # BITS jobs are always notable
            })

        if "BITS" not in self.type_filters:
            self.type_filters.append("BITS")
        return self

    def add_scheduled_tasks(self, tasks: List[Dict]):
        """Add Scheduled Task events."""
        if not tasks:
            return self

        suspicious_actions = ['powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'certutil', 'bitsadmin', 'rundll32']

        for t in tasks:
            # Tasks don't have creation time in our data, skip timestamp
            name = t.get('TaskName', '') or ''
            action = t.get('Action', '') or ''
            state = t.get('State', '') or ''

            is_risky = any(s in str(action).lower() for s in suspicious_actions)

            self.events.append({
                "Timestamp": None,
                "Type": "Task",
                "Source": state,
                "Description": f"Task: {name} | {str(action)[:60]}",
                "Risky": is_risky,
                "NoTimestamp": True
            })

        if "Task" not in self.type_filters:
            self.type_filters.append("Task")
        return self

    def add_services(self, services: List[Dict]):
        """Add Service events."""
        if not services:
            return self

        suspicious_paths = ['temp', 'appdata', 'programdata', 'public']

        for s in services:
            name = s.get('Name', s.get('name', '')) or ''
            path = s.get('PathName', s.get('BinaryPathName', '')) or ''
            state = s.get('State', s.get('status', '')) or ''

            is_risky = any(p in str(path).lower() for p in suspicious_paths)

            self.events.append({
                "Timestamp": None,
                "Type": "Service",
                "Source": str(state),
                "Description": f"Service: {name} | {str(path)[:60]}",
                "Risky": is_risky,
                "NoTimestamp": True
            })

        if "Service" not in self.type_filters:
            self.type_filters.append("Service")
        return self

    def add_wmi_persistence(self, wmi: List[Dict]):
        """Add WMI persistence events."""
        if not wmi:
            return self

        for w in wmi:
            name = w.get('Name', 'Unknown') or 'Unknown'
            entry_type = w.get('Type', '') or ''
            command = w.get('Command', w.get('Query', '')) or ''

            # WMI persistence is always suspicious
            self.events.append({
                "Timestamp": None,
                "Type": "WMI",
                "Source": str(entry_type),
                "Description": f"WMI: {name} | {str(command)[:60]}",
                "Risky": True,
                "NoTimestamp": True
            })

        if "WMI" not in self.type_filters:
            self.type_filters.append("WMI")
        return self

    def add_startup_files(self, startup: List[Dict]):
        """Add Startup folder file events."""
        if not startup:
            return self

        dangerous_exts = ['.exe', '.bat', '.cmd', '.vbs', '.ps1', '.js', '.hta', '.scr']

        for s in startup:
            filename = s.get('Filename', s.get('filename', '')) or ''
            path = s.get('Path', s.get('path', '')) or ''
            modified = s.get('Modified', s.get('modified'))

            is_risky = any(str(filename).lower().endswith(ext) for ext in dangerous_exts)

            self.events.append({
                "Timestamp": modified,
                "Type": "Startup",
                "Source": "Persistence",
                "Description": f"Startup: {filename} | {str(path)[:50]}",
                "Risky": is_risky
            })

        if "Startup" not in self.type_filters:
            self.type_filters.append("Startup")
        return self

    def add_registry_persistence(self, registry: List[Dict]):
        """Add Registry Run key persistence events."""
        if not registry:
            return self

        suspicious_paths = ['temp', 'appdata', 'programdata', 'public', 'downloads']

        for r in registry:
            name = r.get('Name', r.get('name', '')) or ''
            value = r.get('Value', r.get('value', r.get('Data', ''))) or ''
            key_path = r.get('Key', r.get('key', '')) or ''

            is_risky = any(p in str(value).lower() for p in suspicious_paths)

            self.events.append({
                "Timestamp": None,
                "Type": "Registry",
                "Source": "Run Key",
                "Description": f"{name}: {str(value)[:70]}",
                "Risky": is_risky,
                "NoTimestamp": True
            })

        if "Registry" not in self.type_filters:
            self.type_filters.append("Registry")
        return self

    def add_browser_downloads(self, downloads: List[Dict]):
        """Add browser download events."""
        if not downloads:
            return self

        dangerous_exts = ['.exe', '.msi', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.hta', '.scr']

        for d in downloads:
            timestamp = d.get('StartTime', d.get('start_time', d.get('Time')))
            if not timestamp:
                continue

            filename = d.get('FilePath', d.get('filename', '')) or ''
            if '\\' in str(filename):
                filename = str(filename).split('\\')[-1]
            url = d.get('URL', d.get('url', '')) or ''

            is_risky = any(str(filename).lower().endswith(ext) for ext in dangerous_exts)

            self.events.append({
                "Timestamp": timestamp,
                "Type": "Download",
                "Source": "Browser",
                "Description": f"Downloaded: {filename} from {str(url)[:50]}",
                "Risky": is_risky
            })

        if "Download" not in self.type_filters:
            self.type_filters.append("Download")
        return self

    def add_network_connections(self, connections: List[Dict]):
        """Add network connection events."""
        if not connections:
            return self

        suspicious_ports = [4444, 5555, 6666, 1234, 31337, 8080, 8443, 9001]

        for c in connections:
            process = c.get('Process', c.get('name', 'Unknown')) or 'Unknown'
            raddr = c.get('raddr', '') or ''
            laddr = c.get('laddr', '') or ''
            status = c.get('status', '') or ''

            # Check for suspicious ports
            is_risky = False
            if raddr:
                try:
                    port = int(str(raddr).split(':')[-1]) if ':' in str(raddr) else 0
                    is_risky = port in suspicious_ports
                except:
                    pass

            self.events.append({
                "Timestamp": None,
                "Type": "Network",
                "Source": str(status),
                "Description": f"{process}: {laddr} → {raddr}",
                "Risky": is_risky,
                "NoTimestamp": True
            })

        if "Network" not in self.type_filters:
            self.type_filters.append("Network")
        return self

    def get_dataframe(self) -> pd.DataFrame:
        """Convert timeline events to a sorted DataFrame."""
        if not self.events:
            return pd.DataFrame()

        df = pd.DataFrame(self.events)
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
        df = df.dropna(subset=['Timestamp'])
        df = df.sort_values(by='Timestamp', ascending=False)
        return df

    def get_stats(self, df: pd.DataFrame) -> Dict:
        """Get timeline statistics."""
        if df.empty:
            return {}

        return {
            "total": len(df),
            "types": df['Type'].value_counts().to_dict(),
            "risky": len(df[df['Risky'] == True]),
            "time_range": (df['Timestamp'].min(), df['Timestamp'].max())
        }
