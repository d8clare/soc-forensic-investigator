"""
Deep Execution Evidence Tab - Professional Forensic Investigation View.
Displays UserAssist, Prefetch, LNK files, and PowerShell history with risk analysis.
"""
import os
import re

import streamlit as st
import pandas as pd

from core.data_loader import load_json, load_text_file, sanitize_dataframe, get_file_list
from core.risk_engine import RiskEngine


# Suspicious executables commonly used in attacks
SUSPICIOUS_EXECUTABLES = [
    'powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'certutil', 'bitsadmin',
    'regsvr32', 'rundll32', 'msiexec', 'psexec', 'wmic', 'net.exe', 'net1.exe',
    'schtasks', 'at.exe', 'reg.exe', 'sc.exe', 'taskkill', 'whoami', 'hostname',
    'systeminfo', 'ipconfig', 'netstat', 'arp', 'nslookup', 'ping', 'tracert',
    'mimikatz', 'procdump', 'lazagne', 'rubeus', 'sharphound', 'bloodhound'
]

# Suspicious PowerShell patterns
PS_SUSPICIOUS_PATTERNS = [
    (r'-enc\s', 'Encoded Command'),
    (r'-encodedcommand', 'Encoded Command'),
    (r'frombase64string', 'Base64 Decode'),
    (r'downloadstring', 'Download Cradle'),
    (r'downloadfile', 'File Download'),
    (r'invoke-webrequest', 'Web Request'),
    (r'iwr\s', 'Web Request (alias)'),
    (r'invoke-expression', 'Dynamic Execution'),
    (r'iex\s', 'Dynamic Execution (alias)'),
    (r'bypass', 'Execution Bypass'),
    (r'-exec\s+bypass', 'Execution Policy Bypass'),
    (r'-w\s+hidden', 'Hidden Window'),
    (r'-windowstyle\s+hidden', 'Hidden Window'),
    (r'new-object\s+net\.webclient', 'WebClient Object'),
    (r'start-process', 'Process Execution'),
    (r'invoke-mimikatz', 'Credential Theft'),
    (r'get-credential', 'Credential Access'),
    (r'converto-securestring', 'Secure String'),
    (r'add-type', 'Code Compilation'),
    (r'\[reflection\.assembly\]', 'Reflection Loading'),
]


def render(evidence_folder: str, risk_engine: RiskEngine):
    """Render the Deep Execution Evidence tab."""

    # Load all data first for stats
    ua_data = load_json(evidence_folder, "user_assist.json")
    pf_data = load_json(evidence_folder, "prefetch_list.json")
    lnk_data = load_json(evidence_folder, "lnk_files.json")
    shimcache_data = load_json(evidence_folder, "shimcache.json")

    # Analyze execution stats (cached)
    folder_name = os.path.basename(evidence_folder)
    exec_stats = analyze_execution_stats(ua_data, pf_data, lnk_data, shimcache_data, folder_name)

    total_ua = len(ua_data) if ua_data else 0
    total_pf = len(pf_data) if pf_data else 0
    total_lnk = len(lnk_data) if lnk_data else 0
    total_shimcache = len(shimcache_data) if shimcache_data else 0
    suspicious_count = exec_stats.get('suspicious', 0)

    # Simple header with blue styling
    st.markdown(f'<div style="color:#e6edf3;font-size:1.1rem;margin-bottom:15px;"><b>Execution</b> | Shimcache: {total_shimcache} | UserAssist: {total_ua} | Prefetch: {total_pf} | LNK: {total_lnk} | Suspicious: {suspicious_count}</div>', unsafe_allow_html=True)

    # Create subtabs
    tab_shim, tab_ua, tab_pf, tab_lnk, tab_ps = st.tabs([
        f"Shimcache ({total_shimcache})",
        f"UserAssist ({total_ua})",
        f"Prefetch ({total_pf})",
        f"LNK Files ({total_lnk})",
        "PowerShell"
    ])

    # Tab 1: Shimcache
    with tab_shim:
        render_shimcache_tab(shimcache_data, folder_name)

    # Tab 2: UserAssist
    with tab_ua:
        render_userassist_tab(ua_data, folder_name)

    # Tab 3: Prefetch
    with tab_pf:
        render_prefetch_tab(pf_data, folder_name)

    # Tab 4: LNK Files
    with tab_lnk:
        render_lnk_tab(lnk_data, folder_name)

    # Tab 5: PowerShell History
    with tab_ps:
        render_powershell_tab(evidence_folder)

    # Export section
    st.markdown("---")
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        if shimcache_data:
            df_export = pd.DataFrame(shimcache_data)
            st.download_button("💾 Shimcache", df_export.to_csv(index=False), "shimcache.csv", "text/csv", key="shim_export")
        else:
            st.button("💾 No Data", disabled=True, key="shim_export_disabled")

    with col2:
        if ua_data:
            df_export = pd.DataFrame(ua_data)
            st.download_button("👆 UserAssist", df_export.to_csv(index=False), "userassist.csv", "text/csv", key="ua_export")
        else:
            st.button("👆 No Data", disabled=True, key="ua_export_disabled")

    with col3:
        if pf_data:
            df_export = pd.DataFrame(pf_data)
            st.download_button("🚀 Prefetch", df_export.to_csv(index=False), "prefetch.csv", "text/csv", key="pf_export")
        else:
            st.button("🚀 No Data", disabled=True, key="pf_export_disabled")

    with col4:
        if lnk_data:
            df_export = pd.DataFrame(lnk_data)
            st.download_button("🔗 LNK Files", df_export.to_csv(index=False), "lnk_files.csv", "text/csv", key="lnk_export")
        else:
            st.button("🔗 No Data", disabled=True, key="lnk_export_disabled")


@st.cache_data
def analyze_execution_stats(ua_data, pf_data, lnk_data, shimcache_data=None, _folder_name: str = ""):
    """Analyze execution data for statistics. Cached for performance."""
    stats = {'suspicious': 0}

    # Check UserAssist
    if ua_data:
        for item in ua_data:
            program = str(item.get('Program', '')).lower()
            if any(s in program for s in SUSPICIOUS_EXECUTABLES):
                stats['suspicious'] += 1

    # Check Prefetch
    if pf_data:
        for item in pf_data:
            name = str(item.get('Name', '')).lower().replace('.pf', '')
            if any(s in name for s in SUSPICIOUS_EXECUTABLES):
                stats['suspicious'] += 1

    # Check LNK targets
    if lnk_data:
        for item in lnk_data:
            target = str(item.get('Target', '')).lower()
            if any(s in target for s in SUSPICIOUS_EXECUTABLES):
                stats['suspicious'] += 1
            if 'temp' in target or 'appdata' in target:
                stats['suspicious'] += 1

    # Check Shimcache
    if shimcache_data:
        suspicious_paths = ['temp', 'appdata\\local\\temp', 'recycle', 'programdata', 'downloads']
        for item in shimcache_data:
            path = str(item.get('path', '')).lower()
            if any(s in path for s in SUSPICIOUS_EXECUTABLES):
                stats['suspicious'] += 1
            elif any(p in path for p in suspicious_paths):
                stats['suspicious'] += 1

    return stats


@st.cache_data
def get_userassist_df_with_risk(ua_data, _folder_name: str = ""):
    """Create and cache UserAssist DataFrame with risk analysis applied."""
    if not ua_data:
        return pd.DataFrame()

    df = pd.DataFrame(ua_data)

    if 'LastRun' in df.columns:
        df['LastRun'] = pd.to_datetime(df['LastRun'], errors='coerce', format='ISO8601')

    def analyze_ua_risk(row):
        program = str(row.get('Program', '')).lower()
        run_count = row.get('RunCount', 0) or 0

        if any(s in program for s in SUSPICIOUS_EXECUTABLES[:15]):
            return "🔴 Suspicious"
        if any(s in program for s in SUSPICIOUS_EXECUTABLES[15:]):
            return "🟠 Recon Tool"
        if run_count > 50:
            return "🟡 High Usage"
        return "✅ Normal"

    df['Risk'] = df.apply(analyze_ua_risk, axis=1)

    # Pre-sort by risk
    risk_order = {"🔴 Suspicious": 0, "🟠 Recon Tool": 1, "🟡 High Usage": 2, "✅ Normal": 3}
    df['_sort'] = df['Risk'].map(risk_order).fillna(3)
    df = df.sort_values('_sort').drop('_sort', axis=1)

    return df


@st.cache_data
def get_prefetch_df_with_risk(pf_data, _folder_name: str = ""):
    """Create and cache Prefetch DataFrame with risk analysis applied."""
    if not pf_data:
        return pd.DataFrame()

    df = pd.DataFrame(pf_data)

    # Parse LastRun timestamp
    if 'LastRun' in df.columns:
        df['LastRun'] = pd.to_datetime(df['LastRun'], errors='coerce')

    def analyze_pf_risk(row):
        name = str(row.get('Name', '')).lower().replace('.pf', '')
        path = str(row.get('Path', '')).lower()

        if any(s in name for s in SUSPICIOUS_EXECUTABLES[:15]):
            return "🔴 Suspicious"
        if any(s in name for s in SUSPICIOUS_EXECUTABLES[15:]):
            return "🟠 Recon Tool"
        if 'temp' in path or 'appdata' in path:
            return "🟡 Unusual Path"
        return "✅ Normal"

    df['Risk'] = df.apply(analyze_pf_risk, axis=1)

    # Pre-sort by risk
    risk_order = {"🔴 Suspicious": 0, "🟠 Recon Tool": 1, "🟡 Unusual Path": 2, "✅ Normal": 3}
    df['_sort'] = df['Risk'].map(risk_order).fillna(3)
    df = df.sort_values('_sort').drop('_sort', axis=1)

    return df


@st.cache_data
def get_lnk_df_with_risk(lnk_data, _folder_name: str = ""):
    """Create and cache LNK files DataFrame with risk analysis applied."""
    if not lnk_data:
        return pd.DataFrame()

    df = pd.DataFrame(lnk_data)

    # Parse timestamps
    for col in ['LastAccess', 'Created', 'Modified']:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors='coerce')

    def analyze_lnk_risk(row):
        target = str(row.get('Target', '')).lower()
        args = str(row.get('Arguments', '')).lower()

        if any(s in target for s in SUSPICIOUS_EXECUTABLES[:15]):
            return "🔴 Suspicious"
        if any(s in args for s in ['-enc', 'bypass', 'hidden', 'downloadstring', 'frombase64']):
            return "🔴 Suspicious"
        if 'temp' in target or 'appdata\\local\\temp' in target:
            return "🟠 Unusual Path"
        return "✅ Normal"

    df['Risk'] = df.apply(analyze_lnk_risk, axis=1)

    # Pre-sort by risk
    risk_order = {"🔴 Suspicious": 0, "🟠 Unusual Path": 1, "✅ Normal": 2}
    df['_sort'] = df['Risk'].map(risk_order).fillna(3)
    df = df.sort_values('_sort').drop('_sort', axis=1)

    return df


@st.cache_data
def get_shimcache_df_with_risk(shimcache_data, _folder_name: str = ""):
    """Create and cache Shimcache DataFrame with risk analysis applied."""
    if not shimcache_data:
        return pd.DataFrame()

    df = pd.DataFrame(shimcache_data)

    # Parse timestamps
    if 'last_modified' in df.columns:
        df['last_modified'] = pd.to_datetime(df['last_modified'], errors='coerce')
    if 'modified' in df.columns:
        df['modified'] = pd.to_datetime(df['modified'], errors='coerce')

    suspicious_paths = ['temp', 'appdata\\local\\temp', 'recycle', 'programdata', 'downloads', 'users\\public']

    def analyze_shim_risk(row):
        path = str(row.get('path', '')).lower()
        filename = path.split('\\')[-1] if '\\' in path else path

        if any(s in filename for s in SUSPICIOUS_EXECUTABLES[:15]):
            return "🔴 Suspicious"
        if any(s in filename for s in SUSPICIOUS_EXECUTABLES[15:]):
            return "🟠 Recon Tool"
        if any(p in path for p in suspicious_paths):
            return "🟡 Unusual Path"
        return "✅ Normal"

    df['Risk'] = df.apply(analyze_shim_risk, axis=1)

    # Pre-sort by risk
    risk_order = {"🔴 Suspicious": 0, "🟠 Recon Tool": 1, "🟡 Unusual Path": 2, "✅ Normal": 3}
    df['_sort'] = df['Risk'].map(risk_order).fillna(3)
    df = df.sort_values('_sort').drop('_sort', axis=1)

    return df


def render_userassist_tab(ua_data, folder_name: str = ""):
    """Render the UserAssist subtab."""
    if not ua_data:
        st.info("No UserAssist data available.")
        return

    # Use cached DataFrame with pre-computed risk analysis (performance optimization)
    df = get_userassist_df_with_risk(ua_data, folder_name)
    if df.empty:
        st.info("No UserAssist data available.")
        return

    # Search and filter row
    col_search, col_filter = st.columns([3, 2])

    with col_search:
        search_ua = st.text_input("search_ua", placeholder="🔍 Search program name...", key="ua_search", label_visibility="collapsed")

    with col_filter:
        risk_filter = st.selectbox("ua_risk", ["All Programs", "Suspicious Only", "High Run Count (>10)"], key="ua_risk_filter", label_visibility="collapsed")

    # Apply filters on cached DataFrame
    filtered_df = df.copy()

    # Apply search filter
    if search_ua:
        search_lower = search_ua.lower()
        filtered_df = filtered_df[filtered_df['Program'].str.lower().str.contains(search_lower, na=False)]

    # Apply risk filter
    if risk_filter == "Suspicious Only":
        filtered_df = filtered_df[filtered_df['Risk'].str.contains("🔴|🟠", regex=True)]
    elif risk_filter == "High Run Count (>10)":
        filtered_df = filtered_df[filtered_df['RunCount'] > 10]

    df = filtered_df

    # DataFrame is already pre-sorted by risk in cache

    st.markdown(f'<div style="color:#888;font-size:0.8rem;margin:10px 0;">Showing {len(df)} UserAssist entries</div>', unsafe_allow_html=True)

    # Data table
    column_order = ["Risk", "Program", "RunCount", "LastRun"]

    st.dataframe(
        sanitize_dataframe(df),
        column_order=[c for c in column_order if c in df.columns],
        width="stretch",
        height=400,
        column_config={
            "Risk": st.column_config.TextColumn("Risk", width="small"),
            "Program": st.column_config.TextColumn("Program Path", width="large"),
            "RunCount": st.column_config.NumberColumn("Run Count", width="small"),
            "LastRun": st.column_config.DatetimeColumn("Last Executed", format="D/M/Y H:mm")
        },
        hide_index=True
    )

    # Analyst explanation
    with st.expander("📖 What is UserAssist?"):
        st.markdown("""
**UserAssist** is a Windows registry artifact that tracks programs launched via Windows Explorer (GUI).

| Field | Description |
|-------|-------------|
| **Program** | Path to the executed program (ROT13 encoded in registry) |
| **RunCount** | Number of times the program was launched |
| **LastRun** | Timestamp of the last execution |

**Forensic Value:**
- **User Activity**: Shows programs the user explicitly launched (clicked on)
- **Execution Count**: Indicates frequency of use
- **Timestamps**: Precise last execution time
- **User-Specific**: Each user has their own UserAssist data

**Key Points for Analysts:**
- Only tracks GUI launches (not command-line execution)
- Data is per-user (stored in NTUSER.DAT)
- ROT13 encoding is applied to paths in registry (decoded here)
- Focus time may also be recorded (time spent in foreground)

**Suspicious Indicators:**
- Execution of tools from temp/downloads folders
- Known hacking tools (mimikatz, psexec, etc.)
- Programs with suspicious names or paths

**MITRE ATT&CK:** T1204 (User Execution)

**Registry Location:** `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist`
        """)


def render_prefetch_tab(pf_data, folder_name: str = ""):
    """Render the Prefetch Cache subtab."""


    if not pf_data:
        st.info("No Prefetch data available.")
        return

    # Use cached DataFrame with pre-computed risk analysis (performance optimization)
    df = get_prefetch_df_with_risk(pf_data, folder_name)
    if df.empty:
        st.info("No Prefetch data available.")
        return

    # Search and filter row
    col_search, col_filter = st.columns([3, 2])

    with col_search:
        search_pf = st.text_input("search_pf", placeholder="🔍 Search executable name...", key="pf_search", label_visibility="collapsed")

    with col_filter:
        risk_filter = st.selectbox("pf_risk", ["All Executables", "Suspicious Only", "Recent (Last 7d)"], key="pf_risk_filter", label_visibility="collapsed")

    # Apply filters on cached DataFrame
    filtered_df = df.copy()

    # Apply search filter
    if search_pf:
        search_lower = search_pf.lower()
        filtered_df = filtered_df[filtered_df['Name'].str.lower().str.contains(search_lower, na=False)]

    # Apply risk filter
    if risk_filter == "Suspicious Only":
        filtered_df = filtered_df[filtered_df['Risk'].str.contains("🔴|🟠", regex=True)]
    elif risk_filter == "Recent (Last 7d)" and 'LastRun' in filtered_df.columns:
        cutoff = pd.Timestamp.now() - pd.Timedelta(days=7)
        filtered_df = filtered_df[filtered_df['LastRun'] >= cutoff]

    df = filtered_df

    # DataFrame is already pre-sorted by risk in cache

    st.markdown(f'<div style="color:#888;font-size:0.8rem;margin:10px 0;">Showing {len(df)} Prefetch entries</div>', unsafe_allow_html=True)

    # Data table
    column_order = ["Risk", "Name", "LastRun", "RunCount", "ExecutionCount", "Path"]

    st.dataframe(
        sanitize_dataframe(df),
        column_order=[c for c in column_order if c in df.columns],
        width="stretch",
        height=400,
        column_config={
            "Risk": st.column_config.TextColumn("Risk", width="small"),
            "Name": st.column_config.TextColumn("Executable", width="medium"),
            "LastRun": st.column_config.DatetimeColumn("Last Executed", format="D/M/Y H:mm"),
            "RunCount": st.column_config.NumberColumn("Runs", width="small"),
            "ExecutionCount": st.column_config.NumberColumn("Runs", width="small"),
            "Path": st.column_config.TextColumn("Path", width="large")
        },
        hide_index=True
    )

    # Analyst explanation
    with st.expander("📖 What is Prefetch?"):
        st.markdown("""
**Prefetch** is a Windows performance feature that caches program loading information to speed up subsequent launches.

| Field | Description |
|-------|-------------|
| **Name** | Executable name with hash (e.g., `CMD.EXE-89305D47.pf`) |
| **LastRun** | Last execution timestamp |
| **RunCount** | Total number of executions |
| **Path** | Location of the prefetch file |

**Forensic Value:**
- **Definitive Execution Proof**: Unlike Shimcache, Prefetch only exists if the program actually ran
- **Execution Count**: Shows how many times a program was executed
- **Last 8 Timestamps**: Recent versions store last 8 run times
- **Files/Directories Accessed**: Prefetch files contain lists of files the program loaded

**Key Points for Analysts:**
- Prefetch must be enabled (default on client Windows, disabled on servers)
- Limited to ~128 files (oldest are deleted)
- Hash in filename is based on path + command line
- Same program from different locations = different prefetch files

**Suspicious Indicators:**
- Prefetch for known attack tools
- Programs executed from unusual locations
- Single execution (RunCount=1) of suspicious tools

**MITRE ATT&CK:** T1059 (Command and Scripting Interpreter)

**Location:** `C:\\Windows\\Prefetch\\`
        """)


def render_lnk_tab(lnk_data, folder_name: str = ""):
    """Render the LNK Files subtab."""


    if not lnk_data:
        st.info("No LNK file data available.")
        return

    # Use cached DataFrame with pre-computed risk analysis (performance optimization)
    df = get_lnk_df_with_risk(lnk_data, folder_name)
    if df.empty:
        st.info("No LNK file data available.")
        return

    # Search and filter row
    col_search, col_filter = st.columns([3, 2])

    with col_search:
        search_lnk = st.text_input("search_lnk", placeholder="🔍 Search name or target...", key="lnk_search", label_visibility="collapsed")

    with col_filter:
        risk_filter = st.selectbox("lnk_risk", ["All Shortcuts", "Suspicious Only", "Temp/AppData Targets"], key="lnk_risk_filter", label_visibility="collapsed")

    # Apply filters on cached DataFrame
    filtered_df = df.copy()

    # Apply search filter
    if search_lnk:
        search_lower = search_lnk.lower()
        mask = filtered_df.astype(str).apply(lambda x: x.str.lower().str.contains(search_lower, na=False)).any(axis=1)
        filtered_df = filtered_df[mask]

    # Apply risk filter
    if risk_filter == "Suspicious Only":
        filtered_df = filtered_df[filtered_df['Risk'].str.contains("🔴|🟠", regex=True)]
    elif risk_filter == "Temp/AppData Targets":
        filtered_df = filtered_df[filtered_df['Target'].str.lower().str.contains('temp|appdata', na=False)]

    df = filtered_df

    st.markdown(f'<div style="color:#888;font-size:0.8rem;margin:10px 0;">Showing {len(df)} LNK files</div>', unsafe_allow_html=True)

    # Data table
    column_order = ["Risk", "Name", "Target", "Arguments", "LastAccess", "Created"]

    st.dataframe(
        sanitize_dataframe(df),
        column_order=[c for c in column_order if c in df.columns],
        width="stretch",
        height=400,
        column_config={
            "Risk": st.column_config.TextColumn("Risk", width="small"),
            "Name": st.column_config.TextColumn("Shortcut Name", width="medium"),
            "Target": st.column_config.TextColumn("Target Path", width="large"),
            "Arguments": st.column_config.TextColumn("Arguments", width="medium"),
            "LastAccess": st.column_config.DatetimeColumn("Last Access", format="D/M/Y H:mm"),
            "Created": st.column_config.DatetimeColumn("Created", format="D/M/Y H:mm")
        },
        hide_index=True
    )

    # Analyst explanation
    with st.expander("📖 What are LNK Files?"):
        st.markdown("""
**LNK Files (Windows Shortcuts)** are small files that point to other files, folders, or applications.

| Field | Description |
|-------|-------------|
| **Name** | Shortcut filename |
| **Target** | The actual file/program the shortcut points to |
| **Arguments** | Command-line arguments passed to the target |
| **Working Dir** | Directory where the target runs |
| **Created/Accessed** | Timestamps of the shortcut file |

**Forensic Value:**
- **File Access Evidence**: LNK files are created when files are opened
- **Deleted File References**: May point to files that no longer exist
- **Network Paths**: Can reveal access to network shares
- **Removable Media**: Evidence of USB/external drive access
- **Timeline**: Timestamps help establish user activity

**Key Points for Analysts:**
- Recent Items folder contains auto-generated LNK files
- LNK files persist even after target is deleted
- Contains metadata: target path, MAC times, volume serial, NetBIOS name
- Attackers may weaponize LNK files to execute malicious code

**Suspicious Indicators:**
- LNK targeting PowerShell/cmd with encoded commands
- Shortcuts to scripts in temp/appdata folders
- Hidden arguments or unusual working directories
- LNK files in startup folders

**MITRE ATT&CK:** T1547.009 (Shortcut Modification), T1204.002 (Malicious File)

**Common Locations:**
- `%APPDATA%\\Microsoft\\Windows\\Recent\\`
- `%APPDATA%\\Microsoft\\Windows\\Start Menu\\`
- Desktop folders
        """)


def render_powershell_tab(evidence_folder):
    """Render the PowerShell History subtab."""


    ps_dir = os.path.join(evidence_folder, "PowerShell_History")

    if not os.path.exists(ps_dir):
        st.info("No PowerShell History folder found.")
        return

    ps_files = get_file_list(ps_dir, ".txt")

    if not ps_files:
        st.info("PowerShell_History folder exists but is empty.")
        return

    # File selector
    selected_ps_file = st.selectbox("Select User History:", ps_files, key="ps_file_select")

    if not selected_ps_file:
        return

    content = load_text_file(ps_dir, selected_ps_file)

    if not content:
        st.warning("Could not read history file.")
        return

    # Analyze PowerShell commands
    lines = content.strip().split('\n')
    suspicious_commands = []
    all_commands = []

    for i, line in enumerate(lines):
        line_lower = line.lower().strip()
        if not line_lower:
            continue

        risk = "✅ Normal"
        findings = []

        for pattern, desc in PS_SUSPICIOUS_PATTERNS:
            if re.search(pattern, line_lower):
                findings.append(desc)

        if findings:
            if any(f in ['Encoded Command', 'Download Cradle', 'Credential Theft', 'Dynamic Execution'] for f in findings):
                risk = "🔴 High Risk"
            else:
                risk = "🟠 Suspicious"
            suspicious_commands.append({
                'Line': i + 1,
                'Command': line[:100],
                'Risk': risk,
                'Findings': ', '.join(findings)
            })

        all_commands.append({
            'Line': i + 1,
            'Command': line,
            'Risk': risk
        })

    # Stats
    total_commands = len(all_commands)
    suspicious_count = len(suspicious_commands)

    st.caption(f"Commands: {total_commands} | Suspicious: {suspicious_count}")

    # Search in history
    search_ps = st.text_input("search_ps", placeholder="🔍 Search commands...", key="ps_search", label_visibility="collapsed")

    # Filter view
    view_mode = st.radio("View", ["All Commands", "Suspicious Only"], horizontal=True, key="ps_view", label_visibility="collapsed")

    # Display commands
    if view_mode == "Suspicious Only":
        display_commands = suspicious_commands
    else:
        display_commands = all_commands

    # Apply search
    if search_ps:
        search_lower = search_ps.lower()
        display_commands = [c for c in display_commands if search_lower in c['Command'].lower()]

    if display_commands:
        df_ps = pd.DataFrame(display_commands)
        st.dataframe(
            df_ps,
            width="stretch",
            height=350,
            column_config={
                "Line": st.column_config.NumberColumn("#", width="small"),
                "Command": st.column_config.TextColumn("Command", width="large"),
                "Risk": st.column_config.TextColumn("Risk", width="small"),
                "Findings": st.column_config.TextColumn("Findings", width="medium")
            },
            hide_index=True
        )

    # Raw content expander
    with st.expander("📄 View Raw PowerShell History"):
        st.code(content, language="powershell")

    # Export
    st.download_button("💻 Export PowerShell History", content, f"powershell_history_{selected_ps_file}", "text/plain", key="ps_export")

    # Analyst explanation
    with st.expander("📖 What is PowerShell History?"):
        st.markdown("""
**PowerShell History (PSReadLine)** stores commands typed in PowerShell console sessions.

| Field | Description |
|-------|-------------|
| **Command** | The PowerShell command that was executed |
| **Line** | Line number in the history file |
| **Risk** | Assessed risk level based on suspicious patterns |
| **Findings** | Specific suspicious patterns detected |

**Forensic Value:**
- **Command Reconstruction**: See exactly what commands attackers ran
- **Lateral Movement**: Evidence of remote execution attempts
- **Data Exfiltration**: Download/upload commands
- **Persistence**: Commands that establish persistence
- **Reconnaissance**: System enumeration commands

**Suspicious Patterns to Look For:**
| Pattern | Indication |
|---------|------------|
| `-enc` / `-EncodedCommand` | Base64 encoded commands (evasion) |
| `DownloadString` / `DownloadFile` | Downloading payloads |
| `Invoke-Expression` / `IEX` | Dynamic code execution |
| `-ExecutionPolicy Bypass` | Bypassing security controls |
| `-WindowStyle Hidden` | Hidden execution |
| `Invoke-Mimikatz` | Credential theft |

**Key Points for Analysts:**
- History is per-user (stored in user profile)
- Default: last 4096 commands saved
- Not all PowerShell activity is logged here (scripts, remoting)
- Check Windows Event Logs for more complete logging (if enabled)

**MITRE ATT&CK:** T1059.001 (PowerShell), T1027 (Obfuscation)

**Location:** `%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt`
        """)


def render_shimcache_tab(shimcache_data, folder_name: str = ""):
    """Render the Shimcache subtab."""


    if not shimcache_data:
        st.info("No Shimcache data available. This artifact provides execution evidence even for deleted programs.")
        return

    # Use cached DataFrame with pre-computed risk analysis (performance optimization)
    df = get_shimcache_df_with_risk(shimcache_data, folder_name)
    if df.empty:
        st.info("No Shimcache data available.")
        return

    # Search and filter row
    col_search, col_filter = st.columns([3, 2])

    with col_search:
        search_shim = st.text_input("search_shim", placeholder="🔍 Search path or filename...", key="shim_search", label_visibility="collapsed")

    with col_filter:
        risk_filter = st.selectbox("shim_risk", ["All Entries", "Suspicious Only", "Temp/Downloads Locations"], key="shim_risk_filter", label_visibility="collapsed")

    # Apply filters on cached DataFrame
    filtered_df = df.copy()

    # Apply search filter
    if search_shim:
        search_lower = search_shim.lower()
        filtered_df = filtered_df[filtered_df['path'].str.lower().str.contains(search_lower, na=False)]

    # Apply risk filter
    if risk_filter == "Suspicious Only":
        filtered_df = filtered_df[filtered_df['Risk'].str.contains("🔴|🟠", regex=True)]
    elif risk_filter == "Temp/Downloads Locations":
        filtered_df = filtered_df[filtered_df['path'].str.lower().str.contains('temp|download|appdata', na=False)]

    df = filtered_df

    # DataFrame is already pre-sorted by risk in cache

    st.markdown(f'<div style="color:#888;font-size:0.8rem;margin:10px 0;">Showing {len(df)} Shimcache entries</div>', unsafe_allow_html=True)

    # Data table - show available columns (collector provides path and position)
    column_order = ["Risk", "position", "path", "last_modified", "modified", "executed", "execution_flag", "size"]

    st.dataframe(
        sanitize_dataframe(df),
        column_order=[c for c in column_order if c in df.columns],
        width="stretch",
        height=400,
        column_config={
            "Risk": st.column_config.TextColumn("Risk", width="small"),
            "position": st.column_config.NumberColumn("Position", width="small", help="Order in cache (lower = more recent)"),
            "path": st.column_config.TextColumn("Path", width="large"),
            "last_modified": st.column_config.DatetimeColumn("Last Modified", format="D/M/Y H:mm"),
            "modified": st.column_config.DatetimeColumn("Modified", format="D/M/Y H:mm"),
            "executed": st.column_config.CheckboxColumn("Executed", width="small"),
            "execution_flag": st.column_config.TextColumn("Exec Flag", width="small"),
            "size": st.column_config.NumberColumn("Size", width="small")
        },
        hide_index=True
    )

    # Analyst explanation
    with st.expander("📖 What is Shimcache?"):
        st.markdown("""
**Shimcache (Application Compatibility Cache)** is a Windows mechanism that tracks program execution for compatibility purposes.

| Field | Description |
|-------|-------------|
| **Path** | Full path to the executable that was shimmed |
| **Position** | Order in the cache (lower = more recent) |
| **Last Modified** | File modification time (NOT execution time) |

**Forensic Value:**
- **Evidence of Execution**: Programs appear in Shimcache when Windows checks compatibility, typically at execution
- **Deleted Programs**: Shows evidence of programs that have been deleted - the entry persists even if the file is gone
- **Timeline Analysis**: Helps establish what programs existed/ran on the system
- **Malware Detection**: Attackers often delete their tools, but Shimcache retains evidence

**Key Points for Analysts:**
- Entry does NOT guarantee execution (Windows may check compatibility without running)
- No execution timestamp - only file modification time is stored
- Survives reboots - data persists in registry
- Limited entries (~1024) - oldest entries are pushed out

**MITRE ATT&CK:** T1059 (Command and Scripting Interpreter)

**Registry Location:** `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache`
        """)
