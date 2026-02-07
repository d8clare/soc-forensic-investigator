"""
Process Intelligence Tab.
Displays process information with risk scoring, deep dive analysis, and process tree.
"""
import os
import streamlit as st
import pandas as pd
import re

from core.data_loader import load_json, sanitize_dataframe
from core.evidence_cache import get_evidence
from core.risk_engine import RiskEngine
from core.security import escape_html, safe_html_value, logger
from components.data_table import ForensicTable, create_virustotal_link
from config.theme import THEME


# MITRE ATT&CK Techniques for Process Analysis
MITRE_TECHNIQUES = {
    "T1059": {"name": "Command & Scripting Interpreter", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1059/"},
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion", "url": "https://attack.mitre.org/techniques/T1055/"},
    "T1036": {"name": "Masquerading", "tactic": "Defense Evasion", "url": "https://attack.mitre.org/techniques/T1036/"},
    "T1543": {"name": "Create/Modify System Process", "tactic": "Persistence", "url": "https://attack.mitre.org/techniques/T1543/"},
    "T1134": {"name": "Access Token Manipulation", "tactic": "Defense Evasion", "url": "https://attack.mitre.org/techniques/T1134/"},
}

# Suspicious process patterns
SUSPICIOUS_PROCESSES = {
    "lolbins": {
        "names": ["mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe",
                  "msiexec.exe", "wmic.exe", "cscript.exe", "wscript.exe", "installutil.exe",
                  "regasm.exe", "regsvcs.exe", "msbuild.exe", "cmstp.exe", "odbcconf.exe"],
        "risk": 40,
        "mitre": "T1218",
        "description": "Living-off-the-Land Binary"
    },
    "shells": {
        "names": ["cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe", "sh.exe"],
        "risk": 20,
        "mitre": "T1059",
        "description": "Command Shell"
    },
    "remote_tools": {
        "names": ["psexec.exe", "psexesvc.exe", "paexec.exe", "winexesvc.exe", "winrm.exe",
                  "wsmprovhost.exe", "schtasks.exe", "at.exe"],
        "risk": 50,
        "mitre": "T1021",
        "description": "Remote Execution Tool"
    },
    "credential_tools": {
        "names": ["mimikatz.exe", "procdump.exe", "lsass.exe", "sekurlsa.exe", "wce.exe",
                  "gsecdump.exe", "pwdump.exe", "cachedump.exe"],
        "risk": 80,
        "mitre": "T1003",
        "description": "Credential Access Tool"
    },
    "hacking_tools": {
        "names": ["nmap.exe", "nc.exe", "netcat.exe", "ncat.exe", "masscan.exe",
                  "hydra.exe", "medusa.exe", "john.exe", "hashcat.exe", "burp.exe"],
        "risk": 90,
        "mitre": "T1046",
        "description": "Hacking Tool"
    },
    "mining": {
        "names": ["xmrig.exe", "minerd.exe", "cgminer.exe", "bfgminer.exe", "ethminer.exe",
                  "phoenix.exe", "t-rex.exe", "nbminer.exe"],
        "risk": 70,
        "mitre": "T1496",
        "description": "Cryptocurrency Miner"
    }
}

# Suspicious command line patterns
SUSPICIOUS_CMDLINE_PATTERNS = [
    {"pattern": r"-enc\s+[A-Za-z0-9+/=]{50,}", "risk": 70, "desc": "Encoded PowerShell", "mitre": "T1059.001"},
    {"pattern": r"-nop\s+-w\s+hidden", "risk": 60, "desc": "Hidden PowerShell", "mitre": "T1059.001"},
    {"pattern": r"downloadstring|iex|invoke-expression", "risk": 70, "desc": "Download & Execute", "mitre": "T1059.001"},
    {"pattern": r"bypass|unrestricted|executionpolicy", "risk": 50, "desc": "Execution Policy Bypass", "mitre": "T1059.001"},
    {"pattern": r"\\AppData\\Local\\Temp\\[^\\]+\.exe", "risk": 60, "desc": "Temp Execution", "mitre": "T1204"},
    {"pattern": r"\\Users\\Public\\", "risk": 50, "desc": "Public Folder Execution", "mitre": "T1204"},
    {"pattern": r"http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "risk": 60, "desc": "IP-based URL", "mitre": "T1071"},
    {"pattern": r"net\s+(user|localgroup|group)\s+", "risk": 40, "desc": "User Enumeration", "mitre": "T1087"},
    {"pattern": r"reg\s+(add|delete|query)\s+.*run", "risk": 60, "desc": "Registry Run Key", "mitre": "T1547.001"},
    {"pattern": r"schtasks\s+/create", "risk": 50, "desc": "Scheduled Task Creation", "mitre": "T1053.005"},
    {"pattern": r"whoami\s*/priv", "risk": 30, "desc": "Privilege Check", "mitre": "T1033"},
    {"pattern": r"vssadmin.*shadows", "risk": 80, "desc": "Shadow Copy Manipulation", "mitre": "T1490"},
]

# Suspicious parent-child relationships
SUSPICIOUS_CHAINS = {
    "office_spawn_shell": {
        "parents": ["winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "onenote.exe", "msaccess.exe"],
        "children": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe"],
        "risk": 80,
        "mitre": "T1566.001",
        "description": "Office Application Spawning Shell"
    },
    "browser_spawn_shell": {
        "parents": ["chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe"],
        "children": ["cmd.exe", "powershell.exe", "mshta.exe"],
        "risk": 70,
        "mitre": "T1189",
        "description": "Browser Spawning Shell"
    },
    "explorer_spawn_script": {
        "parents": ["explorer.exe"],
        "children": ["wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe"],
        "risk": 50,
        "mitre": "T1204",
        "description": "Explorer Spawning Script Host"
    },
    "services_spawn_shell": {
        "parents": ["services.exe", "svchost.exe"],
        "children": ["cmd.exe", "powershell.exe"],
        "risk": 60,
        "mitre": "T1569.002",
        "description": "Service Spawning Shell"
    },
    "wmiprvse_spawn": {
        "parents": ["wmiprvse.exe"],
        "children": ["cmd.exe", "powershell.exe"],
        "risk": 70,
        "mitre": "T1047",
        "description": "WMI Execution"
    }
}


def analyze_process(proc: dict) -> dict:
    """Analyze a single process for suspicious indicators."""
    result = {
        "indicator": "✅",
        "risk_score": 0,
        "risk_level": "info",
        "findings": [],
        "mitre": []
    }

    name = str(proc.get("name", "")).lower()
    cmdline = str(proc.get("cmdline", "")).lower()
    parent_name = str(proc.get("parent_name", "")).lower()
    sig_status = proc.get("SignatureStatus", "Unknown")
    exe_path = str(proc.get("exe", "")).lower()

    # Check suspicious process names
    for category, data in SUSPICIOUS_PROCESSES.items():
        if any(n.lower() == name for n in data["names"]):
            result["risk_score"] += data["risk"]
            result["findings"].append(f"{data['description']}: {name}")
            if data["mitre"] not in result["mitre"]:
                result["mitre"].append(data["mitre"])

    # Check suspicious command line patterns
    for pattern_data in SUSPICIOUS_CMDLINE_PATTERNS:
        if re.search(pattern_data["pattern"], cmdline, re.IGNORECASE):
            result["risk_score"] += pattern_data["risk"]
            result["findings"].append(pattern_data["desc"])
            if pattern_data["mitre"] not in result["mitre"]:
                result["mitre"].append(pattern_data["mitre"])

    # Check suspicious parent-child relationships
    for chain_name, chain_data in SUSPICIOUS_CHAINS.items():
        if any(p in parent_name for p in chain_data["parents"]) and \
           any(c == name for c in chain_data["children"]):
            result["risk_score"] += chain_data["risk"]
            result["findings"].append(chain_data["description"])
            if chain_data["mitre"] not in result["mitre"]:
                result["mitre"].append(chain_data["mitre"])

    # Check signature status
    if sig_status != "Valid":
        result["risk_score"] += 30
        result["findings"].append(f"Unsigned/Invalid signature: {sig_status}")

    # Check for unusual paths
    if exe_path:
        suspicious_paths = ["\\temp\\", "\\tmp\\", "\\users\\public\\", "\\programdata\\",
                           "\\appdata\\local\\temp\\", "\\downloads\\"]
        if any(sp in exe_path for sp in suspicious_paths):
            result["risk_score"] += 30
            result["findings"].append("Executing from suspicious location")
            result["mitre"].append("T1204")

    # Check for masquerading (system process in wrong location)
    system_procs = ["svchost.exe", "csrss.exe", "lsass.exe", "services.exe", "smss.exe", "wininit.exe"]
    if name in system_procs and "\\windows\\system32\\" not in exe_path:
        result["risk_score"] += 80
        result["findings"].append(f"Potential masquerading: {name} outside System32")
        result["mitre"].append("T1036.005")

    # Set indicator and level based on score
    if result["risk_score"] >= 70:
        result["indicator"] = "🔴"
        result["risk_level"] = "critical"
    elif result["risk_score"] >= 50:
        result["indicator"] = "🟠"
        result["risk_level"] = "high"
    elif result["risk_score"] >= 30:
        result["indicator"] = "🟡"
        result["risk_level"] = "medium"
    elif result["risk_score"] > 0:
        result["indicator"] = "🔵"
        result["risk_level"] = "low"

    return result


def analyze_process_stats(df: pd.DataFrame) -> dict:
    """Analyze overall process statistics."""
    stats = {
        "total": len(df),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "unsigned": 0,
        "unique_users": 0,
        "suspicious_chains": [],
        "lolbins_found": []
    }

    if df.empty:
        return stats

    # Count by risk level
    if 'Risk Level' in df.columns:
        stats["critical"] = len(df[df['Risk Level'] == 'critical'])
        stats["high"] = len(df[df['Risk Level'] == 'high'])
        stats["medium"] = len(df[df['Risk Level'] == 'medium'])

    # Count unsigned
    if 'SignatureStatus' in df.columns:
        stats["unsigned"] = len(df[df['SignatureStatus'] != 'Valid'])

    # Unique users
    if 'username' in df.columns:
        stats["unique_users"] = df['username'].dropna().nunique()

    # Find LOLBins
    if 'name' in df.columns:
        for name in df['name'].dropna():
            name_lower = str(name).lower()
            if name_lower in [n.lower() for n in SUSPICIOUS_PROCESSES.get("lolbins", {}).get("names", [])]:
                if name not in stats["lolbins_found"]:
                    stats["lolbins_found"].append(name)

    return stats


def build_process_tree(df_proc: pd.DataFrame) -> dict:
    """
    Build a process tree structure from process data.

    Returns:
        Dictionary mapping parent_pid to list of child processes
    """
    tree = {}
    for _, row in df_proc.iterrows():
        parent_pid = row.get('parent_pid', 0)
        if parent_pid not in tree:
            tree[parent_pid] = []
        tree[parent_pid].append(row.to_dict())
    return tree


def get_node_icon(proc: dict) -> str:
    """Get icon based on process risk level."""
    risk_level = proc.get('Risk Level', 'info')
    sig_status = proc.get('SignatureStatus', 'Unknown')

    if risk_level == 'critical':
        return "🔴"
    elif risk_level == 'high':
        return "🟠"
    elif risk_level == 'medium':
        return "🟡"
    elif sig_status != 'Valid':
        return "⚠️"
    else:
        return "✅"


def build_tree_html(proc: dict, tree: dict, level: int = 0, lines: list = None) -> list:
    """Build tree as list of HTML lines with enhanced styling.

    All dynamic content is HTML-escaped to prevent XSS attacks.
    """
    if lines is None:
        lines = []

    pid = proc.get('pid', 0)
    # Escape process name to prevent XSS
    name = escape_html(proc.get('name', 'Unknown'))
    icon = get_node_icon(proc)
    risk_score = proc.get('Risk Score', 0)
    has_children = pid in tree and len(tree[pid]) > 0
    child_count = len(tree.get(pid, []))

    # Colors and backgrounds based on risk
    if risk_score >= 70:
        color = "#ff4444"
        bg = "rgba(255,68,68,0.1)"
        border = "#ff4444"
    elif risk_score >= 50:
        color = "#ff8c00"
        bg = "rgba(255,140,0,0.08)"
        border = "#ff8c00"
    elif risk_score >= 30:
        color = "#ffd700"
        bg = "rgba(255,215,0,0.06)"
        border = "#ffd700"
    else:
        color = "#8892b0"
        bg = "transparent"
        border = "transparent"

    # Tree connectors with better styling
    indent_html = ""
    for i in range(level):
        indent_html += '<span style="color:#3d4555;margin-right:2px">│</span><span style="width:12px;display:inline-block"></span>'

    connector = '<span style="color:#3d4555">├── </span>' if level > 0 else ''

    # Child count badge
    child_badge = ""
    if has_children:
        child_badge = f'<span style="background:#1e3a5f;color:#64b5f6;padding:1px 6px;border-radius:10px;font-size:10px;margin-left:8px">{child_count}</span>'

    # Build the line with hover effect styling
    line_style = f"padding:4px 8px;margin:1px 0;border-radius:4px;border-left:3px solid {border};background:{bg}"

    # All dynamic values are escaped
    lines.append(
        f'<div style="{line_style}">'
        f'{indent_html}{connector}'
        f'<span style="font-size:15px;margin-right:6px">{icon}</span>'
        f'<span style="color:{color};font-weight:600">{name}</span>'
        f'<span style="color:#5a6377;margin-left:8px;font-size:11px">PID: {escape_html(str(pid))}</span>'
        f'{child_badge}'
        f'</div>'
    )

    # Add all children
    if has_children:
        children = tree[pid]
        children_sorted = sorted(children, key=lambda x: x.get('Risk Score', 0), reverse=True)
        for child in children_sorted:
            build_tree_html(child, tree, level + 1, lines)

    return lines


@st.cache_data
def prepare_process_data(_procs: list, folder_name: str):
    """
    Prepare and analyze process data with caching.
    The folder_name is used as a cache key.
    """
    if not _procs:
        return None, None

    df_proc = pd.DataFrame(_procs)

    # Prepare command line field
    if 'cmdline' in df_proc.columns:
        df_proc['cmdline'] = df_proc['cmdline'].apply(
            lambda x: " ".join(x) if isinstance(x, list) else (str(x) if x else "")
        )

    # Analyze each process
    analysis_results = []
    for _, row in df_proc.iterrows():
        analysis = analyze_process(row.to_dict())
        analysis_results.append({
            'Indicator': analysis['indicator'],
            'Risk Score': analysis['risk_score'],
            'Risk Level': analysis['risk_level'],
            'Findings': '; '.join(analysis['findings'][:3]) if analysis['findings'] else ''
        })

    analysis_df = pd.DataFrame(analysis_results)
    df_proc = pd.concat([analysis_df, df_proc], axis=1)
    df_proc_sorted = df_proc.sort_values(by='Risk Score', ascending=False)

    # Calculate stats
    stats = analyze_process_stats(df_proc)

    return df_proc_sorted, stats


def render(evidence_folder: str, risk_engine: RiskEngine):
    """
    Render the Process Intelligence tab.

    Args:
        evidence_folder: Path to the evidence folder
        risk_engine: RiskEngine instance for risk scoring
    """
    procs = load_json(evidence_folder, "processes.json")

    if not procs:
        st.info("No process data available.")
        return

    # Use cached analysis
    folder_name = os.path.basename(evidence_folder)
    df_proc_sorted, stats = prepare_process_data(procs, folder_name)

    if df_proc_sorted is None:
        st.info("No process data available.")
        return

    df_proc = df_proc_sorted.copy()

    # Add VirusTotal links (not cached as it's just URL generation)
    if 'sha256' in df_proc.columns:
        df_proc['VirusTotal'] = df_proc['sha256'].apply(create_virustotal_link)

    # Simple header with blue styling
    st.markdown(f'<div style="color:#e6edf3;font-size:1.1rem;margin-bottom:15px;"><b>Processes</b> | Total: {stats["total"]:,} | Critical: {stats["critical"]} | High: {stats["high"]} | Unsigned: {stats["unsigned"]} | Users: {stats["unique_users"]}</div>', unsafe_allow_html=True)

    # Create subtabs
    p_sub_tabs = st.tabs(["Process Table", "Process Tree", "Deep Dive", "Suspicious"])

    # Tab 1: Main Process Table
    with p_sub_tabs[0]:
        render_process_table(df_proc_sorted)

    # Tab 2: Process Tree
    with p_sub_tabs[1]:
        render_process_tree(df_proc, df_proc_sorted)

    # Tab 3: Deep Dive Analysis
    with p_sub_tabs[2]:
        render_deep_dive(df_proc, df_proc_sorted, evidence_folder)

    # Tab 4: Suspicious Activity
    with p_sub_tabs[3]:
        render_suspicious_activity(df_proc)


def render_process_table(df_proc_sorted: pd.DataFrame):
    """Render the main process table."""
    st.subheader("All Running Processes")

    # Filter Section
    col1, col2, col3 = st.columns([2, 1, 1])

    with col1:
        search = st.text_input("🔍 Search Name / Command", placeholder="Enter keywords...", key="proc_search")

    with col2:
        risk_filter = st.selectbox("Risk Level", ['All', 'Critical', 'High', 'Medium', 'Low'], key="proc_risk")

    with col3:
        sig_filter = st.selectbox("Signature", ['All', 'Valid', 'Invalid/Unsigned'], key="proc_sig")

    df_display = df_proc_sorted.copy()

    # Apply filters
    if search:
        mask = df_display.astype(str).apply(
            lambda x: x.str.contains(search, case=False, na=False)
        ).any(axis=1)
        df_display = df_display[mask]

    if risk_filter != 'All':
        df_display = df_display[df_display['Risk Level'] == risk_filter.lower()]

    if sig_filter == 'Valid':
        df_display = df_display[df_display['SignatureStatus'] == 'Valid']
    elif sig_filter == 'Invalid/Unsigned':
        df_display = df_display[df_display['SignatureStatus'] != 'Valid']

    critical = df_display[df_display['Risk Level'].isin(['critical', 'high'])]

    # Display table
    column_order = [
        "Indicator", "Risk Score", "name", "pid", "parent_name", "parent_pid",
        "SignatureStatus", "Publisher", "username", "create_time",
        "exe", "cmdline", "Findings"
    ]

    existing_cols = [c for c in column_order if c in df_display.columns]
    vt_cols = ['VirusTotal'] if 'VirusTotal' in df_display.columns else []

    st.dataframe(
        sanitize_dataframe(df_display[existing_cols + vt_cols]),
        width="stretch",
        height=500,
        column_config={
            "Indicator": st.column_config.TextColumn("", width="small"),
            "Risk Score": st.column_config.NumberColumn("Risk", format="%d", width="small"),
            "parent_name": "Parent Name",
            "SignatureStatus": "Signature",
            "Publisher": "Signed By",
            "create_time": st.column_config.DatetimeColumn("Start Time", format="D/M/Y H:mm:ss"),
            "VirusTotal": st.column_config.LinkColumn("VT", display_text="Check"),
            "Findings": st.column_config.TextColumn("Findings", width="large")
        },
        hide_index=True
    )

    # Export
    st.markdown("---")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.caption(f"Showing {len(df_display):,} processes")
    with col2:
        csv = df_display.to_csv(index=False)
        st.download_button("📥 Export Filtered", csv, "processes_filtered.csv", "text/csv")
    with col3:
        if not critical.empty:
            crit_csv = critical.to_csv(index=False)
            st.download_button("🚨 Export High-Risk", crit_csv, "high_risk_processes.csv", "text/csv")


def render_process_tree(df_proc: pd.DataFrame, df_proc_sorted: pd.DataFrame):
    """Render the process tree view."""
    st.subheader("Process Tree View")

    # Build process tree
    tree = build_process_tree(df_proc)

    # Filter options
    col1, col2 = st.columns(2)
    with col1:
        root_options = ["All root processes"] + [f"{r['name']} (PID: {r['pid']})" for _, r in df_proc.head(50).iterrows()]
        root_filter = st.selectbox("Start from:", root_options, index=0, key="tree_root_filter")
    with col2:
        show_only_risky = st.checkbox("Risky branches only", value=False, key="tree_risky_only")

    # Find root processes
    all_pids = set(df_proc['pid'].tolist())

    if root_filter == "All root processes":
        root_procs = df_proc[~df_proc['parent_pid'].isin(all_pids)].to_dict('records')
    else:
        selected_pid = int(root_filter.split("PID: ")[1].rstrip(")"))
        root_procs = df_proc[df_proc['pid'] == selected_pid].to_dict('records')

    # Check if branch has risk
    def branch_has_risk(pid, checked=None):
        if checked is None:
            checked = set()
        if pid in checked:
            return False
        checked.add(pid)
        proc_row = df_proc[df_proc['pid'] == pid]
        if not proc_row.empty:
            if proc_row.iloc[0].get('Risk Score', 0) > 0:
                return True
        if pid in tree:
            for child in tree[pid]:
                if branch_has_risk(child['pid'], checked):
                    return True
        return False

    # Filter and sort roots
    if show_only_risky:
        root_procs = [r for r in root_procs if branch_has_risk(r['pid'])]

    if not root_procs:
        st.success("No suspicious process branches found." if show_only_risky else "No processes to display.")
        return

    root_procs_sorted = sorted(root_procs, key=lambda x: x.get('Risk Score', 0), reverse=True)

    # Build and render tree as single HTML block
    all_lines = []
    for root_proc in root_procs_sorted:
        build_tree_html(root_proc, tree, 0, all_lines)
        all_lines.append('<div style="height:8px"></div>')  # Spacing between trees

    tree_html = "".join(all_lines)
    st.markdown(
        f'''<div style="
            font-family: 'Cascadia Code', 'Fira Code', Consolas, monospace;
            font-size: 13px;
            padding: 20px;
            background: linear-gradient(135deg, #0d1117 0%, #161b22 100%);
            border-radius: 12px;
            border: 1px solid #30363d;
            max-height: 600px;
            overflow: auto;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        ">{tree_html}</div>''',
        unsafe_allow_html=True
    )

    # Stats bar
    total_procs = sum(len(tree.get(r['pid'], [])) + 1 for r in root_procs_sorted)
    st.markdown(
        f'<div style="display:flex;gap:20px;margin-top:10px;color:#8b949e;font-size:12px">'
        f'<span>📊 {len(root_procs_sorted)} root processes</span>'
        f'<span>🌳 {total_procs} total in tree</span>'
        f'</div>',
        unsafe_allow_html=True
    )


def render_deep_dive(df_proc: pd.DataFrame, df_proc_sorted: pd.DataFrame, evidence_folder: str):
    """Render the deep dive analysis tab."""
    st.subheader("Detailed Process Investigation")

    if df_proc.empty:
        st.info("No process data available.")
        return

    # Build PID set once (fast lookup)
    pid_set = set(df_proc_sorted['pid'].tolist())
    pid_list = list(pid_set)
    first_pid = df_proc_sorted['pid'].iloc[0] if not df_proc_sorted.empty else 0

    # Session state for investigation
    if 'investigated_pid' not in st.session_state:
        st.session_state.investigated_pid = first_pid

    # Ensure investigated_pid is valid
    if st.session_state.investigated_pid not in pid_set:
        st.session_state.investigated_pid = first_pid

    # Show current process info
    current_row = df_proc_sorted[df_proc_sorted['pid'] == st.session_state.investigated_pid]
    if not current_row.empty:
        curr = current_row.iloc[0]
        st.markdown(f"**Current:** {curr['Indicator']} `{curr['name']}` (PID: {curr['pid']}) - Risk: {curr['Risk Score']}")

    # PID navigation - simple text input with button
    col1, col2 = st.columns([2, 1])
    with col1:
        new_pid_str = st.text_input("Enter PID:", value=str(st.session_state.investigated_pid), key="pid_text_input")
        try:
            new_pid = int(new_pid_str)
            if new_pid in pid_set and new_pid != st.session_state.investigated_pid:
                if st.button("🔍 Go to PID", key="go_pid_btn"):
                    st.session_state.investigated_pid = new_pid
                    st.rerun()
        except ValueError:
            pass

    with col2:
        if st.button("🔴 Highest Risk", key="highest_risk_btn"):
            st.session_state.investigated_pid = first_pid
            st.rerun()

    # Get process details
    proc_match = df_proc[df_proc['pid'] == st.session_state.investigated_pid]
    if proc_match.empty:
        st.warning(f"PID {st.session_state.investigated_pid} not found. Showing first process.")
        st.session_state.investigated_pid = pid_list[0]
        proc_match = df_proc[df_proc['pid'] == st.session_state.investigated_pid]

    details = proc_match.iloc[0]
    current_pid = details['pid']
    st.divider()

    # Process header - all dynamic content is HTML-escaped
    risk_score = details['Risk Score']
    risk_color = "#ff4444" if risk_score >= 70 else "#ff8c00" if risk_score >= 50 else "#ffcc00" if risk_score >= 30 else "#00cc66"

    # Process header info
    detail_findings = str(details.get('Findings', 'No specific findings'))
    st.subheader(f"{details['Indicator']} {details['name']} (PID: {current_pid})")
    st.caption(f"Risk Score: {risk_score} | {detail_findings}")

    # Process details columns
    c1, c2 = st.columns(2)

    with c1:
        st.markdown("### Identification")
        st.markdown(f"**User:** `{details.get('username', 'Unknown')}`")

        # Parent process with navigation button
        p_name = details.get('parent_name', 'Unknown')
        p_pid = details.get('parent_pid', 0)

        # Convert to int safely
        try:
            p_pid_int = int(p_pid) if p_pid else 0
        except (ValueError, TypeError):
            p_pid_int = 0

        st.markdown(f"**Parent:** `{p_name}` (PID: {p_pid_int})")

        # Check if parent exists in process list (use pid_set from above)
        if p_pid_int > 0 and p_pid_int in pid_set:
            if st.button("⬆️ Go to Parent", key="goto_parent_btn"):
                st.session_state.investigated_pid = p_pid_int
                st.rerun()
        elif p_pid_int > 0:
            st.caption(f"Parent PID {p_pid_int} not in collected processes")

        st.markdown("**Executable Path:**")
        st.code(details.get('exe', 'Unknown'), language="text")

        st.markdown("**SHA256 Hash:**")
        if details.get('sha256'):
            st.code(details['sha256'], language="text")

    with c2:
        st.markdown("### Security Status")
        sig_status = details.get('SignatureStatus', 'Unknown')
        sig_color = "#00cc66" if sig_status == "Valid" else "#ff4444"
        st.markdown(f"**Signature:** <span style='color:{sig_color}; font-weight: bold;'>{sig_status}</span>",
                    unsafe_allow_html=True)
        st.markdown(f"**Publisher:** `{details.get('Publisher', 'Unknown')}`")
        st.markdown(f"**Start Time:** `{details.get('create_time', 'Unknown')}`")

        if details.get('VirusTotal'):
            st.link_button("🔗 Check on VirusTotal", details['VirusTotal'])

        # VirusTotal API enrichment
        if details.get('sha256'):
            if st.button("🔬 Deep Scan with VT API", key="vt_deep_scan"):
                try:
                    from core.threat_intel_api import ThreatIntelEnricher
                    from core.security import get_api_key

                    # Load API key from secure storage
                    vt_key = get_api_key('virustotal_api_key') or ''

                    enricher = ThreatIntelEnricher(vt_api_key=vt_key)

                    if enricher.vt.is_configured():
                        with st.spinner("Querying VirusTotal..."):
                            result = enricher.enrich_hash(details['sha256'])

                        if result:
                            det_color = "#28a745" if not result.detected else "#ff6b6b"
                            st.markdown(f'''<div style="background:#1e1e2e;border-radius:8px;padding:15px;margin-top:10px;">
<div style="display:flex;justify-content:space-between;align-items:center;">
<div style="font-weight:bold;color:white;">VirusTotal Result</div>
<div style="background:{det_color};color:white;padding:3px 12px;border-radius:15px;font-size:0.85rem;">{result.detection_ratio}</div>
</div>
{"<div style='color:#ff6b6b;margin-top:10px;font-size:0.85rem;'>Detected as: " + ", ".join(result.malware_names[:3]) + "</div>" if result.malware_names else ""}
</div>''', unsafe_allow_html=True)
                        else:
                            st.info("File not found in VirusTotal database")
                    else:
                        st.warning("VirusTotal API key not configured. Add via Settings.")
                except Exception as e:
                    st.error(f"Error: {str(e)}")

    st.divider()

    # Child processes
    st.markdown("### Child Processes")
    children = df_proc[df_proc['parent_pid'] == current_pid]
    if not children.empty:
        st.info(f"This process has {len(children)} child process(es)")
        # Display as a simple table instead of buttons
        child_data = []
        for idx, child in children.iterrows():
            child_data.append({
                "Indicator": child.get('Indicator', '✅'),
                "Name": child.get('name', ''),
                "PID": child.get('pid', ''),
                "Risk": child.get('Risk Score', 0),
                "Command": str(child.get('cmdline', ''))
            })
        st.dataframe(pd.DataFrame(child_data), width="stretch", hide_index=True)
        st.caption("Select a child process from the dropdown above to investigate.")
    else:
        st.caption("No child processes.")

    st.divider()

    # Network Activity
    st.markdown("### Network Activity")

    # Load network data using cached evidence
    net_data = get_evidence(evidence_folder, "network")
    df_net_all = pd.DataFrame(net_data) if net_data else pd.DataFrame()

    if not df_net_all.empty and 'pid' in df_net_all.columns:
        proc_net = df_net_all[df_net_all['pid'] == current_pid]
        if not proc_net.empty:
            st.warning(f"Found {len(proc_net)} active network connections!")
            display_cols = ['laddr', 'raddr', 'status']
            display_cols = [c for c in display_cols if c in proc_net.columns]
            st.dataframe(
                sanitize_dataframe(proc_net[display_cols]),
                width="stretch",
                hide_index=True
            )
        else:
            st.success("No active network connections found.")
    else:
        st.info("No network data available.")

    st.divider()

    # Command Line
    st.markdown("### Full Command Line")
    st.code(details.get('cmdline', 'No command line available'), language="powershell")

    # Loaded Modules
    if 'loaded_modules' in details and details['loaded_modules']:
        modules = details['loaded_modules']
        if isinstance(modules, str):
            try:
                import ast
                modules = ast.literal_eval(modules)
            except (ValueError, SyntaxError):
                modules = []

        if modules:
            with st.expander(f"📚 Loaded Modules / DLLs ({len(modules)})"):
                st.dataframe(
                    pd.DataFrame(modules, columns=["Module Path"]),
                    width="stretch"
                )

    # Process Behavior - Related Files and Registry (load on demand)
    st.divider()
    with st.expander("📁 Related Files & Artifacts", expanded=False):
        exe_path = str(details.get('exe', '')).lower()
        proc_name = str(details.get('name', '')).lower()

        # Extract process directory
        proc_dir = ""
        if exe_path:
            proc_dir = exe_path.rsplit('\\', 1)[0] if '\\' in exe_path else exe_path.rsplit('/', 1)[0]

        # Load and search related files
        files_data = get_evidence(evidence_folder, "recent_files") or []
        related_files = []
        if files_data and proc_dir:
            for f in files_data[:500]:  # Limit search
                fpath = str(f.get('path', '')).lower()
                fname = str(f.get('filename', '')).lower()
                if proc_dir in fpath or proc_name.replace('.exe', '') in fname:
                    related_files.append({
                        "File": f.get('filename', ''),
                        "Path": f.get('path', '')[:80],
                        "Modified": f.get('modified', '')
                    })
                    if len(related_files) >= 20:
                        break

        if related_files:
            st.markdown(f"**📄 Related Files ({len(related_files)})**")
            st.dataframe(pd.DataFrame(related_files), width="stretch", hide_index=True)
        else:
            st.caption("No related files found.")

        # Shimcache
        shimcache_data = get_evidence(evidence_folder, "shimcache") or []
        shimcache_entries = []
        for entry in shimcache_data[:200]:
            epath = str(entry.get('path', '')).lower()
            if proc_name in epath:
                shimcache_entries.append({
                    "Path": entry.get('path', ''),
                    "Last Modified": entry.get('last_modified', '')
                })
                if len(shimcache_entries) >= 10:
                    break

        if shimcache_entries:
            st.markdown(f"**📜 Shimcache History ({len(shimcache_entries)})**")
            st.dataframe(pd.DataFrame(shimcache_entries), width="stretch", hide_index=True)

        # Startup persistence
        startup_data = get_evidence(evidence_folder, "startup") or []
        startup_entries = []
        for entry in startup_data:
            epath = str(entry.get('Path', entry.get('path', ''))).lower()
            ename = str(entry.get('Filename', entry.get('filename', ''))).lower()
            if proc_name in epath or proc_name in ename:
                startup_entries.append({
                    "Name": entry.get('Filename', entry.get('filename', '')),
                    "Path": entry.get('Path', entry.get('path', ''))
                })

        if startup_entries:
            st.warning("⚠️ This process has startup persistence!")
            st.dataframe(pd.DataFrame(startup_entries), width="stretch", hide_index=True)


def render_suspicious_activity(df_proc: pd.DataFrame):
    """Render the suspicious activity tab."""
    st.subheader("Suspicious Process Activity")

    # Suspicious chains detection
    st.markdown("### 🔗 Suspicious Process Chains")

    suspicious_chains = []

    for _, proc in df_proc.iterrows():
        parent_name = str(proc.get('parent_name', '')).lower()
        proc_name = str(proc.get('name', '')).lower()

        for chain_name, chain_data in SUSPICIOUS_CHAINS.items():
            if any(p in parent_name for p in chain_data["parents"]) and \
               any(c == proc_name for c in chain_data["children"]):
                suspicious_chains.append({
                    "Type": chain_data["description"],
                    "MITRE": chain_data["mitre"],
                    "Parent": proc.get('parent_name'),
                    "Parent PID": proc.get('parent_pid'),
                    "Child": proc.get('name'),
                    "Child PID": proc.get('pid'),
                    "Risk": chain_data["risk"],
                    "Command": str(proc.get('cmdline', ''))
                })

    if suspicious_chains:
        st.error(f"Found {len(suspicious_chains)} suspicious process chain(s) - check table above for details.")
    else:
        st.success("No suspicious process chains detected.")

    st.markdown("---")

    # LOLBins analysis
    st.markdown("### 🔧 Living-off-the-Land Binaries (LOLBins)")

    lolbins_found = []
    for _, proc in df_proc.iterrows():
        name = str(proc.get('name', '')).lower()
        if name in [n.lower() for n in SUSPICIOUS_PROCESSES.get("lolbins", {}).get("names", [])]:
            lolbins_found.append({
                "Name": proc.get('name'),
                "PID": proc.get('pid'),
                "User": proc.get('username'),
                "Command": str(proc.get('cmdline', '')),
                "Parent": proc.get('parent_name')
            })

    if lolbins_found:
        st.warning(f"Found {len(lolbins_found)} LOLBin(s) running!")
        st.dataframe(pd.DataFrame(lolbins_found), width="stretch", hide_index=True)
    else:
        st.success("No LOLBins detected.")

    st.markdown("---")

    # Unsigned processes
    st.markdown("### ⚠️ Unsigned/Invalid Signature Processes")

    unsigned = df_proc[df_proc['SignatureStatus'] != 'Valid']
    if not unsigned.empty:
        st.warning(f"Found {len(unsigned)} unsigned or invalid signature process(es)")

        display_cols = ['Indicator', 'name', 'pid', 'SignatureStatus', 'exe', 'username']
        existing = [c for c in display_cols if c in unsigned.columns]

        st.dataframe(
            unsigned[existing].head(20),
            width="stretch",
            hide_index=True
        )
    else:
        st.success("All processes have valid signatures.")

    # Export suspicious findings
    st.markdown("---")
    if suspicious_chains or lolbins_found or not unsigned.empty:
        findings = {
            "suspicious_chains": suspicious_chains,
            "lolbins": lolbins_found,
            "unsigned_count": len(unsigned)
        }
        import json
        st.download_button(
            "📥 Export Suspicious Findings",
            json.dumps(findings, indent=2, default=str),
            "suspicious_processes.json",
            "application/json"
        )
