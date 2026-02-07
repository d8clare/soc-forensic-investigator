"""
Persistence & Auto-Start Analysis Tab - Professional Forensic Investigation View.
Displays registry autoruns, scheduled tasks, and services with risk analysis.
"""
import os
import streamlit as st
import pandas as pd

from core.data_loader import load_json, sanitize_dataframe
from core.evidence_cache import get_evidence
from core.risk_engine import RiskEngine
from components.ui_components import info_banner, no_data_message


# Risk indicators for dark mode compatibility
RISK_INDICATORS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "normal": "⚪"
}

# MITRE ATT&CK Persistence Techniques
MITRE_TECHNIQUES = {
    "registry": {"id": "T1547", "name": "Boot or Logon Autostart Execution"},
    "tasks": {"id": "T1053", "name": "Scheduled Task/Job"},
    "services": {"id": "T1543", "name": "Create or Modify System Process"},
    "wmi": {"id": "T1546.003", "name": "WMI Event Subscription"},
    "startup": {"id": "T1547.001", "name": "Startup Folder"}
}


def render(evidence_folder: str, risk_engine: RiskEngine):
    """Render the Persistence Analysis tab."""

    # Load all data first for stats
    reg_data = load_json(evidence_folder, "registry_autoruns.json")
    tasks_data = load_json(evidence_folder, "scheduled_tasks.json")
    services_data = load_json(evidence_folder, "services_list.json")
    wmi_data = load_json(evidence_folder, "wmi_persistence.json")
    startup_data = load_json(evidence_folder, "startup_files.json")

    # Analyze all items for stats (all cached for performance)
    folder_name = os.path.basename(evidence_folder)
    reg_risks = analyze_all_registry(reg_data, folder_name) if reg_data else []
    task_risks = analyze_all_tasks(tasks_data, folder_name) if tasks_data else []
    service_risks = analyze_all_services(services_data, folder_name) if services_data else []
    wmi_risks = analyze_all_wmi(wmi_data, folder_name) if wmi_data else []
    startup_risks = analyze_all_startup(startup_data, folder_name) if startup_data else []

    # Count risks
    all_risks = reg_risks + task_risks + service_risks + wmi_risks + startup_risks
    critical_count = sum(1 for r in all_risks if "Critical" in r or "🔴" in r)
    high_count = sum(1 for r in all_risks if "Suspicious" in r or "High" in r or "🟠" in r)
    medium_count = sum(1 for r in all_risks if "Medium" in r or "Obfuscated" in r or "🟡" in r)
    normal_count = len(all_risks) - critical_count - high_count - medium_count

    total_items = len(reg_data or []) + len(tasks_data or []) + len(services_data or []) + len(wmi_data or []) + len(startup_data or [])

    # Simple header with blue styling
    st.markdown(f'<div style="color:#e6edf3;font-size:1.1rem;margin-bottom:15px;"><b>Persistence</b> | Total: {total_items} | Critical: {critical_count} | Suspicious: {high_count}</div>', unsafe_allow_html=True)

    # Create subtabs
    p_tabs = st.tabs([
        f"Registry ({len(reg_data or [])})",
        f"Tasks ({len(tasks_data or [])})",
        f"Services ({len(services_data or [])})",
        f"WMI ({len(wmi_data or [])})",
        f"Startup ({len(startup_data or [])})"
    ])

    # Tab 1: Registry Autoruns
    with p_tabs[0]:
        render_registry_tab(reg_data, folder_name)

    # Tab 2: Scheduled Tasks
    with p_tabs[1]:
        render_tasks_tab(tasks_data, folder_name)

    # Tab 3: Services Analysis
    with p_tabs[2]:
        render_services_tab(services_data, folder_name)

    # Tab 4: WMI Persistence
    with p_tabs[3]:
        render_wmi_tab(wmi_data, folder_name)

    # Tab 5: Startup Folders
    with p_tabs[4]:
        render_startup_tab(startup_data, folder_name)

    # Export section
    st.markdown("---")

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        if reg_data:
            df_export = pd.DataFrame(reg_data)
            st.download_button("📋 Registry", df_export.to_csv(index=False), "registry_autoruns.csv", "text/csv", key="persist_reg")
        else:
            st.button("📋 No Data", disabled=True, key="persist_reg_disabled")

    with col2:
        if tasks_data:
            df_export = pd.DataFrame(tasks_data)
            st.download_button("⏰ Tasks", df_export.to_csv(index=False), "scheduled_tasks.csv", "text/csv", key="persist_tasks")
        else:
            st.button("⏰ No Data", disabled=True, key="persist_tasks_disabled")

    with col3:
        if services_data:
            df_export = pd.DataFrame(services_data)
            st.download_button("⚙️ Services", df_export.to_csv(index=False), "services.csv", "text/csv", key="persist_services")
        else:
            st.button("⚙️ No Data", disabled=True, key="persist_services_disabled")

    with col4:
        if wmi_data:
            df_export = pd.DataFrame(wmi_data)
            st.download_button("🔗 WMI", df_export.to_csv(index=False), "wmi_persistence.csv", "text/csv", key="persist_wmi")
        else:
            st.button("🔗 No Data", disabled=True, key="persist_wmi_disabled")

    with col5:
        if startup_data:
            df_export = pd.DataFrame(startup_data)
            st.download_button("📂 Startup", df_export.to_csv(index=False), "startup_files.csv", "text/csv", key="persist_startup")
        else:
            st.button("📂 No Data", disabled=True, key="persist_startup_disabled")


@st.cache_data
def analyze_all_registry(reg_data, _folder_name: str = ""):
    """Analyze all registry items and return risk list. Cached for performance."""
    if not reg_data:
        return []
    risks = []
    critical_indicators = ['powershell', 'cmd.exe', 'mshta', 'wscript', 'cscript', 'certutil', 'bitsadmin', 'regsvr32']
    suspicious_indicators = ['.ps1', '.bat', '.vbs', 'temp', 'appdata', 'programdata']

    for item in reg_data:
        value = str(item.get('Value', '')).lower()
        path = str(item.get('Path', '')).lower()

        if any(x in value for x in critical_indicators):
            risks.append("🔴 Critical")
        elif any(x in value for x in suspicious_indicators) or 'temp' in path:
            risks.append("🟠 Suspicious")
        else:
            risks.append("⚪ Normal")
    return risks


@st.cache_data
def get_registry_df_with_risk(reg_data, _folder_name: str = ""):
    """Create and cache registry DataFrame with risk analysis applied."""
    if not reg_data:
        return pd.DataFrame()

    df = pd.DataFrame(reg_data)

    # Pre-compute risk column
    critical_indicators = ['powershell', 'cmd.exe', 'mshta', 'wscript', 'cscript', 'certutil', 'bitsadmin', 'regsvr32']
    suspicious_indicators = ['.ps1', '.bat', '.vbs', 'temp', 'appdata', 'programdata']

    def analyze_reg_risk(row):
        value = str(row.get('Value', '')).lower()
        path = str(row.get('Path', '')).lower()

        if any(x in value for x in critical_indicators):
            return "🔴 Critical"
        if any(x in value for x in suspicious_indicators) or 'temp' in path:
            return "🟠 Suspicious"
        return "⚪ Normal"

    df['Risk'] = df.apply(analyze_reg_risk, axis=1)

    # Pre-sort by risk
    risk_order = {"🔴 Critical": 0, "🟠 Suspicious": 1, "🟡 Medium": 2, "⚪ Normal": 3}
    df['_sort'] = df['Risk'].map(risk_order)
    df = df.sort_values('_sort').drop('_sort', axis=1)

    return df


@st.cache_data
def analyze_all_tasks(tasks_data, _folder_name: str = ""):
    """Analyze all scheduled tasks and return risk list. Cached for performance."""
    if not tasks_data:
        return []
    risks = []
    for task in tasks_data:
        action = str(task.get('Action', '')).lower()
        name = str(task.get('TaskName', '')).lower()

        if any(x in action for x in ['powershell', 'cmd.exe', 'bitsadmin', 'mshta', 'wscript', 'cscript', 'certutil']):
            risks.append("🔴 Critical")
        elif name.startswith('{') and len(name) > 30:
            risks.append("🟠 Suspicious")
        elif any(x in action for x in ['.ps1', '.bat', '.vbs', 'temp', 'appdata']):
            risks.append("🟡 Medium")
        else:
            risks.append("⚪ Normal")
    return risks


@st.cache_data
def analyze_all_services(services_data, _folder_name: str = ""):
    """Analyze all services and return risk list. Cached for performance."""
    if not services_data:
        return []
    risks = []
    suspicious_paths = ['temp', 'appdata', 'programdata', 'users\\public', 'recycle']
    suspicious_names = ['svchost', 'csrss', 'lsass', 'services', 'winlogon']

    for service in services_data:
        path = str(service.get('PathName', service.get('BinaryPathName', ''))).lower()
        name = str(service.get('Name', '')).lower()
        start_type = str(service.get('StartMode', service.get('StartType', ''))).lower()

        # Check for services running from suspicious paths
        if any(x in path for x in suspicious_paths):
            risks.append("🔴 Critical")
        # Check for name masquerading (common system service names in wrong location)
        elif any(n in name for n in suspicious_names) and 'system32' not in path:
            risks.append("🟠 Suspicious")
        elif start_type == 'auto' and 'system32' not in path and 'program files' not in path:
            risks.append("🟡 Medium")
        else:
            risks.append("⚪ Normal")
    return risks


@st.cache_data
def get_services_df_with_risk(services_data, _folder_name: str = ""):
    """Create and cache services DataFrame with risk analysis applied."""
    if not services_data:
        return pd.DataFrame()

    df = pd.DataFrame(services_data)

    critical_indicators = ['powershell', 'cmd.exe', 'mshta', 'wscript', 'cscript', 'temp\\', 'appdata\\']
    suspicious_indicators = ['.ps1', '.bat', '.vbs', 'programdata']

    def analyze_service_risk(row):
        bin_path = str(row.get('BinPath', row.get('PathName', row.get('BinaryPathName', '')))).lower()
        name = str(row.get('Name', '')).lower()

        if any(x in bin_path for x in critical_indicators):
            return "🔴 High Risk"
        if any(x in bin_path for x in suspicious_indicators):
            return "🟠 Suspicious"
        if name.startswith('{') or (len(name) > 20 and name.isalnum()):
            return "🟠 Suspicious"
        return "⚪ Normal"

    df['Risk'] = df.apply(analyze_service_risk, axis=1)

    # Pre-sort by risk
    risk_order = {"🔴 High Risk": 0, "🟠 Suspicious": 1, "⚪ Normal": 2}
    df['_sort'] = df['Risk'].map(risk_order).fillna(3)
    df = df.sort_values('_sort').drop('_sort', axis=1)

    return df


@st.cache_data
def get_tasks_df_with_risk(tasks_data, _folder_name: str = ""):
    """Create and cache tasks DataFrame with risk analysis applied."""
    if not tasks_data:
        return pd.DataFrame()

    df = pd.DataFrame(tasks_data)

    critical_indicators = ['powershell', 'cmd.exe', 'bitsadmin', 'mshta', 'wscript', 'cscript', 'certutil', 'regsvr32']
    suspicious_indicators = ['.ps1', '.bat', '.vbs', 'temp', 'appdata', 'programdata']

    def analyze_task_risk(row):
        action = str(row.get('Action', '')).lower()
        name = str(row.get('TaskName', '')).lower()

        if any(x in action for x in critical_indicators):
            return "🔴 Critical"
        if name.startswith('{') and len(name) > 30:
            return "🟠 Obfuscated Name"
        if any(x in action for x in suspicious_indicators):
            return "🟠 Suspicious"
        if 'hidden' in action or '-w hidden' in action or '-windowstyle hidden' in action:
            return "🔴 Critical"
        return "⚪ Normal"

    df['Risk'] = df.apply(analyze_task_risk, axis=1)

    # Pre-sort by risk
    risk_order = {"🔴 Critical": 0, "🟠 Obfuscated Name": 1, "🟠 Suspicious": 1, "🟡 Medium": 2, "⚪ Normal": 3}
    df['_sort'] = df['Risk'].map(risk_order)
    df = df.sort_values('_sort').drop('_sort', axis=1)

    return df


@st.cache_data
def analyze_all_wmi(wmi_data, _folder_name: str = ""):
    """Analyze all WMI subscriptions and return risk list. Cached for performance."""
    if not wmi_data:
        return []
    risks = []
    for entry in wmi_data:
        # Use actual collector field names: Type, Name, Query, Command
        entry_type = str(entry.get('Type', '')).lower()
        command = str(entry.get('Command', '') or entry.get('Query', '')).lower()

        if entry_type == 'eventconsumer':
            if any(x in command for x in ['-enc', 'frombase64', 'hidden', 'powershell', 'cmd.exe']):
                risks.append("🔴 Critical")
            elif command:
                risks.append("🟠 Suspicious")
            else:
                risks.append("🟡 Medium")
        elif entry_type == 'eventfilter':
            if any(x in command for x in ['win32_process', 'win32_logon', '__instancecreation']):
                risks.append("🟠 Suspicious")
            else:
                risks.append("🟡 Medium")
        else:
            risks.append("⚪ Normal")
    return risks


@st.cache_data
def analyze_all_startup(startup_data, _folder_name: str = ""):
    """Analyze all startup files and return risk list. Cached for performance."""
    if not startup_data:
        return []
    risks = []
    script_extensions = ['.vbs', '.bat', '.ps1', '.js', '.hta', '.cmd', '.wsf']
    exe_extensions = ['.exe', '.dll', '.scr', '.pif']

    for entry in startup_data:
        # Use actual collector field names: Filename (capitalized)
        filename = str(entry.get('Filename', entry.get('filename', ''))).lower()

        if any(filename.endswith(ext) for ext in script_extensions):
            risks.append("🔴 Critical")
        elif any(filename.endswith(ext) for ext in exe_extensions):
            risks.append("🟠 Suspicious")
        elif filename.endswith('.lnk'):
            risks.append("🟡 Medium")
        else:
            risks.append("⚪ Normal")
    return risks


@st.cache_data
def get_wmi_df_with_risk(wmi_data, _folder_name: str = ""):
    """Create and cache WMI DataFrame with risk analysis applied."""
    if not wmi_data:
        return pd.DataFrame()

    df = pd.DataFrame(wmi_data)

    def analyze_wmi_risk(row):
        entry_type = str(row.get('Type', '')).lower()
        command = str(row.get('Command', '') or row.get('Query', '')).lower()

        if entry_type == 'eventconsumer':
            if command:
                if any(x in command for x in ['-enc', '-encodedcommand', 'frombase64', 'hidden', '-w hidden', 'powershell', 'cmd.exe']):
                    return "🔴 Critical"
                if any(x in command for x in ['.exe', '.ps1', '.bat', '.vbs', 'wscript', 'cscript']):
                    return "🟠 Suspicious"
            return "🟡 Medium"
        elif entry_type == 'eventfilter':
            if any(x in command for x in ['win32_process', 'win32_logon', '__instancecreation', '__instancemodification']):
                return "🟠 Suspicious"
            return "🟡 Medium"
        elif entry_type == 'binding':
            return "🟡 Medium"
        return "⚪ Normal"

    df['Risk'] = df.apply(analyze_wmi_risk, axis=1)

    # Pre-sort by risk
    risk_order = {"🔴 Critical": 0, "🟠 Suspicious": 1, "🟡 Medium": 2, "⚪ Normal": 3}
    df['_sort'] = df['Risk'].map(risk_order).fillna(3)
    df = df.sort_values('_sort').drop('_sort', axis=1)

    return df


@st.cache_data
def get_startup_df_with_risk(startup_data, _folder_name: str = ""):
    """Create and cache startup files DataFrame with risk analysis applied."""
    if not startup_data:
        return pd.DataFrame()

    df = pd.DataFrame(startup_data)

    script_extensions = ['.vbs', '.bat', '.ps1', '.js', '.hta', '.cmd', '.wsf']
    exe_extensions = ['.exe', '.dll', '.scr', '.pif']

    def analyze_startup_risk(row):
        filename = str(row.get('Filename', row.get('filename', ''))).lower()
        path = str(row.get('Path', row.get('path', ''))).lower()

        if any(filename.endswith(ext) for ext in script_extensions):
            return "🔴 Critical"
        if any(filename.endswith(ext) for ext in exe_extensions):
            return "🟠 Suspicious"
        if filename.endswith('.lnk'):
            if any(ext in path for ext in script_extensions + exe_extensions):
                return "🟡 Medium"
            return "⚪ Normal"
        return "⚪ Normal"

    df['Risk'] = df.apply(analyze_startup_risk, axis=1)

    # Add location column
    def get_location(row):
        path = str(row.get('Path', row.get('path', '')))
        if 'ProgramData' in path:
            return "All Users"
        return "Current User"

    df['Location'] = df.apply(get_location, axis=1)

    # Format file size
    def format_size(size):
        try:
            size = int(size)
            if size >= 1024*1024:
                return f"{size/(1024*1024):.1f} MB"
            elif size >= 1024:
                return f"{size/1024:.1f} KB"
            return f"{size} B"
        except:
            return "N/A"

    if 'Size' in df.columns:
        df['Size_Formatted'] = df['Size'].apply(format_size)

    # Pre-sort by risk
    risk_order = {"🔴 Critical": 0, "🟠 Suspicious": 1, "🟡 Medium": 2, "⚪ Normal": 3}
    df['_sort'] = df['Risk'].map(risk_order).fillna(3)
    df = df.sort_values('_sort').drop('_sort', axis=1)

    return df


def render_registry_tab(reg_data, folder_name: str):
    """Render the Registry Autoruns subtab."""
    if not reg_data:
        st.info("No Registry persistence data found.")
        return

    # Use cached DataFrame with pre-computed risk analysis (performance optimization)
    df_reg = get_registry_df_with_risk(reg_data, folder_name)
    if df_reg.empty:
        st.info("No Registry persistence data found.")
        return

    # Search and filter row
    col_search, col_filter = st.columns([3, 2])

    with col_search:
        search_reg = st.text_input("search_reg", placeholder="🔍 Search registry entries...", key="reg_search", label_visibility="collapsed")

    with col_filter:
        risk_filter = st.selectbox("risk_filter_reg", ["All Risk Levels", "Critical Only", "Suspicious Only", "Normal Only"], key="reg_risk_filter", label_visibility="collapsed")

    # Apply search filter (on cached DataFrame)
    filtered_df = df_reg.copy()
    if search_reg:
        search_lower = search_reg.lower()
        filtered_df = filtered_df[
            filtered_df['Name'].str.lower().str.contains(search_lower, na=False) |
            filtered_df['Value'].str.lower().str.contains(search_lower, na=False) |
            filtered_df['Path'].str.lower().str.contains(search_lower, na=False)
        ]

    # Apply risk filter
    if risk_filter == "Critical Only":
        filtered_df = filtered_df[filtered_df['Risk'].str.contains("🔴")]
    elif risk_filter == "Suspicious Only":
        filtered_df = filtered_df[filtered_df['Risk'].str.contains("🟠")]
    elif risk_filter == "Normal Only":
        filtered_df = filtered_df[filtered_df['Risk'].str.contains("⚪")]

    df_reg = filtered_df

    st.markdown(f'<div style="color:#888;font-size:0.8rem;margin:10px 0;">Showing {len(df_reg)} registry entries</div>', unsafe_allow_html=True)

    # Data table
    st.dataframe(
        sanitize_dataframe(df_reg),
        column_order=["Risk", "Category", "Name", "Value", "Path"],
        width="stretch",
        height=400,
        column_config={
            "Risk": st.column_config.TextColumn("Risk", width="small"),
            "Category": st.column_config.TextColumn("Location", width="small"),
            "Name": st.column_config.TextColumn("Entry Name", width="medium"),
            "Value": st.column_config.TextColumn("Command / Value", width="large"),
            "Path": st.column_config.TextColumn("Registry Path", width="medium")
        },
        hide_index=True
    )


def render_tasks_tab(tasks_data, folder_name: str = ""):
    """Render the Scheduled Tasks subtab."""
    if not tasks_data:
        st.info("No Scheduled Tasks found.")
        return

    # Use cached DataFrame with pre-computed risk analysis (performance optimization)
    df_tasks = get_tasks_df_with_risk(tasks_data, folder_name)
    if df_tasks.empty:
        st.info("No Scheduled Tasks found.")
        return

    # Search and filter row
    col_search, col_filter, col_state = st.columns([2, 1.5, 1.5])

    with col_search:
        search_tasks = st.text_input("search_tasks", placeholder="🔍 Search tasks...", key="tasks_search", label_visibility="collapsed")

    with col_filter:
        risk_filter = st.selectbox("risk_filter_tasks", ["All Risk Levels", "Critical Only", "Suspicious Only"], key="tasks_risk_filter", label_visibility="collapsed")

    with col_state:
        if 'State' in df_tasks.columns:
            states = ["All States"] + df_tasks['State'].unique().tolist()
            state_filter = st.selectbox("state_filter", states, key="tasks_state_filter", label_visibility="collapsed")
        else:
            state_filter = "All States"

    # Apply filters on cached DataFrame
    filtered_df = df_tasks.copy()

    # Apply search filter
    if search_tasks:
        search_lower = search_tasks.lower()
        mask = filtered_df.astype(str).apply(lambda x: x.str.lower().str.contains(search_lower, na=False)).any(axis=1)
        filtered_df = filtered_df[mask]

    # Apply risk filter
    if risk_filter == "Critical Only":
        filtered_df = filtered_df[filtered_df['Risk'].str.contains("🔴")]
    elif risk_filter == "Suspicious Only":
        filtered_df = filtered_df[filtered_df['Risk'].str.contains("🟠")]

    # Apply state filter
    if state_filter != "All States" and 'State' in filtered_df.columns:
        filtered_df = filtered_df[filtered_df['State'] == state_filter]

    df_tasks = filtered_df

    st.markdown(f'<div style="color:#888;font-size:0.8rem;margin:10px 0;">Showing {len(df_tasks)} scheduled tasks</div>', unsafe_allow_html=True)

    # Data table
    st.dataframe(
        sanitize_dataframe(df_tasks),
        column_order=["Risk", "TaskName", "State", "Action", "TaskPath"],
        width="stretch",
        height=400,
        column_config={
            "Risk": st.column_config.TextColumn("Risk", width="small"),
            "TaskName": st.column_config.TextColumn("Task Name", width="medium"),
            "State": st.column_config.TextColumn("State", width="small"),
            "Action": st.column_config.TextColumn("Command Executed", width="large"),
            "TaskPath": st.column_config.TextColumn("Task Path", width="medium")
        },
        hide_index=True
    )


def render_services_tab(services_data, folder_name: str = ""):
    """Render the Services Analysis subtab."""
    if not services_data:
        st.warning("No services data found. Make sure collect_services() is running in the collector.")
        return

    # Use cached DataFrame with pre-computed risk analysis (performance optimization)
    df_serv = get_services_df_with_risk(services_data, folder_name)
    if df_serv.empty:
        st.warning("No services data found.")
        return

    # Search and filter row
    col_search, col_filter, col_status = st.columns([2, 1.5, 1.5])

    with col_search:
        search_serv = st.text_input("search_serv", placeholder="🔍 Search services...", key="serv_search", label_visibility="collapsed")

    with col_filter:
        risk_filter = st.selectbox("risk_filter_serv", ["All Risk Levels", "High Risk Only", "Suspicious Only"], key="serv_risk_filter", label_visibility="collapsed")

    with col_status:
        if 'Status' in df_serv.columns:
            statuses = ["All Status"] + df_serv['Status'].unique().tolist()
            status_filter = st.selectbox("status_filter", statuses, key="serv_status_filter", label_visibility="collapsed")
        else:
            status_filter = "All Status"

    # Apply filters on cached DataFrame
    filtered_df = df_serv.copy()

    # Apply search filter
    if search_serv:
        search_lower = search_serv.lower()
        mask = filtered_df.astype(str).apply(lambda x: x.str.lower().str.contains(search_lower, na=False)).any(axis=1)
        filtered_df = filtered_df[mask]

    # Apply risk filter
    if risk_filter == "High Risk Only":
        filtered_df = filtered_df[filtered_df['Risk'].str.contains("🔴")]
    elif risk_filter == "Suspicious Only":
        filtered_df = filtered_df[filtered_df['Risk'].str.contains("🟠")]

    # Apply status filter
    if status_filter != "All Status" and 'Status' in filtered_df.columns:
        filtered_df = filtered_df[filtered_df['Status'] == status_filter]

    df_serv = filtered_df

    st.markdown(f'<div style="color:#888;font-size:0.8rem;margin:10px 0;">Showing {len(df_serv)} services</div>', unsafe_allow_html=True)

    # Data table
    column_order = ["Risk", "DisplayName", "Name", "Status", "StartType", "BinPath", "SHA256", "Username"]

    st.dataframe(
        sanitize_dataframe(df_serv),
        column_order=[c for c in column_order if c in df_serv.columns],
        width="stretch",
        height=400,
        column_config={
            "Risk": st.column_config.TextColumn("Risk", width="small"),
            "DisplayName": st.column_config.TextColumn("Display Name", width="medium"),
            "Name": st.column_config.TextColumn("Service Name", width="small"),
            "Status": st.column_config.TextColumn("Status", width="small"),
            "StartType": st.column_config.TextColumn("Start Type", width="small"),
            "BinPath": st.column_config.TextColumn("Binary Path", width="large"),
            "SHA256": st.column_config.TextColumn("Hash", width="medium"),
            "Username": st.column_config.TextColumn("Run As", width="small")
        },
        hide_index=True
    )


def render_wmi_tab(wmi_data, folder_name: str = ""):
    """Render the WMI Persistence subtab."""
    if not wmi_data:
        st.info("No WMI event subscriptions detected. This is typically a good sign - WMI persistence is commonly used by malware.")
        return

    # Use cached DataFrame with pre-computed risk analysis (performance optimization)
    df_wmi = get_wmi_df_with_risk(wmi_data, folder_name)
    if df_wmi.empty:
        st.info("No WMI event subscriptions detected.")
        return

    # Search and filter row
    col_search, col_filter = st.columns([3, 2])

    with col_search:
        search_wmi = st.text_input("search_wmi", placeholder="🔍 Search WMI entries...", key="wmi_search", label_visibility="collapsed")

    with col_filter:
        risk_filter = st.selectbox("risk_filter_wmi", ["All Risk Levels", "Critical Only", "Suspicious Only", "EventConsumer Only", "EventFilter Only"], key="wmi_risk_filter", label_visibility="collapsed")

    # Apply filters on cached DataFrame
    filtered_df = df_wmi.copy()

    # Apply search filter
    if search_wmi:
        search_lower = search_wmi.lower()
        mask = filtered_df.astype(str).apply(lambda x: x.str.lower().str.contains(search_lower, na=False)).any(axis=1)
        filtered_df = filtered_df[mask]

    # Apply risk/type filter
    if risk_filter == "Critical Only":
        filtered_df = filtered_df[filtered_df['Risk'].str.contains("🔴")]
    elif risk_filter == "Suspicious Only":
        filtered_df = filtered_df[filtered_df['Risk'].str.contains("🟠")]
    elif risk_filter == "EventConsumer Only":
        filtered_df = filtered_df[filtered_df['Type'].str.lower() == 'eventconsumer']
    elif risk_filter == "EventFilter Only":
        filtered_df = filtered_df[filtered_df['Type'].str.lower() == 'eventfilter']

    df_wmi = filtered_df

    st.markdown(f'<div style="color:#888;font-size:0.8rem;margin:10px 0;">Showing {len(df_wmi)} WMI entries</div>', unsafe_allow_html=True)

    # Data table - use actual collector field names
    column_order = ["Risk", "Type", "Name", "Query", "Command", "Filter", "Consumer"]

    st.dataframe(
        sanitize_dataframe(df_wmi),
        column_order=[c for c in column_order if c in df_wmi.columns],
        width="stretch",
        height=350,
        column_config={
            "Risk": st.column_config.TextColumn("Risk", width="small"),
            "Type": st.column_config.TextColumn("Entry Type", width="small"),
            "Name": st.column_config.TextColumn("Name", width="medium"),
            "Query": st.column_config.TextColumn("WQL Query", width="large"),
            "Command": st.column_config.TextColumn("Command/Script", width="large"),
            "Filter": st.column_config.TextColumn("Filter Ref", width="medium"),
            "Consumer": st.column_config.TextColumn("Consumer Ref", width="medium")
        },
        hide_index=True
    )

    # Analyst explanation
    with st.expander("📖 What is WMI Persistence?"):
        st.markdown("""
**WMI Event Subscriptions** allow code to execute when specific system events occur - a powerful persistence mechanism.

| Component | Description |
|-----------|-------------|
| **EventFilter** | Defines WHEN to trigger (WQL query matching events) |
| **EventConsumer** | Defines WHAT to execute when triggered |
| **FilterToConsumerBinding** | Links the filter to the consumer |

**Consumer Types:**
| Type | Risk | Description |
|------|------|-------------|
| **CommandLineEventConsumer** | 🔴 Critical | Executes command-line commands |
| **ActiveScriptEventConsumer** | 🔴 Critical | Runs VBScript/JScript code |
| **ScriptingStandardConsumerSetting** | 🟠 High | Script execution settings |
| **LogFileEventConsumer** | 🟡 Medium | Writes to log files |
| **NTEventLogEventConsumer** | ✅ Low | Creates event log entries |
| **SMTPEventConsumer** | 🟡 Medium | Sends emails |

**Common Malicious Triggers:**
- `__InstanceCreationEvent` - Process creation
- `Win32_LogonSession` - User logon
- `__IntervalTimerInstruction` - Timed intervals
- `Win32_LocalTime` - Specific time of day

**Forensic Value:**
- Survives reboots without registry/file modification
- Hard to detect with traditional antivirus
- Often used by APTs for long-term persistence

**Suspicious Indicators:**
- Encoded PowerShell commands
- Connections to external IPs/domains
- Execution from temp directories
- Random/obfuscated names

**MITRE ATT&CK:** T1546.003 (WMI Event Subscription)

**Investigation:** Use `wmic /namespace:\\\\root\\subscription PATH __EventFilter GET` to query
        """)


def render_startup_tab(startup_data, folder_name: str = ""):
    """Render the Startup Folders subtab."""
    if not startup_data:
        st.info("No files found in startup folders.")
        return

    # Use cached DataFrame with pre-computed risk analysis (performance optimization)
    df_startup = get_startup_df_with_risk(startup_data, folder_name)
    if df_startup.empty:
        st.info("No files found in startup folders.")
        return

    # Search and filter row
    col_search, col_filter = st.columns([3, 2])

    with col_search:
        search_startup = st.text_input("search_startup", placeholder="🔍 Search startup files...", key="startup_search", label_visibility="collapsed")

    with col_filter:
        risk_filter = st.selectbox("risk_filter_startup", ["All Risk Levels", "Critical Only", "Suspicious Only"], key="startup_risk_filter", label_visibility="collapsed")

    # Apply filters on cached DataFrame
    filtered_df = df_startup.copy()

    # Apply search filter
    if search_startup:
        search_lower = search_startup.lower()
        mask = filtered_df.astype(str).apply(lambda x: x.str.lower().str.contains(search_lower, na=False)).any(axis=1)
        filtered_df = filtered_df[mask]

    # Apply risk filter
    if risk_filter == "Critical Only":
        filtered_df = filtered_df[filtered_df['Risk'].str.contains("🔴")]
    elif risk_filter == "Suspicious Only":
        filtered_df = filtered_df[filtered_df['Risk'].str.contains("🟠")]

    df_startup = filtered_df

    # Sort by risk
    risk_order = {"🔴 Critical": 0, "🟠 Suspicious": 1, "🟡 Medium": 2, "⚪ Normal": 3}
    df_startup['_sort'] = df_startup['Risk'].map(risk_order).fillna(3)
    df_startup = df_startup.sort_values('_sort').drop('_sort', axis=1)

    st.markdown(f'<div style="color:#888;font-size:0.8rem;margin:10px 0;">Showing {len(df_startup)} startup files</div>', unsafe_allow_html=True)

    # Data table - use actual collector field names
    column_order = ["Risk", "Filename", "Location", "Size_Formatted", "Modified", "SHA256", "Path"]

    st.dataframe(
        sanitize_dataframe(df_startup),
        column_order=[c for c in column_order if c in df_startup.columns],
        width="stretch",
        height=350,
        column_config={
            "Risk": st.column_config.TextColumn("Risk", width="small"),
            "Filename": st.column_config.TextColumn("Filename", width="medium"),
            "Location": st.column_config.TextColumn("Location", width="small"),
            "Size_Formatted": st.column_config.TextColumn("Size", width="small"),
            "Path": st.column_config.TextColumn("Full Path", width="large"),
            "SHA256": st.column_config.TextColumn("SHA256", width="medium"),
            "Modified": st.column_config.TextColumn("Modified", width="small"),
        },
        hide_index=True
    )

    # Analyst explanation
    with st.expander("📖 What are Startup Folders?"):
        st.markdown("""
**Startup Folders** contain files that Windows automatically executes when a user logs in.

| Field | Description |
|-------|-------------|
| **Filename** | Name of the file in the startup folder |
| **Location** | "All Users" (runs for everyone) or "Current User" |
| **Path** | Full path to the startup item |
| **SHA256** | File hash for VirusTotal lookup |
| **Modified** | Last modification time of the file |

**Startup Folder Locations:**
| Location | Path | Scope |
|----------|------|-------|
| Per-User | `%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup` | Current user |
| All Users | `%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup` | All users |

**Forensic Value:**
- Simple persistence mechanism often used by malware
- Easy to verify - files are visible in Explorer
- Can contain shortcuts (.lnk), scripts, or executables
- Executes after user logon (user context)

**Dangerous File Types:**
| Extension | Risk | Description |
|-----------|------|-------------|
| `.exe`, `.scr` | 🔴 Critical | Direct executable |
| `.bat`, `.cmd` | 🔴 Critical | Batch scripts |
| `.vbs`, `.js` | 🔴 Critical | Script files |
| `.ps1` | 🔴 Critical | PowerShell scripts |
| `.lnk` | 🟠 High | Shortcuts (check target) |
| `.hta` | 🔴 Critical | HTML applications |

**Investigation Steps:**
1. Check file hash on VirusTotal
2. Review file creation/modification timestamps
3. For shortcuts, examine the target path and arguments
4. Compare against known legitimate startup entries
5. Check if file was recently added around incident time

**MITRE ATT&CK:** T1547.001 (Registry Run Keys / Startup Folder)
        """)
