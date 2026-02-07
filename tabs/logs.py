"""
Event Logs Explorer Tab - Professional Forensic Investigation View.
Displays Windows event logs with filtering, categorization, and analysis.
Supports SQLite pagination for large datasets.
"""
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta

from core.data_loader import load_json, sanitize_dataframe
from core.risk_engine import RiskEngine

# Try to import SQLite cache functions
try:
    from core.evidence_cache import query_evidence, count_evidence, search_evidence
    SQLITE_AVAILABLE = True
except ImportError:
    SQLITE_AVAILABLE = False


# Important Event IDs with descriptions and risk levels
EVENT_IDS = {
    # Security - Critical
    1102: {"desc": "Audit Log Cleared", "category": "Log Tampering", "risk": "critical", "mitre": "T1070.001"},
    104: {"desc": "Event Log Cleared", "category": "Log Tampering", "risk": "critical", "mitre": "T1070.001"},
    4720: {"desc": "User Account Created", "category": "Account Management", "risk": "critical", "mitre": "T1136"},
    4726: {"desc": "User Account Deleted", "category": "Account Management", "risk": "high", "mitre": "T1531"},
    4728: {"desc": "Member Added to Security Group", "category": "Account Management", "risk": "high", "mitre": "T1098"},
    4732: {"desc": "Member Added to Local Group", "category": "Account Management", "risk": "high", "mitre": "T1098"},
    4756: {"desc": "Member Added to Universal Group", "category": "Account Management", "risk": "high", "mitre": "T1098"},

    # Security - Authentication
    4624: {"desc": "Successful Logon", "category": "Authentication", "risk": "info", "mitre": "T1078"},
    4625: {"desc": "Failed Logon", "category": "Authentication", "risk": "medium", "mitre": "T1110"},
    4634: {"desc": "Logoff", "category": "Authentication", "risk": "info", "mitre": ""},
    4648: {"desc": "Explicit Credentials Logon", "category": "Authentication", "risk": "high", "mitre": "T1078"},
    4672: {"desc": "Special Privileges Assigned", "category": "Privilege Use", "risk": "medium", "mitre": "T1078"},
    4776: {"desc": "Credential Validation", "category": "Authentication", "risk": "info", "mitre": ""},

    # Security - Lateral Movement
    4778: {"desc": "Session Reconnected (RDP)", "category": "Remote Access", "risk": "medium", "mitre": "T1021.001"},
    4779: {"desc": "Session Disconnected (RDP)", "category": "Remote Access", "risk": "info", "mitre": ""},
    1149: {"desc": "RDP Authentication Success", "category": "Remote Access", "risk": "medium", "mitre": "T1021.001"},

    # Security - Process/Execution
    4688: {"desc": "Process Created", "category": "Execution", "risk": "info", "mitre": "T1059"},
    4689: {"desc": "Process Exited", "category": "Execution", "risk": "info", "mitre": ""},

    # Security - Persistence
    4698: {"desc": "Scheduled Task Created", "category": "Persistence", "risk": "high", "mitre": "T1053"},
    4699: {"desc": "Scheduled Task Deleted", "category": "Persistence", "risk": "medium", "mitre": "T1053"},
    4700: {"desc": "Scheduled Task Enabled", "category": "Persistence", "risk": "medium", "mitre": "T1053"},
    4701: {"desc": "Scheduled Task Disabled", "category": "Persistence", "risk": "info", "mitre": ""},
    7045: {"desc": "Service Installed", "category": "Persistence", "risk": "high", "mitre": "T1543.003"},
    7040: {"desc": "Service Start Type Changed", "category": "Persistence", "risk": "medium", "mitre": "T1543.003"},

    # PowerShell
    4103: {"desc": "PowerShell Module Logging", "category": "PowerShell", "risk": "medium", "mitre": "T1059.001"},
    4104: {"desc": "PowerShell Script Block", "category": "PowerShell", "risk": "medium", "mitre": "T1059.001"},

    # System
    6005: {"desc": "Event Log Service Started", "category": "System", "risk": "info", "mitre": ""},
    6006: {"desc": "Event Log Service Stopped", "category": "System", "risk": "medium", "mitre": ""},
    6008: {"desc": "Unexpected Shutdown", "category": "System", "risk": "medium", "mitre": ""},
    1074: {"desc": "System Shutdown/Restart", "category": "System", "risk": "info", "mitre": ""},

    # Windows Defender
    1116: {"desc": "Defender Malware Detected", "category": "Antivirus", "risk": "critical", "mitre": ""},
    1117: {"desc": "Defender Action Taken", "category": "Antivirus", "risk": "high", "mitre": ""},
    5001: {"desc": "Defender Real-Time Disabled", "category": "Antivirus", "risk": "critical", "mitre": "T1562.001"},
    5010: {"desc": "Defender Scanning Disabled", "category": "Antivirus", "risk": "high", "mitre": "T1562.001"},

    # Firewall
    2003: {"desc": "Firewall Profile Changed", "category": "Firewall", "risk": "high", "mitre": "T1562.004"},
    2004: {"desc": "Firewall Rule Added", "category": "Firewall", "risk": "medium", "mitre": "T1562.004"},
    2005: {"desc": "Firewall Rule Modified", "category": "Firewall", "risk": "medium", "mitre": "T1562.004"},
}

# Risk level colors and indicators
RISK_INDICATORS = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "info": "⚪"
}


def render(evidence_folder: str, risk_engine: RiskEngine):
    """Render the Event Logs Explorer tab."""

    # Check if SQLite cache is available and enabled
    use_sqlite = SQLITE_AVAILABLE and st.session_state.get('sqlite_enabled', False)

    # Pagination settings
    PAGE_SIZE_OPTIONS = [50, 100, 250, 500, 1000]

    # Initialize pagination state
    if 'logs_page' not in st.session_state:
        st.session_state.logs_page = 0
    if 'logs_page_size' not in st.session_state:
        st.session_state.logs_page_size = 100

    # Load data - use SQLite for pagination if available, fallback to JSON
    if use_sqlite:
        total_count = count_evidence(evidence_folder, "events")
        if total_count > 0:
            ev_data = query_evidence(
                evidence_folder,
                "events",
                limit=st.session_state.logs_page_size,
                offset=st.session_state.logs_page * st.session_state.logs_page_size,
                order_by="time_unix DESC"
            )
        else:
            # SQLite empty, fallback to JSON
            use_sqlite = False
            ev_data = load_json(evidence_folder, "all_events.json")
            total_count = len(ev_data) if ev_data else 0
    else:
        ev_data = load_json(evidence_folder, "all_events.json")
        total_count = len(ev_data) if ev_data else 0

    if not ev_data:
        st.markdown('''<div style="background:#1e1e2e;border-radius:10px;padding:20px;margin-bottom:20px;">
<div style="font-size:1.3rem;font-weight:bold;color:white;">📋 Event Logs Explorer</div>
<div style="color:#888;font-size:0.85rem;margin-top:5px;">Windows Event Logs • Security • System • Application</div>
</div>''', unsafe_allow_html=True)

        st.markdown('''<div style="background:#1e1e2e;border-radius:10px;padding:40px;text-align:center;">
<div style="font-size:3rem;margin-bottom:10px;">📭</div>
<div style="font-size:1.2rem;font-weight:bold;color:white;">No Event Logs Found</div>
<div style="color:#888;margin-top:10px;font-size:0.9rem;">Event logs were not collected or the JSON file is empty.</div>
</div>''', unsafe_allow_html=True)
        return

    # For stats, we need all data or cached stats
    if use_sqlite:
        # Cache stats in session to avoid recomputing
        stats_key = f"logs_stats_{evidence_folder}"
        if stats_key not in st.session_state:
            # Load all events once for stats calculation
            all_events_for_stats = load_json(evidence_folder, "all_events.json") or []
            st.session_state[stats_key] = analyze_event_stats(all_events_for_stats)
        event_stats = st.session_state[stats_key]
        total_events = total_count
    else:
        event_stats = analyze_event_stats(ev_data)
        total_events = len(ev_data)
    critical_count = event_stats.get('critical', 0)
    high_count = event_stats.get('high', 0)
    security_count = event_stats.get('security', 0)

    # Simple header with blue styling
    st.markdown(f'<div style="color:#e6edf3;font-size:1.1rem;margin-bottom:15px;"><b>Logs</b> | Total: {total_events:,} | Critical: {critical_count} | High: {high_count} | Security: {security_count}</div>', unsafe_allow_html=True)


    df = pd.DataFrame(ev_data)

    # Ensure Id is numeric
    if 'Id' in df.columns:
        df['Id'] = pd.to_numeric(df['Id'], errors='coerce')

    # Parse time column
    if 'Time' in df.columns:
        df['Time'] = pd.to_datetime(df['Time'], errors='coerce')

    # Filter row 1: Search and Log Source
    col_search, col_log = st.columns([2, 2])

    with col_search:
        search_text = st.text_input("🔍 Search Message", placeholder="Enter keywords...", key="logs_search")

    with col_log:
        ltypes = ["All Logs"]
        if 'LogName' in df.columns:
            ltypes += df['LogName'].unique().tolist()
        sel_log = st.selectbox("Log Source", ltypes, key="logs_source")

    # Filter row 2: Event ID, Risk Level, Time
    col_id, col_risk, col_time = st.columns([1.5, 1.5, 2])

    with col_id:
        search_id = st.text_input("Event ID", placeholder="e.g., 4624,4625", key="logs_id")

    with col_risk:
        risk_filter = st.selectbox("Risk Level", ["All Risk Levels", "Critical Only", "High & Critical", "Notable Events"], key="logs_risk")

    with col_time:
        time_filter = st.selectbox("Time Range", ["All Time", "Last Hour", "Last 24 Hours", "Last 7 Days"], key="logs_time")

    # Analyze each event
    def analyze_event(row):
        event_id = row.get('Id', 0)
        if pd.isna(event_id):
            event_id = 0
        else:
            event_id = int(event_id)

        event_info = EVENT_IDS.get(event_id, {})
        risk = event_info.get('risk', 'info')
        category = event_info.get('category', 'Other')
        desc = event_info.get('desc', '')
        mitre = event_info.get('mitre', '')

        indicator = RISK_INDICATORS.get(risk, '⚪')

        return pd.Series([indicator, risk, category, desc, mitre])

    df[['Indicator', 'Risk', 'Category', 'Description', 'MITRE']] = df.apply(analyze_event, axis=1)

    # Apply filters
    filtered_df = df.copy()

    # Log source filter
    if sel_log != "All Logs" and 'LogName' in filtered_df.columns:
        filtered_df = filtered_df[filtered_df['LogName'] == sel_log]

    # Text search
    if search_text:
        search_lower = search_text.lower()
        if 'Message' in filtered_df.columns:
            filtered_df = filtered_df[filtered_df['Message'].str.lower().str.contains(search_lower, na=False)]

    # Event ID filter
    if search_id:
        try:
            ids_to_search = [int(i.strip()) for i in search_id.split(',')]
            filtered_df = filtered_df[filtered_df['Id'].isin(ids_to_search)]
        except ValueError:
            st.error("Please enter valid Event IDs separated by commas")

    # Risk filter
    if risk_filter == "Critical Only":
        filtered_df = filtered_df[filtered_df['Risk'] == 'critical']
    elif risk_filter == "High & Critical":
        filtered_df = filtered_df[filtered_df['Risk'].isin(['critical', 'high'])]
    elif risk_filter == "Notable Events":
        filtered_df = filtered_df[filtered_df['Risk'].isin(['critical', 'high', 'medium'])]

    # Time filter
    if time_filter != "All Time" and 'Time' in filtered_df.columns:
        now = datetime.now()
        if time_filter == "Last Hour":
            cutoff = now - timedelta(hours=1)
        elif time_filter == "Last 24 Hours":
            cutoff = now - timedelta(hours=24)
        elif time_filter == "Last 7 Days":
            cutoff = now - timedelta(days=7)
        filtered_df = filtered_df[filtered_df['Time'] >= cutoff]

    # Sort by time (most recent first)
    if 'Time' in filtered_df.columns:
        filtered_df = filtered_df.sort_values('Time', ascending=False)

    # Pagination controls (when SQLite is enabled)
    if use_sqlite:
        total_pages = max(1, (total_count + st.session_state.logs_page_size - 1) // st.session_state.logs_page_size)
        current_page = st.session_state.logs_page + 1

        pag_cols = st.columns([1, 1, 2, 1, 1])

        with pag_cols[0]:
            if st.button("⏮️ First", disabled=st.session_state.logs_page == 0, key="logs_first"):
                st.session_state.logs_page = 0
                st.rerun()

        with pag_cols[1]:
            if st.button("◀️ Prev", disabled=st.session_state.logs_page == 0, key="logs_prev"):
                st.session_state.logs_page -= 1
                st.rerun()

        with pag_cols[2]:
            st.markdown(f'''<div style="text-align:center;padding:8px;background:#1e1e2e;border-radius:6px;">
                <span style="color:#667eea;font-weight:bold;">Page {current_page:,}</span>
                <span style="color:#888;"> of {total_pages:,}</span>
                <span style="color:#666;font-size:0.8rem;"> ({total_count:,} total events)</span>
            </div>''', unsafe_allow_html=True)

        with pag_cols[3]:
            if st.button("Next ▶️", disabled=current_page >= total_pages, key="logs_next"):
                st.session_state.logs_page += 1
                st.rerun()

        with pag_cols[4]:
            if st.button("Last ⏭️", disabled=current_page >= total_pages, key="logs_last"):
                st.session_state.logs_page = total_pages - 1
                st.rerun()

        # Page size selector
        with st.expander("⚙️ Page Settings", expanded=False):
            col_size, col_jump = st.columns(2)
            with col_size:
                new_page_size = st.selectbox(
                    "Events per page",
                    PAGE_SIZE_OPTIONS,
                    index=PAGE_SIZE_OPTIONS.index(st.session_state.logs_page_size) if st.session_state.logs_page_size in PAGE_SIZE_OPTIONS else 1,
                    key="logs_page_size_select"
                )
                if new_page_size != st.session_state.logs_page_size:
                    st.session_state.logs_page_size = new_page_size
                    st.session_state.logs_page = 0
                    st.rerun()

            with col_jump:
                jump_page = st.number_input("Jump to page", min_value=1, max_value=total_pages, value=current_page, key="logs_jump")
                if jump_page != current_page:
                    st.session_state.logs_page = jump_page - 1
                    st.rerun()

        st.markdown(f'<div style="color:#888;font-size:0.8rem;margin:10px 0;">Showing {len(filtered_df):,} filtered of {len(df):,} loaded (page {current_page} of {total_pages})</div>', unsafe_allow_html=True)
    else:
        st.markdown(f'<div style="color:#888;font-size:0.8rem;margin:10px 0;">Showing {len(filtered_df):,} of {len(df):,} events</div>', unsafe_allow_html=True)

    # View tabs
    view_tabs = st.tabs(["Event Table", "Event ID Reference"])

    # Tab 1: Event Table
    with view_tabs[0]:
        # Data table
        column_order = ["Indicator", "Time", "Id", "Description", "Category", "LogName", "LevelDisplayName", "Message"]

        st.dataframe(
            sanitize_dataframe(filtered_df),
            column_order=[c for c in column_order if c in filtered_df.columns],
            width="stretch",
            height=450,
            column_config={
                "Indicator": st.column_config.TextColumn("", width="small"),
                "Time": st.column_config.DatetimeColumn("Timestamp", format="D/M/Y H:mm:ss"),
                "Id": st.column_config.NumberColumn("Event ID", format="%d"),
                "Description": st.column_config.TextColumn("Description", width="medium"),
                "Category": st.column_config.TextColumn("Category", width="small"),
                "LogName": st.column_config.TextColumn("Log", width="small"),
                "LevelDisplayName": st.column_config.TextColumn("Level", width="small"),
                "Message": st.column_config.TextColumn("Message", width="large")
            },
            hide_index=True
        )

    # Tab 2: Event ID Reference
    with view_tabs[1]:
        st.caption("Quick reference for important Windows Event IDs used in forensic investigations.")

        # Build reference table
        ref_data = []
        for event_id, info in sorted(EVENT_IDS.items()):
            indicator = RISK_INDICATORS.get(info.get('risk', 'info'), '⚪')
            ref_data.append({
                'Risk': indicator,
                'ID': event_id,
                'Description': info.get('desc', ''),
                'Category': info.get('category', 'Other'),
                'MITRE': info.get('mitre', '')
            })

        ref_df = pd.DataFrame(ref_data)
        st.dataframe(ref_df, width="stretch", height=400, hide_index=True)

    # Export section
    st.markdown("---")
    critical_df = filtered_df[filtered_df['Risk'] == 'critical']
    col1, col2, col3 = st.columns(3)

    with col1:
        export_df = filtered_df[['Time', 'Id', 'Category', 'Description', 'LogName', 'LevelDisplayName', 'Message']].copy()
        if 'Time' in export_df.columns:
            export_df['Time'] = export_df['Time'].dt.strftime('%Y-%m-%d %H:%M:%S')
        st.download_button("📋 Export Filtered", export_df.to_csv(index=False), "event_logs_filtered.csv", "text/csv", key="logs_filtered_export")

    with col2:
        if not critical_df.empty:
            crit_export = critical_df[['Time', 'Id', 'Description', 'LogName', 'Message']].copy()
            if 'Time' in crit_export.columns:
                crit_export['Time'] = crit_export['Time'].dt.strftime('%Y-%m-%d %H:%M:%S')
            st.download_button(f"🔴 Export Critical ({len(critical_df)})", crit_export.to_csv(index=False), "critical_events.csv", "text/csv", key="logs_critical_export")
        else:
            st.button("🔴 No Critical Events", disabled=True, key="logs_critical_disabled")

    with col3:
        all_export = df[['Time', 'Id', 'LogName', 'LevelDisplayName', 'Message']].copy()
        if 'Time' in all_export.columns:
            all_export['Time'] = all_export['Time'].dt.strftime('%Y-%m-%d %H:%M:%S')
        st.download_button(f"📊 Export All ({len(df):,})", all_export.to_csv(index=False), "all_event_logs.csv", "text/csv", key="logs_all_export")


def analyze_event_stats(ev_data):
    """Analyze events for statistics."""
    stats = {'critical': 0, 'high': 0, 'medium': 0, 'security': 0}

    for event in ev_data:
        event_id = event.get('Id', 0)
        log_name = str(event.get('LogName', '')).lower()

        if event_id:
            try:
                event_id = int(event_id)
                event_info = EVENT_IDS.get(event_id, {})
                risk = event_info.get('risk', 'info')

                if risk == 'critical':
                    stats['critical'] += 1
                elif risk == 'high':
                    stats['high'] += 1
                elif risk == 'medium':
                    stats['medium'] += 1
            except:
                pass

        if 'security' in log_name:
            stats['security'] += 1

    return stats
