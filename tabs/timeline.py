"""
Master Timeline Tab - Clean Table View.
Aggregates all events into a unified chronological view.
"""
import os
from datetime import datetime, timedelta

import streamlit as st
import pandas as pd

from core.data_loader import load_json, sanitize_dataframe
from core.risk_engine import RiskEngine
from components.timeline import ForensicTimeline


@st.cache_data
def build_timeline_dataframe(
    events, browser, usb, files, processes, prefetch,
    userassist, lnk_files, software, cookies,
    shimcache, jump_lists, shellbags, bits_jobs,
    tasks, services, wmi, startup, registry,
    downloads, connections, firefox_history,
    risky_artifact_names: list,
    _folder_name: str = ""
):
    """Build the timeline dataframe with caching."""
    risky_artifacts = set(risky_artifact_names)
    timeline = ForensicTimeline(risky_artifacts)

    # Core event sources
    timeline.add_event_logs(events)
    timeline.add_browser_history(browser)
    timeline.add_browser_history(firefox_history)
    timeline.add_usb_events(usb)
    timeline.add_file_events(files)
    timeline.add_process_events(processes)

    # Execution evidence
    timeline.add_prefetch(prefetch)
    timeline.add_userassist(userassist)
    timeline.add_lnk_files(lnk_files)
    timeline.add_shimcache(shimcache)

    # File access
    timeline.add_jump_lists(jump_lists)
    timeline.add_shellbags(shellbags)

    # Network
    timeline.add_bits_jobs(bits_jobs)
    timeline.add_network_connections(connections)
    timeline.add_browser_downloads(downloads)

    # Persistence
    timeline.add_scheduled_tasks(tasks)
    timeline.add_services(services)
    timeline.add_wmi_persistence(wmi)
    timeline.add_startup_files(startup)
    timeline.add_registry_persistence(registry)

    # Other
    timeline.add_software_installs(software)
    timeline.add_cookies(cookies)

    df = timeline.get_dataframe()
    stats = timeline.get_stats(df) if not df.empty else {}

    return df, stats


def render(evidence_folder: str, risk_engine: RiskEngine):
    """Render the Master Timeline tab."""

    # Load ALL data sources
    events = load_json(evidence_folder, "all_events.json")
    browser = load_json(evidence_folder, "browser_history.json")
    firefox_history = load_json(evidence_folder, "firefox_history.json")
    usb = load_json(evidence_folder, "usb_events.json")
    files = load_json(evidence_folder, "recent_files.json")
    processes = load_json(evidence_folder, "processes.json")

    prefetch = load_json(evidence_folder, "prefetch_list.json")
    userassist = load_json(evidence_folder, "user_assist.json")
    lnk_files = load_json(evidence_folder, "lnk_files.json")
    shimcache = load_json(evidence_folder, "shimcache.json")

    jump_lists = load_json(evidence_folder, "jump_lists.json")
    shellbags = load_json(evidence_folder, "shellbags.json")

    bits_jobs = load_json(evidence_folder, "bits_jobs.json")
    connections = load_json(evidence_folder, "network_connections.json")
    downloads = load_json(evidence_folder, "browser_downloads.json")

    tasks = load_json(evidence_folder, "scheduled_tasks.json")
    services = load_json(evidence_folder, "services.json")
    wmi = load_json(evidence_folder, "wmi_persistence.json")
    startup = load_json(evidence_folder, "startup_files.json")
    registry = load_json(evidence_folder, "registry_persistence.json")

    software = load_json(evidence_folder, "installed_software.json")
    cookies = load_json(evidence_folder, "browser_cookies.json")

    # Get risky artifacts from findings
    risky_artifact_names = []
    for f in risk_engine.all_findings:
        if f.evidence and f.evidence.get('name'):
            risky_artifact_names.append(f.evidence['name'].lower())

    # Build the unified timeline
    folder_name = os.path.basename(evidence_folder)
    with st.spinner("Building timeline..."):
        df, stats = build_timeline_dataframe(
            events, browser, usb, files, processes, prefetch,
            userassist, lnk_files, software, cookies,
            shimcache, jump_lists, shellbags, bits_jobs,
            tasks, services, wmi, startup, registry,
            downloads, connections, firefox_history,
            risky_artifact_names, folder_name
        )

    if df.empty:
        st.info("No timeline data available.")
        return

    # Simple header
    time_range = stats.get('time_range', (None, None))
    time_start = time_range[0].strftime('%Y-%m-%d %H:%M') if time_range[0] else 'Unknown'
    time_end = time_range[1].strftime('%Y-%m-%d %H:%M') if time_range[1] else 'Unknown'

    st.markdown(f'<div style="color:#e6edf3;font-size:1.1rem;margin-bottom:15px;"><b>Timeline</b> | {stats.get("total", 0):,} events | Flagged: {stats.get("risky", 0)} | Sources: {len(stats.get("types", {}))} | Range: {time_start} to {time_end}</div>', unsafe_allow_html=True)

    # Filters
    col1, col2, col3, col4 = st.columns([2, 1, 1, 2])

    with col1:
        available_types = ["All"] + sorted(df['Type'].unique().tolist())
        type_filter = st.selectbox("Source", available_types, key="tl_type")

    with col2:
        time_presets = ["All Time", "Last 24h", "Last 7d", "Last 30d"]
        time_preset = st.selectbox("Time", time_presets, key="tl_time")

    with col3:
        show_risky = st.checkbox("Flagged only", key="tl_risky")

    with col4:
        search_term = st.text_input("Search", placeholder="Search...", key="tl_search")

    # Apply filters
    filtered_df = df.copy()

    if type_filter != "All":
        filtered_df = filtered_df[filtered_df['Type'] == type_filter]

    if time_preset == "Last 24h":
        cutoff = datetime.now() - timedelta(hours=24)
        filtered_df = filtered_df[filtered_df['Timestamp'] >= cutoff]
    elif time_preset == "Last 7d":
        cutoff = datetime.now() - timedelta(days=7)
        filtered_df = filtered_df[filtered_df['Timestamp'] >= cutoff]
    elif time_preset == "Last 30d":
        cutoff = datetime.now() - timedelta(days=30)
        filtered_df = filtered_df[filtered_df['Timestamp'] >= cutoff]

    if show_risky:
        filtered_df = filtered_df[filtered_df['Risky'] == True]

    if search_term:
        search_lower = search_term.lower()
        filtered_df = filtered_df[
            filtered_df['Description'].str.lower().str.contains(search_lower, na=False) |
            filtered_df['Source'].str.lower().str.contains(search_lower, na=False)
        ]

    st.caption(f"Showing {len(filtered_df):,} of {len(df):,} events")

    # Tabs
    tab_table, tab_chart, tab_flagged = st.tabs(["Event Table", "Activity Chart", "Flagged Events"])

    # Tab 1: Event Table
    with tab_table:
        if not filtered_df.empty:
            display_df = filtered_df[['Timestamp', 'Type', 'Source', 'Description', 'Risky']].copy()
            display_df['Risky'] = display_df['Risky'].apply(lambda x: 'Yes' if x else '')

            st.dataframe(
                sanitize_dataframe(display_df.head(1000)),
                width="stretch",
                height=500,
                hide_index=True,
                column_config={
                    "Timestamp": st.column_config.DatetimeColumn("Time", format="D/M/Y H:mm:ss"),
                    "Type": st.column_config.TextColumn("Type", width="small"),
                    "Source": st.column_config.TextColumn("Source", width="medium"),
                    "Description": st.column_config.TextColumn("Description", width="large"),
                    "Risky": st.column_config.TextColumn("Flag", width="small"),
                }
            )

            if len(filtered_df) > 1000:
                st.caption(f"Showing 1,000 of {len(filtered_df):,} events.")
        else:
            st.info("No events match the current filters.")

    # Tab 2: Activity Chart
    with tab_chart:
        if not filtered_df.empty:
            # Events per hour
            chart_df = filtered_df.set_index('Timestamp').resample('1h').size().reset_index()
            chart_df.columns = ['Time', 'Events']
            st.line_chart(chart_df.set_index('Time'), height=300)

            # Events by type
            st.markdown("**Events by Source**")
            type_df = filtered_df['Type'].value_counts().reset_index()
            type_df.columns = ['Type', 'Count']
            st.bar_chart(type_df.set_index('Type'), height=200)
        else:
            st.info("No events to chart.")

    # Tab 3: Flagged Events
    with tab_flagged:
        risky_df = df[df['Risky'] == True]

        if not risky_df.empty:
            st.markdown(f"**{len(risky_df)} flagged events** - These match suspicious patterns.")

            display_risky = risky_df[['Timestamp', 'Type', 'Source', 'Description']].head(100)
            st.dataframe(
                sanitize_dataframe(display_risky),
                width="stretch",
                height=400,
                hide_index=True,
                column_config={
                    "Timestamp": st.column_config.DatetimeColumn("Time", format="D/M/Y H:mm:ss"),
                    "Type": st.column_config.TextColumn("Type", width="small"),
                    "Source": st.column_config.TextColumn("Source", width="medium"),
                    "Description": st.column_config.TextColumn("Description", width="large"),
                }
            )

            if len(risky_df) > 100:
                st.caption(f"Showing 100 of {len(risky_df)} flagged events.")
        else:
            st.success("No flagged events detected.")

    # Export
    st.markdown("---")
    col1, col2 = st.columns(2)

    with col1:
        csv_df = filtered_df[['Timestamp', 'Type', 'Source', 'Description', 'Risky']].copy()
        csv_df['Timestamp'] = csv_df['Timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
        st.download_button(
            "Export CSV",
            csv_df.to_csv(index=False),
            "timeline.csv",
            "text/csv",
            width="stretch"
        )

    with col2:
        json_data = filtered_df[['Timestamp', 'Type', 'Source', 'Description', 'Risky']].copy()
        json_data['Timestamp'] = json_data['Timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
        st.download_button(
            "Export JSON",
            json_data.to_json(orient='records', indent=2),
            "timeline.json",
            "application/json",
            width="stretch"
        )
