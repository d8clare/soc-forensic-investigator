"""
Global Search & Pivot Tab.
Search across ALL artifacts and pivot on indicators.
"""
import streamlit as st
import pandas as pd
import json
from typing import List, Dict

from core.risk_engine import RiskEngine
from core.pivot_engine import PivotEngine
from core.evidence_cache import get_evidence
from components.quick_actions import init_quick_actions_state, render_investigation_notes
from components.export_report import render_export_panel
from components.activity_log import log_search, log_pivot


def search_in_data(data: List[Dict], search_term: str, source_name: str) -> List[Dict]:
    """Search for term in a list of dictionaries."""
    if not data:
        return []

    results = []
    search_lower = search_term.lower()

    for item in data:
        item_str = json.dumps(item, default=str).lower()
        if search_lower in item_str:
            matched_fields = []
            for key, value in item.items():
                if value and search_lower in str(value).lower():
                    matched_fields.append(key)

            results.append({
                "source": source_name,
                "matched_fields": ", ".join(matched_fields[:3]),
                "data": item
            })

    return results


def render(evidence_folder: str, risk_engine: RiskEngine):
    """Render the Global Search & Pivot tab."""

    init_quick_actions_state()

    folder_name = evidence_folder.split("\\")[-1] if "\\" in evidence_folder else evidence_folder.split("/")[-1]
    case_info = {"hostname": folder_name.replace("Evidence_", "").split("_")[0], "date_str": ""}

    subtabs = st.tabs(["Search", "Pivot", "Notes", "Export"])

    with subtabs[0]:
        render_search_mode(evidence_folder, risk_engine)

    with subtabs[1]:
        render_pivot_mode(evidence_folder)

    with subtabs[2]:
        render_investigation_notes()

    with subtabs[3]:
        render_export_panel(evidence_folder, risk_engine, case_info)


def render_search_mode(evidence_folder: str, risk_engine: RiskEngine):
    """Render the global search interface."""

    st.markdown('<div style="color:#e6edf3;font-size:1.1rem;margin-bottom:15px;"><b>Global Search</b> - Search across all artifacts</div>', unsafe_allow_html=True)

    # Search input
    with st.form(key="search_form", clear_on_submit=False):
        col1, col2 = st.columns([4, 1])
        with col1:
            search_term = st.text_input(
                "Search Term",
                placeholder="Enter filename, IP, domain, process name, command, hash...",
                label_visibility="collapsed",
                key="search_input"
            )
        with col2:
            search_submitted = st.form_submit_button("Search", type="primary")

    # Search options
    with st.expander("Search Options", expanded=False):
        max_results = st.slider("Max Results", 10, 500, 100)

    if not search_term:
        st.info("Enter a search term to search across all artifacts.")
        st.markdown("""
**Search ideas:** `temp`, `appdata`, `powershell`, `cmd`, `base64`, `-enc`, `mimikatz`, `psexec`
        """)
        return

    if search_term and search_submitted:
        with st.spinner("Searching..."):
            all_results = perform_search(evidence_folder, search_term, risk_engine)

        st.session_state.search_results = all_results
        st.session_state.last_search_term = search_term
        log_search(search_term, len(all_results))

    # Display results
    if 'search_results' in st.session_state and st.session_state.get('last_search_term') == search_term:
        display_search_results(st.session_state.search_results, search_term, max_results)


def perform_search(evidence_folder: str, search_term: str, risk_engine: RiskEngine) -> List[Dict]:
    """Perform search across all cached evidence data."""
    all_results = []

    data_sources = [
        ("processes", "Processes"),
        ("network", "Network"),
        ("recent_files", "Files"),
        ("dns", "DNS"),
        ("browser_history", "Browser"),
        ("browser_cookies", "Cookies"),
        ("events", "Events"),
        ("registry", "Registry"),
        ("tasks", "Tasks"),
        ("services", "Services"),
        ("software", "Software"),
        ("usb_history", "USB"),
        ("shimcache", "Shimcache"),
        ("startup", "Startup"),
        ("wmi", "WMI"),
        ("bits_jobs", "BITS"),
        ("jump_lists", "Jump Lists"),
        ("shellbags", "Shellbags"),
        ("arp", "ARP"),
        ("hosts", "Hosts"),
        ("userassist", "UserAssist"),
        ("prefetch", "Prefetch"),
        ("lnk_files", "LNK Files"),
        ("powershell", "PowerShell"),
    ]

    for cache_key, source_name in data_sources:
        data = get_evidence(evidence_folder, cache_key)
        if data:
            results = search_in_data(data, search_term, source_name)
            all_results.extend(results)

    # Search findings
    for finding in risk_engine.all_findings:
        finding_str = f"{finding.category} {finding.description} {json.dumps(finding.evidence, default=str)}"
        if search_term.lower() in finding_str.lower():
            all_results.append({
                "source": "Findings",
                "matched_fields": "category, description",
                "data": {
                    "category": finding.category,
                    "description": finding.description,
                    "severity": finding.severity,
                    "score": finding.score
                }
            })

    return all_results


def display_search_results(all_results: List[Dict], search_term: str, max_results: int):
    """Display search results."""
    if all_results:
        st.success(f"Found {len(all_results)} results for '{search_term}'")

        # Group by source
        sources = {}
        for result in all_results[:max_results]:
            source = result["source"]
            if source not in sources:
                sources[source] = []
            sources[source].append(result)

        # Summary
        summary_text = " | ".join([f"{src}: {len(items)}" for src, items in sources.items()])
        st.caption(summary_text)

        # Results by source
        for source, items in sources.items():
            with st.expander(f"{source} ({len(items)} results)", expanded=(len(items) <= 10)):
                render_source_results(source, items)

        # Export
        st.markdown("---")
        col1, col2 = st.columns(2)
        with col1:
            export_data = [{"source": r["source"], **r["data"]} for r in all_results[:max_results]]
            st.download_button(
                "Export JSON",
                json.dumps(export_data, indent=2, default=str),
                f"search_{search_term[:20]}.json",
                "application/json",
                width="stretch"
            )
        with col2:
            csv_rows = [{"source": r["source"], "matched": r["matched_fields"], "data": json.dumps(r["data"], default=str)[:500]} for r in all_results[:max_results]]
            st.download_button(
                "Export CSV",
                pd.DataFrame(csv_rows).to_csv(index=False),
                f"search_{search_term[:20]}.csv",
                "text/csv",
                width="stretch"
            )
    else:
        st.warning(f"No results found for '{search_term}'")


def render_pivot_mode(evidence_folder: str):
    """Render the pivot/correlate interface."""

    st.markdown('<div style="color:#e6edf3;font-size:1.1rem;margin-bottom:15px;"><b>Pivot & Correlate</b> - Enter any IOC to see all related artifacts</div>', unsafe_allow_html=True)

    with st.form(key="pivot_form", clear_on_submit=False):
        col1, col2 = st.columns([4, 1])
        with col1:
            pivot_indicator = st.text_input(
                "Pivot Indicator",
                placeholder="Enter IP, hash, process name, domain, file path...",
                key="pivot_input",
                label_visibility="collapsed"
            )
        with col2:
            pivot_submitted = st.form_submit_button("Pivot", type="primary")

    if pivot_indicator and pivot_submitted:
        engine = PivotEngine(evidence_folder)
        with st.spinner(f"Pivoting on '{pivot_indicator}'..."):
            context = engine.pivot(pivot_indicator)

        log_pivot(pivot_indicator, context.total_matches)

        if context.total_matches > 0:
            st.session_state.pivot_results = context
            st.session_state.pivot_term = pivot_indicator
        else:
            st.warning(f"No matches found for '{pivot_indicator}'")
            return

    # Display cached pivot results
    if 'pivot_results' in st.session_state and st.session_state.get('pivot_term'):
        context = st.session_state.pivot_results
        render_pivot_results(context)
    elif not pivot_indicator:
        st.markdown("""
**Pivot examples:** IP address, file hash (MD5/SHA256), process name, domain, username, file path
        """)


def render_pivot_results(context):
    """Render pivot results."""

    st.markdown(f"**Pivoting on:** `{context.indicator}` ({context.indicator_type.value}) - **{context.total_matches} matches**")

    # Group by source
    sources = {}
    for result in context.results:
        source = result.source
        if source not in sources:
            sources[source] = []
        sources[source].append(result)

    # Summary
    summary_text = " | ".join([f"{src}: {len(items)}" for src, items in sources.items()])
    st.caption(summary_text)

    # Results by source
    source_order = sorted(sources.keys(), key=lambda x: len(sources[x]), reverse=True)
    for source in source_order:
        results = sources[source]
        with st.expander(f"{source} ({len(results)} matches)", expanded=(len(results) <= 5)):
            render_pivot_source_results(source, results)

    # Related indicators
    if context.related_indicators:
        st.markdown("---")
        st.markdown("**Related Indicators:**")
        related_list = list(context.related_indicators)[:12]
        st.code("  |  ".join(related_list), language=None)


def render_source_results(source: str, items: list):
    """Render search results for a source."""
    display_data = []
    for item in items:
        data = item["data"]
        row = {"Matched": item["matched_fields"]}

        if source == "Processes":
            row["Name"] = data.get("name", "")
            row["PID"] = data.get("pid", "")
            row["Command"] = str(data.get("cmdline", ""))[:80]
        elif source == "Network":
            row["Local"] = data.get("laddr", "")
            row["Remote"] = data.get("raddr", "")
            row["Status"] = data.get("status", "")
        elif source == "Files":
            row["Filename"] = data.get("filename", "")
            row["Path"] = str(data.get("path", ""))[:60]
        elif source == "DNS":
            row["Entry"] = data.get("Entry", data.get("Record Name", ""))
            row["Data"] = str(data.get("Data", ""))[:50]
        elif source == "Events":
            row["ID"] = data.get("Id", "")
            row["Provider"] = str(data.get("ProviderName", ""))[:25]
            row["Message"] = str(data.get("Message", ""))[:80]
        elif source == "Findings":
            row["Category"] = data.get("category", "")
            row["Severity"] = data.get("severity", "")
        else:
            for key, value in list(data.items())[:4]:
                row[key[:12]] = str(value)[:50] if value else ""

        display_data.append(row)

    if display_data:
        st.dataframe(pd.DataFrame(display_data), width="stretch", hide_index=True)


def render_pivot_source_results(source: str, results: list):
    """Render pivot results for a source."""
    display_data = []
    for result in results:
        data = result.data
        row = {"Matched": result.matched_field}

        if source == "Processes":
            row["Name"] = data.get("name", "")
            row["PID"] = data.get("pid", "")
            row["Command"] = str(data.get("cmdline", ""))[:70]
        elif source == "Network":
            row["Local"] = data.get("laddr", "")
            row["Remote"] = data.get("raddr", "")
            row["Status"] = data.get("status", "")
        elif source == "DNS":
            row["Entry"] = data.get("Entry", data.get("Record Name", ""))
            row["Data"] = str(data.get("Data", ""))[:40]
        elif source == "Files":
            row["Filename"] = data.get("filename", "")
            row["Path"] = str(data.get("path", ""))[:50]
        elif source == "Events":
            row["ID"] = data.get("Id", "")
            row["Provider"] = str(data.get("ProviderName", ""))[:25]
        else:
            for key, value in list(data.items())[:4]:
                if not key.startswith('_'):
                    row[key[:12]] = str(value)[:40] if value else ""

        display_data.append(row)

    if display_data:
        st.dataframe(pd.DataFrame(display_data), width="stretch", hide_index=True)
