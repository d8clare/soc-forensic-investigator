"""
Pivot Modal Component - UI for displaying cross-artifact correlations.
Shows all related artifacts when an analyst clicks on an IOC.
"""
import streamlit as st
import pandas as pd
import json
from typing import Optional

from core.pivot_engine import PivotEngine, PivotContext, PivotType
from core.security import escape_html


def show_pivot_modal(evidence_folder: str, indicator: Optional[str] = None):
    """
    Display a pivot search modal/section for investigating an indicator.

    Args:
        evidence_folder: Path to evidence folder
        indicator: Optional pre-filled indicator to search
    """
    engine = PivotEngine(evidence_folder)

    # Pivot search input
    st.markdown('''<div style="background:linear-gradient(135deg,#1a1a2e 0%,#0f3460 100%);border-radius:10px;padding:20px;margin-bottom:20px;border:1px solid rgba(102,126,234,0.3);">
<div style="display:flex;align-items:center;gap:15px;margin-bottom:15px;">
<div style="font-size:2rem;">🔗</div>
<div>
<div style="font-size:1.2rem;font-weight:bold;color:white;">Pivot & Correlate</div>
<div style="color:#888;font-size:0.85rem;">Click any IOC to see ALL related artifacts across the investigation</div>
</div>
</div>
</div>''', unsafe_allow_html=True)

    # Input row
    col1, col2 = st.columns([4, 1])
    with col1:
        search_indicator = st.text_input(
            "Pivot Indicator",
            value=indicator or "",
            placeholder="Enter IP, hash, process name, domain, file path, or username...",
            key="pivot_search_input",
            label_visibility="collapsed"
        )
    with col2:
        pivot_button = st.button("🔗 Pivot", type="primary", width="stretch")

    # Quick pivot from session state (clicked from tables)
    if 'pivot_indicator' in st.session_state and st.session_state.pivot_indicator:
        search_indicator = st.session_state.pivot_indicator
        st.session_state.pivot_indicator = None
        pivot_button = True

    if search_indicator and pivot_button:
        with st.spinner(f"Pivoting on '{search_indicator}'..."):
            context = engine.pivot(search_indicator)

        if context.total_matches > 0:
            render_pivot_results(context, engine)
        else:
            st.warning(f"No matches found for '{escape_html(search_indicator)}'")
            st.info("Try:\n- Different spelling or partial matches\n- Just the filename without path\n- IP without port number")


def render_pivot_results(context: PivotContext, engine: PivotEngine):
    """Render the results of a pivot operation."""

    # Type indicator with icon
    type_icons = {
        PivotType.IP: ("🌐", "#48dbfb"),
        PivotType.HASH: ("🔐", "#ff6b6b"),
        PivotType.PROCESS: ("⚙️", "#feca57"),
        PivotType.DOMAIN: ("🌍", "#1dd1a1"),
        PivotType.FILE: ("📄", "#667eea"),
        PivotType.USER: ("👤", "#a29bfe"),
        PivotType.REGISTRY: ("📝", "#fd79a8"),
        PivotType.COMMAND: ("💻", "#74b9ff"),
    }

    icon, color = type_icons.get(context.indicator_type, ("🔍", "#667eea"))

    # Summary header
    st.markdown(f'''<div style="background:linear-gradient(135deg,{color}22 0%,{color}11 100%);border-left:4px solid {color};border-radius:0 10px 10px 0;padding:20px;margin:20px 0;">
<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:15px;">
<div style="display:flex;align-items:center;gap:15px;">
<div style="font-size:2.5rem;">{icon}</div>
<div>
<div style="color:#888;font-size:0.75rem;text-transform:uppercase;letter-spacing:1px;">Pivoting on {context.indicator_type.value.upper()}</div>
<div style="color:white;font-size:1.3rem;font-weight:bold;font-family:monospace;word-break:break-all;">{escape_html(context.indicator)}</div>
</div>
</div>
<div style="display:flex;gap:15px;">
<div style="text-align:center;padding:10px 20px;background:rgba(255,255,255,0.05);border-radius:8px;">
<div style="color:{color};font-size:1.8rem;font-weight:bold;">{context.total_matches}</div>
<div style="color:#888;font-size:0.7rem;text-transform:uppercase;">Matches</div>
</div>
<div style="text-align:center;padding:10px 20px;background:rgba(255,255,255,0.05);border-radius:8px;">
<div style="color:{color};font-size:1.8rem;font-weight:bold;">{context.sources_searched}</div>
<div style="color:#888;font-size:0.7rem;text-transform:uppercase;">Sources</div>
</div>
</div>
</div>
</div>''', unsafe_allow_html=True)

    # Group results by source
    sources = {}
    for result in context.results:
        source = result.source
        if source not in sources:
            sources[source] = []
        sources[source].append(result)

    # Source overview cards
    st.markdown("### 📊 Matches by Source")
    cols = st.columns(min(len(sources), 6))
    source_order = sorted(sources.keys(), key=lambda x: len(sources[x]), reverse=True)

    for i, source in enumerate(source_order[:6]):
        count = len(sources[source])
        with cols[i]:
            severity_color = "#28a745" if count < 3 else "#feca57" if count < 10 else "#ff6b6b"
            st.markdown(f'''<div style="background:rgba(102,126,234,0.1);border-radius:8px;padding:12px;text-align:center;border:1px solid {severity_color}40;">
<div style="color:{severity_color};font-size:1.5rem;font-weight:bold;">{count}</div>
<div style="color:#888;font-size:0.75rem;">{source}</div>
</div>''', unsafe_allow_html=True)

    st.markdown("---")

    # Detailed results by source type
    for source in source_order:
        results = sources[source]
        with st.expander(f"📁 {source} ({len(results)} matches)", expanded=(len(results) <= 5)):
            render_source_results(source, results)

    # Related indicators section
    if context.related_indicators:
        st.markdown("### 🔗 Related Indicators")
        st.markdown("*Click to pivot on these related IOCs:*")

        related_list = list(context.related_indicators)[:20]
        cols = st.columns(4)

        for i, related in enumerate(related_list):
            with cols[i % 4]:
                if st.button(f"🔗 {related[:30]}", key=f"pivot_{related[:20]}_{i}", width="stretch"):
                    st.session_state.pivot_indicator = related
                    st.rerun()


def render_source_results(source: str, results: list):
    """Render results for a specific source with appropriate formatting."""

    display_data = []

    for result in results:
        data = result.data
        row = {"Matched": result.matched_field}

        # Source-specific column extraction
        if source == "Processes":
            row["Name"] = data.get("name", "")
            row["PID"] = data.get("pid", "")
            row["Command"] = str(data.get("cmdline", ""))[:80]
            row["User"] = data.get("username", "")

        elif source == "Network":
            row["Local"] = data.get("laddr", "")
            row["Remote"] = data.get("raddr", "")
            row["Status"] = data.get("status", "")
            row["PID"] = data.get("pid", "")

        elif source == "DNS":
            row["Entry"] = data.get("Entry", data.get("Record Name", ""))
            row["Type"] = data.get("Record Type", data.get("Type", ""))
            row["Data"] = str(data.get("Data", ""))[:50]

        elif source == "Files":
            row["Filename"] = data.get("filename", "")
            row["Path"] = str(data.get("path", ""))[:60]
            row["Hash"] = str(data.get("sha256", data.get("md5", "")))[:20] + "..."

        elif source in ["Browser", "Firefox"]:
            row["Title"] = str(data.get("title", ""))[:40]
            row["URL"] = str(data.get("url", ""))[:60]
            row["Visits"] = data.get("visit_count", data.get("visits", ""))

        elif source == "Registry":
            row["Key"] = str(data.get("Key", data.get("Path", "")))[:50]
            row["Name"] = data.get("Name", "")
            row["Value"] = str(data.get("Value", data.get("Data", "")))[:50]

        elif source == "Tasks":
            row["Name"] = data.get("TaskName", "")
            row["Action"] = str(data.get("Action", ""))[:60]
            row["State"] = data.get("State", "")

        elif source == "Services":
            row["Name"] = data.get("Name", "")
            row["Path"] = str(data.get("BinPath", ""))[:60]
            row["State"] = data.get("State", data.get("Status", ""))

        elif source == "Events":
            row["ID"] = data.get("Id", "")
            row["Provider"] = data.get("ProviderName", "")[:30]
            row["Time"] = str(data.get("TimeCreated", ""))[:19]
            row["Message"] = str(data.get("Message", ""))[:60]

        elif source == "Shimcache":
            row["Path"] = str(data.get("path", ""))[:80]
            row["Modified"] = data.get("last_modified", "")

        elif source == "Startup":
            row["Filename"] = data.get("Filename", data.get("filename", ""))
            row["Path"] = str(data.get("Path", data.get("path", "")))[:60]

        elif source == "WMI":
            row["Name"] = data.get("Name", "")
            row["Type"] = data.get("__CLASS", data.get("type", ""))
            row["Command"] = str(data.get("Command", data.get("CommandLineTemplate", "")))[:50]

        elif source == "BITS":
            row["Name"] = data.get("DisplayName", "")
            row["URL"] = str(data.get("RemoteUrl", data.get("Files", "")))[:60]
            row["State"] = data.get("JobState", "")

        else:
            # Generic display - take first 4 fields
            for key, value in list(data.items())[:4]:
                if not key.startswith('_'):
                    row[key[:15]] = str(value)[:50] if value else ""

        display_data.append(row)

    if display_data:
        df = pd.DataFrame(display_data)
        st.dataframe(df, width="stretch", hide_index=True)


def create_pivot_button(value: str, button_key: str = None) -> bool:
    """
    Create a small pivot button that sets the pivot indicator in session state.

    Args:
        value: The value to pivot on when clicked
        button_key: Unique key for the button

    Returns:
        True if clicked
    """
    key = button_key or f"pv_{hash(value)}"
    if st.button("🔗", key=key, help=f"Pivot on: {value[:50]}"):
        st.session_state.pivot_indicator = value
        st.session_state.pivot_tab_selected = True
        return True
    return False


def render_pivotable_value(value: str, display_text: str = None, max_len: int = 50):
    """
    Render a value with an inline pivot link.

    Args:
        value: The actual value to pivot on
        display_text: Optional display text (defaults to value)
        max_len: Maximum display length
    """
    display = display_text or value
    if len(display) > max_len:
        display = display[:max_len] + "..."

    col1, col2 = st.columns([0.9, 0.1])
    with col1:
        st.code(display, language=None)
    with col2:
        if st.button("🔗", key=f"pv_{hash(value)}_{hash(display)}", help=f"Pivot on {value[:30]}"):
            st.session_state.pivot_indicator = value
            st.rerun()


def add_pivot_column_to_dataframe(df: pd.DataFrame, value_column: str, button_prefix: str = ""):
    """
    Add a pivot button column to a dataframe.

    Args:
        df: DataFrame to modify
        value_column: Column containing values to pivot on
        button_prefix: Prefix for button keys
    """
    # This adds visual cues but actual interactivity requires JS
    df['🔗'] = df[value_column].apply(
        lambda x: f"🔗 {str(x)[:20]}" if x else ""
    )
    return df
