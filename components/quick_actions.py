"""
Quick Actions Component - Context menu actions for artifact values.
Provides Copy, Search, Add to IOCs, Flag as suspicious functionality.
"""
import streamlit as st
import json
from typing import Optional, List, Dict, Any
from datetime import datetime

from core.security import escape_html


def init_quick_actions_state():
    """Initialize session state for quick actions."""
    if 'flagged_indicators' not in st.session_state:
        st.session_state.flagged_indicators = []
    if 'custom_iocs' not in st.session_state:
        st.session_state.custom_iocs = []
    if 'clipboard_value' not in st.session_state:
        st.session_state.clipboard_value = None


def add_to_iocs(value: str, ioc_type: str = "unknown", note: str = ""):
    """Add an indicator to the custom IOC list."""
    init_quick_actions_state()

    ioc = {
        "value": value,
        "type": ioc_type,
        "note": note,
        "added_at": datetime.now().isoformat(),
        "added_by": "analyst"
    }

    # Avoid duplicates
    if not any(i['value'] == value for i in st.session_state.custom_iocs):
        st.session_state.custom_iocs.append(ioc)
        return True
    return False


def flag_as_suspicious(value: str, reason: str = "", severity: str = "medium"):
    """Flag an indicator as suspicious for the investigation."""
    init_quick_actions_state()

    flag = {
        "value": value,
        "reason": reason,
        "severity": severity,
        "flagged_at": datetime.now().isoformat()
    }

    if not any(f['value'] == value for f in st.session_state.flagged_indicators):
        st.session_state.flagged_indicators.append(flag)
        return True
    return False


def get_flagged_indicators() -> List[Dict]:
    """Get list of flagged indicators."""
    init_quick_actions_state()
    return st.session_state.flagged_indicators


def get_custom_iocs() -> List[Dict]:
    """Get list of custom IOCs."""
    init_quick_actions_state()
    return st.session_state.custom_iocs


def remove_flag(value: str):
    """Remove a flag from an indicator."""
    init_quick_actions_state()
    st.session_state.flagged_indicators = [
        f for f in st.session_state.flagged_indicators if f['value'] != value
    ]


def remove_ioc(value: str):
    """Remove an IOC from the list."""
    init_quick_actions_state()
    st.session_state.custom_iocs = [
        i for i in st.session_state.custom_iocs if i['value'] != value
    ]


def render_quick_action_buttons(value: str, value_type: str = "unknown"):
    """
    Render quick action buttons for a value.

    Args:
        value: The indicator value
        value_type: Type hint (ip, hash, process, file, etc.)
    """
    init_quick_actions_state()

    cols = st.columns(4)

    with cols[0]:
        if st.button("📋 Copy", key=f"copy_{hash(value)}", width="stretch"):
            st.session_state.clipboard_value = value
            st.toast(f"Copied: {value[:30]}...", icon="📋")

    with cols[1]:
        if st.button("🔍 Search", key=f"search_{hash(value)}", width="stretch"):
            st.session_state.pivot_indicator = value
            st.toast(f"Searching for: {value[:30]}...", icon="🔍")
            st.rerun()

    with cols[2]:
        if st.button("📌 Add IOC", key=f"ioc_{hash(value)}", width="stretch"):
            if add_to_iocs(value, value_type):
                st.toast(f"Added to IOCs: {value[:30]}...", icon="📌")
            else:
                st.toast("Already in IOC list", icon="ℹ️")

    with cols[3]:
        if st.button("🚩 Flag", key=f"flag_{hash(value)}", width="stretch"):
            if flag_as_suspicious(value, severity="high"):
                st.toast(f"Flagged: {value[:30]}...", icon="🚩")
            else:
                st.toast("Already flagged", icon="ℹ️")


def render_action_menu(value: str, value_type: str = "unknown", compact: bool = False):
    """
    Render a compact action menu as a popover/expander.

    Args:
        value: The indicator value
        value_type: Type hint
        compact: Use more compact layout
    """
    init_quick_actions_state()

    with st.popover("⋯", width="content"):
        st.markdown(f"**Actions for:** `{escape_html(value[:40])}`")

        if st.button("📋 Copy to Clipboard", key=f"m_copy_{hash(value)}", width="stretch"):
            st.session_state.clipboard_value = value
            st.toast("Copied!", icon="📋")

        if st.button("🔗 Pivot / Search All", key=f"m_pivot_{hash(value)}", width="stretch"):
            st.session_state.pivot_indicator = value
            st.rerun()

        if st.button("📌 Add to IOC List", key=f"m_ioc_{hash(value)}", width="stretch"):
            add_to_iocs(value, value_type)
            st.toast("Added to IOCs", icon="📌")

        if st.button("🚩 Flag as Suspicious", key=f"m_flag_{hash(value)}", width="stretch"):
            flag_as_suspicious(value, severity="high")
            st.toast("Flagged!", icon="🚩")

        # External lookups
        st.markdown("---")
        st.markdown("**External Lookups:**")

        if value_type in ["hash", "unknown"] and len(value) in [32, 40, 64]:
            vt_url = f"https://www.virustotal.com/gui/search/{value}"
            st.markdown(f"[🦠 VirusTotal]({vt_url})")

        if value_type in ["ip", "unknown"]:
            # Check if it looks like an IP
            import re
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
                st.markdown(f"[🌐 AbuseIPDB](https://www.abuseipdb.com/check/{value})")
                st.markdown(f"[📍 Shodan](https://www.shodan.io/host/{value})")

        if value_type in ["domain", "unknown"]:
            if '.' in value and not value.replace('.', '').isdigit():
                st.markdown(f"[🔍 URLScan](https://urlscan.io/search/#{value})")


def render_flagged_sidebar():
    """Render a sidebar section showing flagged indicators and IOCs."""
    init_quick_actions_state()

    flagged = get_flagged_indicators()
    iocs = get_custom_iocs()

    if not flagged and not iocs:
        return

    st.sidebar.markdown("---")

    # Flagged indicators
    if flagged:
        st.sidebar.markdown(f"### 🚩 Flagged ({len(flagged)})")
        for flag in flagged[-5:]:  # Show last 5
            col1, col2 = st.sidebar.columns([0.8, 0.2])
            with col1:
                st.sidebar.code(flag['value'][:25], language=None)
            with col2:
                if st.sidebar.button("❌", key=f"rm_flag_{hash(flag['value'])}"):
                    remove_flag(flag['value'])
                    st.rerun()

    # Custom IOCs
    if iocs:
        st.sidebar.markdown(f"### 📌 IOCs ({len(iocs)})")
        for ioc in iocs[-5:]:
            col1, col2 = st.sidebar.columns([0.8, 0.2])
            with col1:
                st.sidebar.code(ioc['value'][:25], language=None)
            with col2:
                if st.sidebar.button("❌", key=f"rm_ioc_{hash(ioc['value'])}"):
                    remove_ioc(ioc['value'])
                    st.rerun()

    # Export buttons
    if flagged or iocs:
        st.sidebar.markdown("---")
        export_data = {
            "flagged": flagged,
            "iocs": iocs,
            "exported_at": datetime.now().isoformat()
        }
        st.sidebar.download_button(
            "📥 Export Flags/IOCs",
            json.dumps(export_data, indent=2),
            "investigation_iocs.json",
            "application/json",
            width="stretch"
        )


def render_investigation_notes():
    """Render a panel for investigation notes, flags, and IOCs."""
    init_quick_actions_state()

    flagged = get_flagged_indicators()
    iocs = get_custom_iocs()

    st.markdown("### 📝 Investigation Notes")

    tabs = st.tabs(["🚩 Flagged Indicators", "📌 Custom IOCs"])

    with tabs[0]:
        if flagged:
            for i, flag in enumerate(flagged):
                col1, col2, col3 = st.columns([0.6, 0.3, 0.1])
                with col1:
                    st.code(flag['value'], language=None)
                with col2:
                    st.caption(f"Flagged: {flag['flagged_at'][:10]}")
                with col3:
                    if st.button("🗑️", key=f"del_flag_{i}"):
                        remove_flag(flag['value'])
                        st.rerun()
        else:
            st.info("No indicators flagged yet. Use the 🚩 button on any value to flag it.")

    with tabs[1]:
        if iocs:
            df_data = []
            for ioc in iocs:
                df_data.append({
                    "Value": ioc['value'][:50],
                    "Type": ioc['type'],
                    "Added": ioc['added_at'][:10]
                })
            st.dataframe(df_data, width="stretch", hide_index=True)

            # Export
            st.download_button(
                "📥 Export IOC List",
                "\n".join([i['value'] for i in iocs]),
                "custom_iocs.txt",
                "text/plain"
            )
        else:
            st.info("No custom IOCs added yet. Use the 📌 button on any value to add it.")
