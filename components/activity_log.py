"""
Activity Logging Component - Tracks analyst actions for audit trail.
"""
import streamlit as st
import json
from datetime import datetime
from typing import Optional, List, Dict
from dataclasses import dataclass, asdict


@dataclass
class ActivityEntry:
    """Represents a single activity log entry."""
    timestamp: str
    action: str
    category: str
    details: str
    artifact: Optional[str] = None


def init_activity_log():
    """Initialize activity log in session state."""
    if 'activity_log' not in st.session_state:
        st.session_state.activity_log = []


def log_activity(action: str, category: str, details: str = "", artifact: str = None):
    """
    Log an analyst activity.

    Args:
        action: Action type (search, pivot, flag, export, view, etc.)
        category: Category of activity (search, investigation, export, navigation)
        details: Additional details about the action
        artifact: Optional artifact value involved
    """
    init_activity_log()

    entry = ActivityEntry(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        action=action,
        category=category,
        details=details,
        artifact=artifact
    )

    st.session_state.activity_log.append(asdict(entry))

    # Keep only last 500 entries to prevent memory issues
    if len(st.session_state.activity_log) > 500:
        st.session_state.activity_log = st.session_state.activity_log[-500:]


def get_activity_log() -> List[Dict]:
    """Get the activity log."""
    init_activity_log()
    return st.session_state.activity_log


def clear_activity_log():
    """Clear the activity log."""
    st.session_state.activity_log = []


def export_activity_log() -> str:
    """Export activity log as JSON string."""
    init_activity_log()
    export_data = {
        "exported_at": datetime.now().isoformat(),
        "session_activities": st.session_state.activity_log
    }
    return json.dumps(export_data, indent=2)


def render_activity_sidebar():
    """Render a compact activity log in the sidebar."""
    init_activity_log()

    activities = st.session_state.activity_log[-10:]  # Last 10 activities

    if not activities:
        return

    st.sidebar.markdown("---")
    st.sidebar.markdown("### 📋 Recent Activity")

    for activity in reversed(activities):
        icon = {
            "search": "🔍",
            "pivot": "🔗",
            "flag": "🚩",
            "export": "📥",
            "view": "👁️",
            "navigation": "📍"
        }.get(activity.get("category", ""), "•")

        time_short = activity.get("timestamp", "")[-8:]  # Just HH:MM:SS
        action = activity.get("action", "")[:30]

        st.sidebar.markdown(
            f'<div style="font-size:0.75rem;color:#888;padding:3px 0;">'
            f'{icon} <span style="color:#aaa;">{time_short}</span> {action}'
            f'</div>',
            unsafe_allow_html=True
        )

    # Export button
    if st.sidebar.button("📥 Export Activity Log", width="stretch", key="export_activity"):
        log_data = export_activity_log()
        st.sidebar.download_button(
            "Download JSON",
            log_data,
            f"activity_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "application/json",
            key="download_activity"
        )


def render_full_activity_log():
    """Render the full activity log in a panel."""
    init_activity_log()

    activities = st.session_state.activity_log

    st.markdown("### 📋 Investigation Activity Log")
    st.caption(f"{len(activities)} activities recorded in this session")

    if not activities:
        st.info("No activities recorded yet. Your searches, pivots, and other actions will appear here.")
        return

    # Filter options
    col1, col2 = st.columns([2, 1])
    with col1:
        filter_category = st.selectbox(
            "Filter by Category",
            ["All"] + list(set(a.get("category", "") for a in activities)),
            key="activity_filter"
        )

    # Apply filter
    if filter_category != "All":
        activities = [a for a in activities if a.get("category") == filter_category]

    # Display as table
    import pandas as pd
    df = pd.DataFrame(activities)

    if not df.empty:
        # Reorder columns
        cols = ["timestamp", "category", "action", "details", "artifact"]
        cols = [c for c in cols if c in df.columns]
        df = df[cols]

        st.dataframe(
            df.sort_values("timestamp", ascending=False),
            width="stretch",
            hide_index=True,
            column_config={
                "timestamp": st.column_config.TextColumn("Time", width="small"),
                "category": st.column_config.TextColumn("Category", width="small"),
                "action": st.column_config.TextColumn("Action", width="medium"),
                "details": st.column_config.TextColumn("Details", width="large"),
                "artifact": st.column_config.TextColumn("Artifact", width="medium")
            }
        )

    # Export button
    col1, col2 = st.columns(2)
    with col1:
        st.download_button(
            "📥 Export Activity Log (JSON)",
            export_activity_log(),
            f"activity_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "application/json",
            width="stretch"
        )
    with col2:
        if st.button("🗑️ Clear Activity Log", width="stretch"):
            clear_activity_log()
            st.rerun()


# Convenience functions for common activities
def log_search(query: str, results_count: int = 0):
    """Log a search action."""
    log_activity(
        action=f"Searched for '{query[:50]}'" + ("..." if len(query) > 50 else ""),
        category="search",
        details=f"Found {results_count} results",
        artifact=query
    )


def log_pivot(indicator: str, matches: int = 0):
    """Log a pivot action."""
    log_activity(
        action=f"Pivoted on indicator",
        category="pivot",
        details=f"Found {matches} related artifacts",
        artifact=indicator
    )


def log_flag(value: str, reason: str = ""):
    """Log a flag action."""
    log_activity(
        action=f"Flagged as suspicious",
        category="flag",
        details=reason,
        artifact=value
    )


def log_export(export_type: str, item_count: int = 0):
    """Log an export action."""
    log_activity(
        action=f"Exported {export_type}",
        category="export",
        details=f"{item_count} items exported"
    )


def log_tab_view(tab_name: str):
    """Log a tab view."""
    log_activity(
        action=f"Viewed {tab_name} tab",
        category="navigation"
    )
