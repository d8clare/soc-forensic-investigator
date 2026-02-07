"""
Loading and progress indicator components.
Provides consistent loading states across the dashboard.
"""
import streamlit as st
import logging
import traceback
from contextlib import contextmanager
from functools import wraps
from typing import Optional, Callable

logger = logging.getLogger(__name__)


@contextmanager
def loading_spinner(message: str = "Loading...", show_progress: bool = False):
    """
    Context manager for showing a loading spinner.

    Usage:
        with loading_spinner("Analyzing evidence..."):
            do_heavy_work()
    """
    with st.spinner(message):
        yield


def show_loading_placeholder(message: str = "Loading data...", icon: str = "⏳"):
    """Show a styled loading placeholder."""
    st.markdown(f'''
        <div style="background:#1e1e2e;border-radius:10px;padding:40px;text-align:center;margin:20px 0;">
            <div style="font-size:2.5rem;margin-bottom:15px;animation:pulse 1.5s infinite;">{icon}</div>
            <div style="color:#888;font-size:1rem;">{message}</div>
        </div>
        <style>
            @keyframes pulse {{
                0%, 100% {{ opacity: 1; }}
                50% {{ opacity: 0.5; }}
            }}
        </style>
    ''', unsafe_allow_html=True)


def show_empty_state(
    title: str,
    message: str,
    icon: str = "📭",
    suggestion: Optional[str] = None
):
    """Show a styled empty state when no data is available."""
    suggestion_html = ""
    if suggestion:
        suggestion_html = f'<div style="color:#667eea;font-size:0.85rem;margin-top:12px;padding:10px;background:rgba(102,126,234,0.1);border-radius:6px;">{suggestion}</div>'

    st.markdown(f'''
        <div style="background:#1e1e2e;border-radius:10px;padding:40px;text-align:center;margin:20px 0;">
            <div style="font-size:3rem;margin-bottom:15px;">{icon}</div>
            <div style="color:white;font-size:1.2rem;font-weight:600;margin-bottom:8px;">{title}</div>
            <div style="color:#888;font-size:0.9rem;">{message}</div>
            {suggestion_html}
        </div>
    ''', unsafe_allow_html=True)


def show_error_state(
    title: str,
    message: str,
    error_details: Optional[str] = None,
    suggestion: Optional[str] = None
):
    """Show a styled error state."""
    details_html = ""
    if error_details:
        details_html = f'<div style="font-family:monospace;font-size:0.75rem;color:#888;margin-top:10px;padding:8px;background:#0d1117;border-radius:4px;word-break:break-all;">{error_details}</div>'

    suggestion_html = ""
    if suggestion:
        suggestion_html = f'<div style="color:#58a6ff;font-size:0.85rem;margin-top:12px;">💡 {suggestion}</div>'

    st.markdown(f'''
        <div style="background:rgba(248,81,73,0.1);border:1px solid #f85149;border-radius:10px;padding:25px;text-align:center;margin:20px 0;">
            <div style="font-size:2.5rem;margin-bottom:10px;">⚠️</div>
            <div style="color:#f85149;font-size:1.1rem;font-weight:600;margin-bottom:8px;">{title}</div>
            <div style="color:#888;font-size:0.9rem;">{message}</div>
            {details_html}
            {suggestion_html}
        </div>
    ''', unsafe_allow_html=True)


def show_partial_data_warning(loaded: int, failed: int, failed_files: list = None):
    """Show a warning when some data failed to load."""
    if failed == 0:
        return

    files_html = ""
    if failed_files:
        files_list = ", ".join(failed_files[:5])
        if len(failed_files) > 5:
            files_list += f" (+{len(failed_files) - 5} more)"
        files_html = f'<div style="font-size:0.8rem;color:#888;margin-top:5px;">Failed: {files_list}</div>'

    st.markdown(f'''
        <div style="background:rgba(210,153,34,0.1);border-left:4px solid #d29922;border-radius:0 8px 8px 0;padding:12px 16px;margin:10px 0;">
            <div style="color:#d29922;font-weight:600;font-size:0.9rem;">⚠️ Partial Data Loaded</div>
            <div style="color:#888;font-size:0.85rem;margin-top:4px;">
                Loaded {loaded} artifact(s), but {failed} file(s) could not be read.
            </div>
            {files_html}
        </div>
    ''', unsafe_allow_html=True)


def show_success_toast(message: str):
    """Show a success notification."""
    st.toast(message, icon="✅")


def show_info_banner(message: str, icon: str = "ℹ️"):
    """Show an informational banner."""
    st.markdown(f'''
        <div style="background:rgba(88,166,255,0.1);border-left:4px solid #58a6ff;border-radius:0 8px 8px 0;padding:12px 16px;margin:10px 0;">
            <div style="color:#58a6ff;font-size:0.9rem;">{icon} {message}</div>
        </div>
    ''', unsafe_allow_html=True)


def safe_render(tab_name: str):
    """
    Decorator to wrap tab render functions with error handling.

    Usage:
        @safe_render("Processes")
        def render(evidence_folder, risk_engine):
            ...
    """
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logger.error("Error rendering %s tab: %s", tab_name, str(e))
                logger.debug(traceback.format_exc())

                error_msg = str(e)
                if len(error_msg) > 200:
                    error_msg = error_msg[:200] + "..."

                show_error_state(
                    title=f"Error Loading {tab_name}",
                    message="An error occurred while rendering this tab.",
                    error_details=error_msg,
                    suggestion="Try refreshing the page or check if evidence files are valid."
                )
        return wrapper
    return decorator


def handle_missing_data(data, data_name: str, required: bool = False):
    """
    Check if data is available and show appropriate message if not.

    Args:
        data: The data to check (list, dict, or DataFrame)
        data_name: Human-readable name of the data
        required: If True, show error. If False, show info.

    Returns:
        True if data is available, False otherwise
    """
    is_empty = data is None or (hasattr(data, '__len__') and len(data) == 0)

    if is_empty:
        if required:
            show_error_state(
                title=f"No {data_name} Found",
                message=f"The {data_name.lower()} data is required but was not found.",
                suggestion="Ensure the collector ran successfully and the evidence files exist."
            )
        else:
            show_empty_state(
                title=f"No {data_name} Available",
                message=f"No {data_name.lower()} data was collected or the file is empty.",
                icon="📭"
            )
        return False
    return True
