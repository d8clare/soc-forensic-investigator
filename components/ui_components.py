"""
Standardized UI Components for SOC Dashboard.
Provides consistent styling across all tabs.
"""
import streamlit as st
from typing import Optional, List, Dict, Any
from config.theme import THEME, get_risk_color, get_severity_color


# =============================================================================
# METRIC CARDS
# =============================================================================

def metric_card(label: str, value: Any, icon: str = "", delta: str = "",
                delta_color: str = "normal", size: str = "medium") -> None:
    """
    Render a styled metric card.

    Args:
        label: Metric label
        value: Metric value
        icon: Optional emoji icon
        delta: Optional delta text
        delta_color: 'good', 'bad', or 'normal'
        size: 'small', 'medium', or 'large'
    """
    sizes = {
        "small": ("1.2rem", "0.7rem", "10px 15px"),
        "medium": ("1.8rem", "0.85rem", "15px 20px"),
        "large": ("2.5rem", "1rem", "20px 25px")
    }
    value_size, label_size, padding = sizes.get(size, sizes["medium"])

    delta_html = ""
    if delta:
        d_color = "#28a745" if delta_color == "good" else "#dc3545" if delta_color == "bad" else "#888"
        delta_html = f'<div style="color:{d_color};font-size:0.75rem;margin-top:4px;">{delta}</div>'

    icon_html = f'<span style="margin-right:8px;">{icon}</span>' if icon else ""

    st.markdown(f'''<div style="background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);border-radius:10px;padding:{padding};border:1px solid rgba(102,126,234,0.2);text-align:center;">
<div style="color:#888;font-size:{label_size};margin-bottom:5px;">{icon_html}{label}</div>
<div style="color:white;font-size:{value_size};font-weight:bold;">{value}</div>
{delta_html}
</div>''', unsafe_allow_html=True)


def risk_metric(score: int, label: str = "Risk Score") -> None:
    """Render a risk score metric with color coding."""
    color = get_risk_color(score)
    st.markdown(f'''<div style="background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);border-radius:10px;padding:15px 20px;border:2px solid {color};text-align:center;">
<div style="color:#888;font-size:0.85rem;margin-bottom:5px;">{label}</div>
<div style="color:{color};font-size:2.2rem;font-weight:bold;">{min(score, 100)}</div>
</div>''', unsafe_allow_html=True)


def stat_row(stats: List[Dict[str, Any]]) -> None:
    """
    Render a row of statistics.

    Args:
        stats: List of dicts with keys: label, value, icon (optional), color (optional)
    """
    cols = st.columns(len(stats))
    for col, stat in zip(cols, stats):
        with col:
            color = stat.get("color", "white")
            icon = stat.get("icon", "")
            st.markdown(f'''<div style="background:rgba(30,30,46,0.5);border-radius:8px;padding:12px;text-align:center;">
<div style="color:#888;font-size:0.75rem;">{icon} {stat["label"]}</div>
<div style="color:{color};font-size:1.3rem;font-weight:bold;">{stat["value"]}</div>
</div>''', unsafe_allow_html=True)


# =============================================================================
# BADGES & INDICATORS
# =============================================================================

def severity_badge(severity: str, text: Optional[str] = None) -> str:
    """
    Generate HTML for a severity badge.

    Args:
        severity: 'critical', 'high', 'medium', 'low', 'info'
        text: Optional custom text

    Returns:
        HTML string
    """
    color = get_severity_color(severity)
    display = text or severity.upper()
    return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:0.8rem;font-weight:600;">{display}</span>'


def status_indicator(status: str, size: int = 10) -> str:
    """
    Generate HTML for a status indicator dot.

    Args:
        status: 'online', 'offline', 'warning', 'error'
        size: Dot size in pixels

    Returns:
        HTML string
    """
    colors = {
        "online": "#28a745",
        "offline": "#6c757d",
        "warning": "#ffc107",
        "error": "#dc3545"
    }
    color = colors.get(status, "#6c757d")
    return f'<span style="display:inline-block;width:{size}px;height:{size}px;border-radius:50%;background:{color};box-shadow:0 0 8px {color};"></span>'


def mitre_badge(technique_id: str, name: str = "", url: str = "") -> None:
    """Render a MITRE ATT&CK technique badge."""
    link_url = url or f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
    name_display = f"<br><span style='font-size:0.65rem;color:#888;'>{name[:25]}</span>" if name else ""

    st.markdown(f'''<a href="{link_url}" target="_blank" style="text-decoration:none;">
<div style="background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);padding:8px 12px;border-radius:6px;text-align:center;border:1px solid #e94560;display:inline-block;">
<span style="color:#e94560;font-weight:bold;font-size:0.85rem;">{technique_id}</span>{name_display}
</div></a>''', unsafe_allow_html=True)


# =============================================================================
# EMPTY STATES
# =============================================================================

def empty_state(icon: str, title: str, message: str, suggestion: str = "") -> None:
    """
    Render an empty state placeholder.

    Args:
        icon: Emoji icon
        title: Main title
        message: Description message
        suggestion: Optional suggestion text
    """
    suggestion_html = f'<div style="color:#667eea;font-size:0.85rem;margin-top:12px;">{suggestion}</div>' if suggestion else ""

    st.markdown(f'''<div style="background:rgba(30,30,46,0.3);border:1px dashed rgba(102,126,234,0.3);border-radius:12px;padding:40px;text-align:center;margin:20px 0;">
<div style="font-size:3rem;margin-bottom:15px;opacity:0.7;">{icon}</div>
<div style="color:white;font-size:1.1rem;font-weight:600;margin-bottom:8px;">{title}</div>
<div style="color:#888;font-size:0.9rem;">{message}</div>
{suggestion_html}
</div>''', unsafe_allow_html=True)


def no_data_message(artifact_type: str = "data") -> None:
    """Render a standardized 'no data' message."""
    empty_state(
        icon="📭",
        title=f"No {artifact_type} Available",
        message=f"No {artifact_type.lower()} was collected or found in this evidence set.",
        suggestion="Run the collector again or check the evidence folder."
    )


def no_findings_message() -> None:
    """Render a 'no findings' message (positive)."""
    st.markdown('''<div style="background:rgba(40,167,69,0.1);border:1px solid rgba(40,167,69,0.3);border-radius:10px;padding:25px;text-align:center;">
<div style="font-size:2rem;margin-bottom:10px;">✅</div>
<div style="color:#28a745;font-size:1.1rem;font-weight:600;">No Suspicious Activity Detected</div>
<div style="color:#888;font-size:0.9rem;margin-top:8px;">This artifact category shows no signs of compromise.</div>
</div>''', unsafe_allow_html=True)


# =============================================================================
# SECTION HEADERS
# =============================================================================

def section_header(title: str, icon: str = "", subtitle: str = "",
                   badge: Optional[str] = None) -> None:
    """
    Render a styled section header.

    Args:
        title: Section title
        icon: Optional emoji icon
        subtitle: Optional subtitle text
        badge: Optional badge text (e.g., count)
    """
    icon_html = f'<span style="margin-right:10px;">{icon}</span>' if icon else ""
    subtitle_html = f'<div style="color:#888;font-size:0.85rem;margin-top:4px;">{subtitle}</div>' if subtitle else ""
    badge_html = f'<span style="background:#667eea;color:white;padding:2px 10px;border-radius:12px;font-size:0.8rem;margin-left:12px;">{badge}</span>' if badge else ""

    st.markdown(f'''<div style="border-bottom:1px solid rgba(102,126,234,0.2);padding-bottom:10px;margin-bottom:15px;">
<div style="display:flex;align-items:center;">
<span style="color:white;font-size:1.2rem;font-weight:600;">{icon_html}{title}</span>{badge_html}
</div>
{subtitle_html}
</div>''', unsafe_allow_html=True)


def info_banner(message: str, type: str = "info") -> None:
    """
    Render an info/warning/error banner.

    Args:
        message: Banner message
        type: 'info', 'warning', 'error', 'success'
    """
    configs = {
        "info": ("#17a2b8", "rgba(23,162,184,0.1)", "ℹ️"),
        "warning": ("#ffc107", "rgba(255,193,7,0.1)", "⚠️"),
        "error": ("#dc3545", "rgba(220,53,69,0.1)", "❌"),
        "success": ("#28a745", "rgba(40,167,69,0.1)", "✅")
    }
    color, bg, icon = configs.get(type, configs["info"])

    st.markdown(f'''<div style="background:{bg};border-left:4px solid {color};border-radius:0 8px 8px 0;padding:12px 16px;margin:10px 0;">
<span style="margin-right:8px;">{icon}</span>
<span style="color:{color};">{message}</span>
</div>''', unsafe_allow_html=True)


# =============================================================================
# CARDS & CONTAINERS
# =============================================================================

def evidence_card(title: str, items: List[Dict], icon: str = "📄") -> None:
    """
    Render an evidence summary card.

    Args:
        title: Card title
        items: List of dicts with 'label' and 'value' keys
        icon: Card icon
    """
    items_html = "".join([
        f'<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.05);"><span style="color:#888;">{item["label"]}</span><span style="color:white;font-weight:500;">{item["value"]}</span></div>'
        for item in items
    ])

    st.markdown(f'''<div style="background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);border-radius:10px;padding:20px;border:1px solid rgba(102,126,234,0.2);">
<div style="display:flex;align-items:center;margin-bottom:15px;">
<span style="font-size:1.5rem;margin-right:10px;">{icon}</span>
<span style="color:white;font-size:1.1rem;font-weight:600;">{title}</span>
</div>
{items_html}
</div>''', unsafe_allow_html=True)


def finding_card(severity: str, category: str, description: str,
                 score: int, evidence: str = "") -> None:
    """
    Render a finding/alert card.

    Args:
        severity: 'critical', 'high', 'medium', 'low'
        category: Finding category
        description: Finding description
        score: Risk score
        evidence: Optional evidence details
    """
    color = get_severity_color(severity)
    evidence_html = f'<div style="background:rgba(0,0,0,0.2);border-radius:4px;padding:8px;margin-top:10px;font-family:monospace;font-size:0.8rem;color:#aaa;">{evidence}</div>' if evidence else ""

    st.markdown(f'''<div style="background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);border-left:4px solid {color};border-radius:0 10px 10px 0;padding:15px 20px;margin:10px 0;">
<div style="display:flex;justify-content:space-between;align-items:center;">
<div>
<span style="background:{color};color:white;padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600;">{severity.upper()}</span>
<span style="color:white;font-weight:600;margin-left:10px;">{category}</span>
</div>
<span style="color:{color};font-weight:bold;">Score: {score}</span>
</div>
<div style="color:#ccc;margin-top:10px;font-size:0.9rem;">{description}</div>
{evidence_html}
</div>''', unsafe_allow_html=True)


# =============================================================================
# PROGRESS & LOADING
# =============================================================================

def loading_spinner(message: str = "Loading...") -> None:
    """Render a loading message with spinner."""
    st.markdown(f'''<div style="text-align:center;padding:30px;">
<div style="display:inline-block;width:30px;height:30px;border:3px solid rgba(102,126,234,0.3);border-top-color:#667eea;border-radius:50%;animation:spin 1s linear infinite;"></div>
<div style="color:#888;margin-top:15px;">{message}</div>
<style>@keyframes spin {{to {{transform: rotate(360deg);}}}}</style>
</div>''', unsafe_allow_html=True)


def progress_bar(current: int, total: int, label: str = "") -> None:
    """Render a custom progress bar."""
    percent = min(100, int((current / total) * 100)) if total > 0 else 0
    label_html = f'<span style="color:#888;font-size:0.8rem;">{label}</span>' if label else ""

    st.markdown(f'''<div style="margin:10px 0;">
{label_html}
<div style="background:rgba(102,126,234,0.2);border-radius:10px;height:8px;overflow:hidden;margin-top:5px;">
<div style="background:linear-gradient(90deg,#667eea,#764ba2);height:100%;width:{percent}%;border-radius:10px;transition:width 0.3s;"></div>
</div>
<div style="color:#888;font-size:0.75rem;text-align:right;margin-top:3px;">{current}/{total} ({percent}%)</div>
</div>''', unsafe_allow_html=True)
