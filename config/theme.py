"""
Centralized theme and styling configuration for SOC Dashboard.
"""
from dataclasses import dataclass
from typing import Optional


@dataclass
class ThemeColors:
    """Centralized color definitions for the dashboard."""
    # Risk score colors
    RISK_LOW: str = "#28a745"
    RISK_MEDIUM: str = "#ffc107"
    RISK_HIGH: str = "#dc3545"
    RISK_CRITICAL: str = "#7b2d26"

    # Severity badge colors
    SEVERITY_INFO: str = "#17a2b8"
    SEVERITY_WARNING: str = "#ffc107"
    SEVERITY_DANGER: str = "#dc3545"
    SEVERITY_CRITICAL: str = "#7b2d26"

    # Timeline event type colors
    EVENT_LOG: str = "#e6f3ff"
    BROWSER: str = "#fff0e6"
    USB: str = "#e6ffe6"
    PROCESS: str = "#ffe6e6"
    FILE_SYSTEM: str = "#f0f0ff"
    NETWORK: str = "#fff5e6"

    # Table row highlighting (dark mode compatible - using darker tones)
    ROW_HIGH_RISK: str = "rgba(220, 53, 69, 0.25)"
    ROW_MEDIUM_RISK: str = "rgba(255, 193, 7, 0.25)"
    ROW_LOW_RISK: str = "rgba(40, 167, 69, 0.15)"
    ROW_SUSPICIOUS: str = "rgba(255, 193, 7, 0.2)"
    ROW_INFO: str = "rgba(23, 162, 184, 0.15)"
    ROW_NORMAL: str = ""

    # Status colors
    SIGNATURE_VALID: str = "#28a745"
    SIGNATURE_INVALID: str = "#dc3545"

    # UI colors
    BORDER_PRIMARY: str = "#007bff"
    BACKGROUND_LIGHT: str = "#f8f9fa"
    TEXT_PRIMARY: str = "#333"
    TEXT_MUTED: str = "#6c757d"


# Global theme instance
THEME = ThemeColors()


def get_risk_color(score: int) -> str:
    """
    Get the appropriate color for a risk score.

    Args:
        score: Risk score from 0-100

    Returns:
        Hex color string
    """
    if score >= 80:
        return THEME.RISK_CRITICAL
    elif score >= 60:
        return THEME.RISK_HIGH
    elif score >= 30:
        return THEME.RISK_MEDIUM
    else:
        return THEME.RISK_LOW


def get_severity_color(severity: str) -> str:
    """
    Get the appropriate color for a severity level.

    Args:
        severity: One of 'info', 'low', 'medium', 'high', 'critical'

    Returns:
        Hex color string
    """
    severity = severity.lower()
    if severity == "critical":
        return THEME.SEVERITY_CRITICAL
    elif severity in ("high", "danger"):
        return THEME.SEVERITY_DANGER
    elif severity in ("medium", "warning"):
        return THEME.SEVERITY_WARNING
    else:
        return THEME.SEVERITY_INFO


def style_risk_badge(level: str, text: Optional[str] = None) -> str:
    """
    Generate HTML for a styled risk badge.

    Args:
        level: Risk level ('low', 'medium', 'high', 'critical')
        text: Optional custom text for the badge

    Returns:
        HTML string for the badge
    """
    color = get_severity_color(level)
    display_text = text or level.upper()

    return f"""
    <span style="
        background-color: {color};
        color: white;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.85em;
        font-weight: bold;
    ">{display_text}</span>
    """


def style_score_display(score: int, label: str = "Risk Score") -> str:
    """
    Generate HTML for a large score display box.

    Args:
        score: Numeric score (0-100)
        label: Label text below the score

    Returns:
        HTML string for the score display
    """
    color = get_risk_color(score)
    capped_score = min(score, 100)

    return f"""
    <div style="
        border: 4px solid {color};
        padding: 15px;
        border-radius: 12px;
        text-align: center;
        background-color: {THEME.BACKGROUND_LIGHT};
    ">
        <h1 style="color: {color}; margin: 0; font-size: 3.5rem;">{capped_score}</h1>
        <b style="color: {THEME.TEXT_PRIMARY};">{label}</b>
    </div>
    """


def get_event_type_color(event_type: str) -> str:
    """
    Get the background color for an event type in the timeline.

    Args:
        event_type: Type of event (Event Log, Browser, USB, Process, etc.)

    Returns:
        Hex color string
    """
    event_colors = {
        "Event Log": THEME.EVENT_LOG,
        "Browser": THEME.BROWSER,
        "USB": THEME.USB,
        "Process": THEME.PROCESS,
        "File System": THEME.FILE_SYSTEM,
        "Network": THEME.NETWORK,
    }
    return event_colors.get(event_type, THEME.ROW_NORMAL)


def color_row_by_risk(risk_status: str) -> str:
    """
    Get the appropriate row background color based on risk status text.

    Args:
        risk_status: Risk status string containing risk level keywords

    Returns:
        CSS background-color value
    """
    risk_status_lower = risk_status.lower()

    if any(kw in risk_status_lower for kw in ["critical", "high risk"]):
        return THEME.ROW_HIGH_RISK
    elif any(kw in risk_status_lower for kw in ["suspicious", "medium"]):
        return THEME.ROW_MEDIUM_RISK
    elif "low" in risk_status_lower:
        return THEME.ROW_LOW_RISK
    else:
        return THEME.ROW_NORMAL
