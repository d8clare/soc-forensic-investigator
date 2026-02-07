"""
Configuration module for SOC Dashboard.
"""
from .theme import (
    THEME,
    ThemeColors,
    get_risk_color,
    get_severity_color,
    style_risk_badge,
    style_score_display,
    get_event_type_color,
    color_row_by_risk
)

__all__ = [
    'THEME',
    'ThemeColors',
    'get_risk_color',
    'get_severity_color',
    'style_risk_badge',
    'style_score_display',
    'get_event_type_color',
    'color_row_by_risk',
]
