"""
Case Header Component - Persistent case info display with quick stats.
"""
import streamlit as st
from typing import Optional
from datetime import datetime
from core.risk_engine import RiskEngine


def render_case_header(case_info: dict, risk_engine: Optional[RiskEngine] = None) -> None:
    """
    Render a persistent case information header with quick stats.

    Args:
        case_info: Dictionary with case metadata (hostname, date_str, file_count, etc.)
        risk_engine: Optional RiskEngine for findings stats
    """
    hostname = case_info.get("hostname", "Unknown")
    date_str = case_info.get("date_str", "Unknown")
    file_count = case_info.get("file_count", 0)

    # Get findings stats from risk engine
    total_findings = 0
    critical_count = 0
    high_count = 0
    risk_score = 0

    if risk_engine:
        findings = risk_engine.all_findings
        total_findings = len(findings)
        critical_count = sum(1 for f in findings if f.severity == "critical")
        high_count = sum(1 for f in findings if f.severity == "high")
        risk_score = risk_engine.get_global_score()

    # Determine overall status
    if critical_count > 0:
        status_color = "#dc3545"
        status_text = "Critical Issues Found"
        status_icon = "🔴"
    elif high_count > 0:
        status_color = "#ff8c00"
        status_text = "High Risk Indicators"
        status_icon = "🟠"
    elif total_findings > 0:
        status_color = "#ffc107"
        status_text = "Review Recommended"
        status_icon = "🟡"
    else:
        status_color = "#28a745"
        status_text = "No Issues Detected"
        status_icon = "🟢"

    # Risk score color
    if risk_score >= 70:
        score_color = "#dc3545"
    elif risk_score >= 50:
        score_color = "#ff8c00"
    elif risk_score >= 30:
        score_color = "#ffc107"
    else:
        score_color = "#28a745"

    st.markdown(f'''<div style="background:linear-gradient(135deg,#12121a 0%,#1a1a2e 100%);border-radius:10px;padding:12px 20px;margin-bottom:15px;border:1px solid rgba(102,126,234,0.2);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:15px;">
<div style="display:flex;align-items:center;gap:20px;flex-wrap:wrap;">
<div style="display:flex;align-items:center;gap:10px;">
<span style="font-size:1.3rem;">🖥️</span>
<div>
<div style="color:white;font-weight:600;font-size:1rem;">{hostname}</div>
<div style="color:#888;font-size:0.75rem;">📅 {date_str}</div>
</div>
</div>
<div style="width:1px;height:30px;background:rgba(255,255,255,0.1);"></div>
<div style="display:flex;align-items:center;gap:8px;">
<span>{status_icon}</span>
<span style="color:{status_color};font-size:0.85rem;font-weight:500;">{status_text}</span>
</div>
</div>
<div style="display:flex;align-items:center;gap:20px;">
<div style="text-align:center;padding:5px 15px;background:rgba(0,0,0,0.2);border-radius:8px;">
<div style="color:{score_color};font-size:1.3rem;font-weight:bold;">{risk_score}</div>
<div style="color:#888;font-size:0.65rem;text-transform:uppercase;">Risk</div>
</div>
<div style="text-align:center;padding:5px 15px;background:rgba(0,0,0,0.2);border-radius:8px;">
<div style="color:#dc3545;font-size:1.3rem;font-weight:bold;">{critical_count}</div>
<div style="color:#888;font-size:0.65rem;text-transform:uppercase;">Critical</div>
</div>
<div style="text-align:center;padding:5px 15px;background:rgba(0,0,0,0.2);border-radius:8px;">
<div style="color:#ff8c00;font-size:1.3rem;font-weight:bold;">{high_count}</div>
<div style="color:#888;font-size:0.65rem;text-transform:uppercase;">High</div>
</div>
<div style="text-align:center;padding:5px 15px;background:rgba(0,0,0,0.2);border-radius:8px;">
<div style="color:white;font-size:1.3rem;font-weight:bold;">{total_findings}</div>
<div style="color:#888;font-size:0.65rem;text-transform:uppercase;">Findings</div>
</div>
</div>
</div>''', unsafe_allow_html=True)


def render_mini_case_header(hostname: str, date_str: str) -> None:
    """
    Render a minimal case header for sidebar or compact views.

    Args:
        hostname: System hostname
        date_str: Collection date string
    """
    st.markdown(f'''<div style="background:rgba(30,30,46,0.5);border-radius:8px;padding:10px 15px;margin-bottom:10px;border:1px solid rgba(102,126,234,0.15);">
<div style="display:flex;align-items:center;gap:8px;">
<span>🖥️</span>
<div>
<div style="color:white;font-size:0.9rem;font-weight:600;">{hostname}</div>
<div style="color:#888;font-size:0.7rem;">{date_str}</div>
</div>
</div>
</div>''', unsafe_allow_html=True)
