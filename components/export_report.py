"""
Export Report Component - Generate PDF/HTML investigation reports.
One-click export of all findings, timeline, and investigation summary.
"""
import streamlit as st
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

from core.data_loader import load_json
from core.risk_engine import RiskEngine
from core.security import escape_html


def generate_html_report(
    evidence_folder: str,
    risk_engine: RiskEngine,
    case_info: Dict,
    include_sections: List[str] = None
) -> str:
    """
    Generate a comprehensive HTML investigation report.

    Args:
        evidence_folder: Path to evidence folder
        risk_engine: RiskEngine with findings
        case_info: Case metadata
        include_sections: List of sections to include

    Returns:
        Complete HTML report as string
    """
    if include_sections is None:
        include_sections = ["summary", "findings", "timeline", "processes", "network", "iocs"]

    # Get data
    findings = risk_engine.all_findings
    techniques = list(risk_engine.mitre_techniques)
    score = risk_engine.get_global_score()
    severity = risk_engine.get_severity()

    # Load additional data as needed
    processes = load_json(evidence_folder, "processes.json") or []
    network = load_json(evidence_folder, "network_connections.json") or []
    events = load_json(evidence_folder, "all_events.json") or []

    # Get flagged/IOCs from session state
    flagged = st.session_state.get('flagged_indicators', [])
    custom_iocs = st.session_state.get('custom_iocs', [])

    # Generate report timestamp
    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build HTML
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOC Investigation Report - {escape_html(case_info.get('hostname', 'Unknown'))}</title>
    <style>
        :root {{
            --bg-primary: #0a0a15;
            --bg-secondary: #1a1a2e;
            --bg-card: #16213e;
            --text-primary: #ffffff;
            --text-secondary: #888888;
            --accent: #667eea;
            --critical: #ff6b6b;
            --high: #feca57;
            --medium: #48dbfb;
            --low: #1dd1a1;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 40px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        .header {{
            background: linear-gradient(135deg, var(--bg-secondary), var(--bg-card));
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 30px;
            border: 1px solid rgba(102, 126, 234, 0.3);
        }}

        .header h1 {{
            font-size: 2rem;
            margin-bottom: 10px;
        }}

        .header .subtitle {{
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}

        .risk-badge {{
            display: inline-block;
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 1.1rem;
            margin-top: 15px;
        }}

        .risk-critical {{ background: rgba(255, 107, 107, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
        .risk-high {{ background: rgba(254, 202, 87, 0.2); color: var(--high); border: 1px solid var(--high); }}
        .risk-medium {{ background: rgba(72, 219, 251, 0.2); color: var(--medium); border: 1px solid var(--medium); }}
        .risk-low {{ background: rgba(29, 209, 161, 0.2); color: var(--low); border: 1px solid var(--low); }}

        .section {{
            background: var(--bg-secondary);
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 25px;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}

        .section h2 {{
            font-size: 1.3rem;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}

        .stat-card {{
            background: var(--bg-card);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}

        .stat-value {{
            font-size: 2rem;
            font-weight: bold;
            color: var(--accent);
        }}

        .stat-label {{
            font-size: 0.8rem;
            color: var(--text-secondary);
            text-transform: uppercase;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}

        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }}

        th {{
            background: var(--bg-card);
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
            color: var(--text-secondary);
        }}

        tr:hover {{
            background: rgba(102, 126, 234, 0.05);
        }}

        .severity-badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
        }}

        .severity-critical {{ background: rgba(255, 107, 107, 0.2); color: var(--critical); }}
        .severity-high {{ background: rgba(254, 202, 87, 0.2); color: var(--high); }}
        .severity-medium {{ background: rgba(72, 219, 251, 0.2); color: var(--medium); }}
        .severity-low {{ background: rgba(29, 209, 161, 0.2); color: var(--low); }}

        .mitre-tag {{
            display: inline-block;
            background: rgba(102, 126, 234, 0.2);
            color: var(--accent);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            margin: 2px;
        }}

        .footer {{
            text-align: center;
            padding: 20px;
            color: var(--text-secondary);
            font-size: 0.85rem;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            margin-top: 40px;
        }}

        @media print {{
            body {{
                background: white;
                color: black;
            }}
            .section {{
                break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SOC Forensic Investigation Report</h1>
            <div class="subtitle">
                <strong>Hostname:</strong> {escape_html(case_info.get('hostname', 'Unknown'))} |
                <strong>Collection Date:</strong> {escape_html(case_info.get('date_str', 'Unknown'))} |
                <strong>Report Generated:</strong> {report_time}
            </div>
            <div class="risk-badge risk-{severity.lower()}">{severity.upper()} RISK - Score: {score}</div>
        </div>
'''

    # Executive Summary Section
    if "summary" in include_sections:
        critical_count = len([f for f in findings if f.severity == 'critical'])
        high_count = len([f for f in findings if f.severity == 'high'])
        medium_count = len([f for f in findings if f.severity == 'medium'])

        html += f'''
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value" style="color: var(--critical);">{critical_count}</div>
                    <div class="stat-label">Critical Findings</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: var(--high);">{high_count}</div>
                    <div class="stat-label">High Findings</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: var(--medium);">{medium_count}</div>
                    <div class="stat-label">Medium Findings</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{len(techniques)}</div>
                    <div class="stat-label">MITRE Techniques</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{len(processes)}</div>
                    <div class="stat-label">Processes</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{len(network)}</div>
                    <div class="stat-label">Connections</div>
                </div>
            </div>
        </div>
'''

    # Findings Section
    if "findings" in include_sections and findings:
        html += '''
        <div class="section">
            <h2>🔍 Security Findings</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Score</th>
                        <th>Category</th>
                        <th>Description</th>
                        <th>MITRE</th>
                    </tr>
                </thead>
                <tbody>
'''
        # Sort by score descending
        sorted_findings = sorted(findings, key=lambda f: f.score, reverse=True)
        for finding in sorted_findings[:50]:  # Limit to top 50
            techniques_html = " ".join([f'<span class="mitre-tag">{t}</span>' for t in finding.mitre_techniques[:3]])
            html += f'''
                    <tr>
                        <td><span class="severity-badge severity-{finding.severity}">{finding.severity.upper()}</span></td>
                        <td>{finding.score}</td>
                        <td>{escape_html(finding.category)}</td>
                        <td>{escape_html(finding.description[:100])}</td>
                        <td>{techniques_html}</td>
                    </tr>
'''
        html += '''
                </tbody>
            </table>
        </div>
'''

    # MITRE ATT&CK Section
    if "mitre" in include_sections and techniques:
        html += '''
        <div class="section">
            <h2>🎯 MITRE ATT&CK Coverage</h2>
            <p style="color: var(--text-secondary); margin-bottom: 15px;">Techniques observed in this investigation:</p>
            <div style="display: flex; flex-wrap: wrap; gap: 8px;">
'''
        for tech in sorted(techniques):
            html += f'<span class="mitre-tag">{tech}</span>'
        html += '''
            </div>
        </div>
'''

    # Flagged Indicators Section
    if "iocs" in include_sections and (flagged or custom_iocs):
        html += '''
        <div class="section">
            <h2>📌 Indicators of Compromise</h2>
'''
        if flagged:
            html += '''
            <h3 style="font-size: 1rem; margin: 15px 0 10px;">🚩 Flagged Indicators</h3>
            <table>
                <thead><tr><th>Indicator</th><th>Flagged At</th></tr></thead>
                <tbody>
'''
            for flag in flagged:
                html += f'''<tr><td><code>{escape_html(flag['value'])}</code></td><td>{flag.get('flagged_at', '')[:19]}</td></tr>'''
            html += '</tbody></table>'

        if custom_iocs:
            html += '''
            <h3 style="font-size: 1rem; margin: 15px 0 10px;">📌 Custom IOCs</h3>
            <table>
                <thead><tr><th>Value</th><th>Type</th><th>Added</th></tr></thead>
                <tbody>
'''
            for ioc in custom_iocs:
                html += f'''<tr><td><code>{escape_html(ioc['value'])}</code></td><td>{ioc.get('type', 'unknown')}</td><td>{ioc.get('added_at', '')[:19]}</td></tr>'''
            html += '</tbody></table>'
        html += '</div>'

    # Footer
    html += f'''
        <div class="footer">
            <p>Generated by SOC Forensic Investigator v2.0.0</p>
            <p>Report ID: {case_info.get('hostname', 'UNK')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}</p>
        </div>
    </div>
</body>
</html>
'''

    return html


def generate_json_report(
    evidence_folder: str,
    risk_engine: RiskEngine,
    case_info: Dict
) -> str:
    """Generate a JSON export of all investigation data."""

    findings_data = []
    for f in risk_engine.all_findings:
        findings_data.append({
            "category": f.category,
            "description": f.description,
            "score": f.score,
            "severity": f.severity,
            "mitre_techniques": f.mitre_techniques,
            "source": f.source,
            "evidence": f.evidence
        })

    report = {
        "report_info": {
            "generated_at": datetime.now().isoformat(),
            "tool_version": "2.0.0",
            "case_hostname": case_info.get('hostname', 'Unknown'),
            "collection_date": case_info.get('date_str', 'Unknown')
        },
        "risk_assessment": {
            "score": risk_engine.get_global_score(),
            "severity": risk_engine.get_severity(),
            "mitre_techniques": list(risk_engine.mitre_techniques)
        },
        "findings": findings_data,
        "flagged_indicators": st.session_state.get('flagged_indicators', []),
        "custom_iocs": st.session_state.get('custom_iocs', [])
    }

    return json.dumps(report, indent=2, default=str)


def render_export_panel(evidence_folder: str, risk_engine: RiskEngine, case_info: Dict):
    """Render the export report panel with options."""

    st.markdown('''<div style="background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);border-radius:10px;padding:20px;margin-bottom:20px;">
<div style="display:flex;align-items:center;gap:15px;">
<div style="font-size:2rem;">📄</div>
<div>
<div style="font-size:1.2rem;font-weight:bold;color:white;">Export Investigation Report</div>
<div style="color:#888;font-size:0.85rem;">Generate comprehensive reports in HTML or JSON format</div>
</div>
</div>
</div>''', unsafe_allow_html=True)

    # Section selection
    st.markdown("#### Select Report Sections")
    cols = st.columns(3)

    with cols[0]:
        inc_summary = st.checkbox("Executive Summary", value=True)
        inc_findings = st.checkbox("Security Findings", value=True)
    with cols[1]:
        inc_mitre = st.checkbox("MITRE ATT&CK", value=True)
        inc_iocs = st.checkbox("IOCs & Flags", value=True)
    with cols[2]:
        inc_timeline = st.checkbox("Timeline", value=False)
        inc_processes = st.checkbox("Process List", value=False)

    sections = []
    if inc_summary: sections.append("summary")
    if inc_findings: sections.append("findings")
    if inc_mitre: sections.append("mitre")
    if inc_iocs: sections.append("iocs")
    if inc_timeline: sections.append("timeline")
    if inc_processes: sections.append("processes")

    st.markdown("---")

    # Export buttons
    col1, col2, col3 = st.columns(3)

    with col1:
        html_report = generate_html_report(evidence_folder, risk_engine, case_info, sections)
        hostname = case_info.get('hostname', 'investigation')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        st.download_button(
            "📄 Download HTML Report",
            html_report,
            f"soc_report_{hostname}_{timestamp}.html",
            "text/html",
            width="stretch"
        )

    with col2:
        json_report = generate_json_report(evidence_folder, risk_engine, case_info)
        st.download_button(
            "📋 Download JSON Report",
            json_report,
            f"soc_report_{hostname}_{timestamp}.json",
            "application/json",
            width="stretch"
        )

    with col3:
        # IOC list export
        iocs = st.session_state.get('custom_iocs', [])
        flagged = st.session_state.get('flagged_indicators', [])
        all_iocs = [i['value'] for i in iocs] + [f['value'] for f in flagged]

        if all_iocs:
            st.download_button(
                "📌 Export IOC List",
                "\n".join(all_iocs),
                f"iocs_{hostname}_{timestamp}.txt",
                "text/plain",
                width="stretch"
            )
        else:
            st.button("📌 Export IOC List", disabled=True, width="stretch",
                      help="Flag indicators or add IOCs first")

    # Preview
    with st.expander("👁️ Preview HTML Report", expanded=False):
        st.components.v1.html(html_report, height=600, scrolling=True)
