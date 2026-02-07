"""
MITRE ATT&CK Mapping Tab.
Displays detected techniques mapped to the kill chain with detailed evidence.
"""
import json
import os

import streamlit as st
import pandas as pd

from core.risk_engine import RiskEngine
from core.security import escape_html, safe_html_value, mask_credentials
from config.theme import THEME


@st.cache_data
def load_mitre_mapping():
    """Load MITRE mapping from JSON file (cached)."""
    try:
        config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "mitre_mapping.json")
        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        pass
    return {"techniques": {}, "kill_chain_phases": []}


def format_evidence(evidence: dict) -> str:
    """Format evidence dictionary into readable string.

    All values are HTML-escaped and credentials are masked.
    """
    if not evidence:
        return ""

    parts = []

    def safe_value(key: str, max_len: int = 0) -> str:
        """Get escaped and masked value from evidence."""
        val = evidence.get(key, '')
        if not val:
            return ''
        val_str = mask_credentials(str(val))
        if max_len and len(val_str) > max_len:
            val_str = val_str[:max_len] + "..."
        return escape_html(val_str)

    # Process evidence
    if 'name' in evidence:
        parts.append(f"**Process:** `{safe_value('name')}`")
    if 'path' in evidence:
        parts.append(f"**Path:** `{safe_value('path')}`")
    if 'exe' in evidence:
        parts.append(f"**Executable:** `{safe_value('exe')}`")
    if 'cmdline' in evidence:
        parts.append(f"**Command:** `{safe_value('cmdline', 150)}`")
    if 'pid' in evidence and evidence['pid']:
        parts.append(f"**PID:** `{safe_value('pid')}`")

    # Parent/child for process chains
    if 'parent' in evidence:
        parts.append(f"**Parent:** `{safe_value('parent')}`")
    if 'child' in evidence:
        parts.append(f"**Child:** `{safe_value('child')}`")

    # Network evidence
    if 'remote_addr' in evidence:
        parts.append(f"**Remote Address:** `{safe_value('remote_addr')}`")
    if 'remote_ip' in evidence:
        parts.append(f"**Remote IP:** `{safe_value('remote_ip')}`")
    if 'remote_port' in evidence:
        parts.append(f"**Port:** `{safe_value('remote_port')}`")

    # File evidence
    if 'filename' in evidence:
        parts.append(f"**File:** `{safe_value('filename')}`")
    if 'sha256' in evidence and evidence['sha256']:
        sha = escape_html(str(evidence['sha256'])[:16])
        parts.append(f"**SHA256:** `{sha}...`")

    # DNS evidence
    if 'domain' in evidence:
        parts.append(f"**Domain:** `{safe_value('domain')}`")

    # Event log evidence
    if 'event_id' in evidence:
        parts.append(f"**Event ID:** `{safe_value('event_id')}`")
    if 'log_name' in evidence and evidence['log_name']:
        parts.append(f"**Log:** `{safe_value('log_name')}`")
    if 'time' in evidence and evidence['time']:
        parts.append(f"**Time:** `{safe_value('time')}`")
    if 'provider' in evidence and evidence['provider']:
        parts.append(f"**Provider:** `{safe_value('provider')}`")
    if 'message' in evidence and evidence['message']:
        parts.append(f"**Message:** `{safe_value('message', 200)}`")

    # Registry evidence
    if 'value' in evidence:
        parts.append(f"**Value:** `{safe_value('value', 100)}`")

    # Signature
    if 'signature' in evidence:
        parts.append(f"**Signature:** `{safe_value('signature')}`")

    return " | ".join(parts) if parts else escape_html(str(evidence))


def render(evidence_folder: str, risk_engine: RiskEngine):
    """
    Render the MITRE ATT&CK Mapping tab.

    Args:
        evidence_folder: Path to the evidence folder
        risk_engine: RiskEngine instance with detected techniques
    """
    # Load MITRE mapping data
    mitre_data = load_mitre_mapping()
    techniques_db = mitre_data.get("techniques", {})
    kill_chain = mitre_data.get("kill_chain_phases", [])

    # Get detected techniques from risk engine
    detected_techniques = risk_engine.mitre_techniques
    findings_by_mitre = risk_engine.get_findings_by_mitre()

    if not detected_techniques:
        st.info("No MITRE ATT&CK techniques detected in current evidence.")
        return

    # Count tactics
    tactics = set()
    for tech_id in detected_techniques:
        if tech_id in techniques_db:
            tactics.add(techniques_db[tech_id].get("tactic", "Unknown"))
    total_evidence = sum(len(f) for f in findings_by_mitre.values())

    # Simple header with blue styling
    st.markdown(f'<div style="color:#e6edf3;font-size:1.1rem;margin-bottom:15px;"><b>MITRE ATT&CK</b> | Techniques: {len(detected_techniques)} | Tactics: {len(tactics)} | Evidence: {total_evidence}</div>', unsafe_allow_html=True)

    # Build table data (used for both table view and CSV export)
    table_data = []
    for tech_id in sorted(detected_techniques):
        tech_info = techniques_db.get(tech_id, {})
        tech_name = tech_info.get("name", tech_id)
        findings = findings_by_mitre.get(tech_id, [])

        for finding in findings:
            evidence = finding.evidence
            artifact = ""
            location = ""

            # Process/file artifacts
            if 'name' in evidence:
                artifact = evidence['name']
            elif 'filename' in evidence:
                artifact = evidence['filename']
            elif 'domain' in evidence:
                artifact = evidence['domain']
            elif 'event_id' in evidence:
                artifact = f"Event {evidence['event_id']}"

            # Location/details
            if 'path' in evidence:
                location = evidence['path']
            elif 'exe' in evidence:
                location = evidence['exe']
            elif 'remote_addr' in evidence:
                location = evidence['remote_addr']
            elif 'cmdline' in evidence:
                location = str(evidence['cmdline'])[:150] + "..." if len(str(evidence.get('cmdline', ''))) > 150 else str(evidence.get('cmdline', ''))
            elif 'message' in evidence:
                location = str(evidence['message'])[:200] + "..." if len(str(evidence.get('message', ''))) > 200 else str(evidence.get('message', ''))
            elif 'log_name' in evidence:
                location = f"{evidence.get('log_name', '')} @ {evidence.get('time', '')}"

            table_data.append({
                "Technique": f"{tech_id}",
                "Name": tech_name,
                "Severity": finding.severity.upper(),
                "Score": finding.score,
                "Category": finding.category,
                "Artifact": artifact,
                "Location/Details": location,
                "Source": finding.source
            })

    # Use subtabs
    view_tabs = st.tabs(["By Technique", "Evidence Table"])

    with view_tabs[0]:
        # Detailed Technique List with Evidence
        st.subheader("Detected Techniques with Evidence")

        for tech_id in sorted(detected_techniques):
            tech_info = techniques_db.get(tech_id, {})
            tech_name = tech_info.get("name", tech_id)
            tech_tactic = tech_info.get("tactic", "Unknown")
            tech_url = tech_info.get("url", f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/")
            tech_desc = tech_info.get("description", "No description available.")

            findings = findings_by_mitre.get(tech_id, [])

            with st.expander(f"{tech_id} - {tech_name} ({len(findings)} evidence items)", expanded=False):
                # Technique info
                col1, col2 = st.columns([4, 1])
                with col1:
                    st.markdown(f"**Tactic:** {tech_tactic}")
                    st.caption(tech_desc)
                with col2:
                    st.link_button("MITRE", tech_url)

                if findings:
                    st.markdown("---")
                    st.markdown("**Evidence Found:**")

                    for i, finding in enumerate(findings, 1):
                        severity_color = {
                            'critical': THEME.SEVERITY_CRITICAL,
                            'high': THEME.SEVERITY_DANGER,
                            'medium': THEME.SEVERITY_WARNING,
                            'low': THEME.SEVERITY_INFO,
                        }.get(finding.severity, THEME.SEVERITY_INFO)

                        # Format evidence details
                        evidence_str = format_evidence(finding.evidence)

                        st.markdown(
                            f"""
                            <div style="
                                border-left: 4px solid {severity_color};
                                padding: 10px 15px;
                                margin: 8px 0;
                                background-color: #f8f9fa;
                                border-radius: 0 4px 4px 0;
                            ">
                                <div style="display: flex; justify-content: space-between; align-items: center;">
                                    <strong>{finding.category}</strong>
                                    <span style="background: {severity_color}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 0.8em;">
                                        Score: {finding.score} | {finding.severity.upper()}
                                    </span>
                                </div>
                                <div style="margin-top: 8px; color: #333;">
                                    {finding.description}
                                </div>
                            </div>
                            """,
                            unsafe_allow_html=True
                        )

                        # Show evidence details separately for better readability
                        if finding.evidence:
                            with st.container():
                                evidence = finding.evidence

                                # Process evidence
                                if 'name' in evidence or 'filename' in evidence:
                                    name = evidence.get('name') or evidence.get('filename', '')
                                    st.code(f"Name: {name}", language=None)

                                if 'path' in evidence or 'exe' in evidence:
                                    path = evidence.get('path') or evidence.get('exe', '')
                                    st.code(f"Path: {path}", language=None)

                                if 'cmdline' in evidence:
                                    st.code(f"Command: {evidence['cmdline']}", language="powershell")

                                if 'parent' in evidence and 'child' in evidence:
                                    st.code(f"Parent: {evidence['parent']} → Child: {evidence['child']}", language=None)

                                # Network evidence
                                if 'remote_addr' in evidence:
                                    st.code(f"Remote: {evidence['remote_addr']}", language=None)

                                if 'domain' in evidence:
                                    st.code(f"Domain: {evidence['domain']}", language=None)

                                # Registry evidence
                                if 'value' in evidence:
                                    st.code(f"Value: {str(evidence['value'])[:200]}", language=None)

                                # Event log evidence
                                if 'event_id' in evidence:
                                    st.markdown("**Event Details:**")

                                    col1, col2, col3 = st.columns(3)
                                    with col1:
                                        st.code(f"Event ID: {evidence['event_id']}", language=None)
                                    with col2:
                                        if evidence.get('log_name'):
                                            st.code(f"Log: {evidence['log_name']}", language=None)
                                    with col3:
                                        if evidence.get('time'):
                                            st.code(f"Time: {evidence['time']}", language=None)

                                    if evidence.get('provider'):
                                        st.code(f"Provider: {evidence['provider']}", language=None)

                                    if evidence.get('message'):
                                        msg = str(evidence['message'])
                                        # Use unique key with tech_id and index
                                        unique_key = f"msg_{tech_id}_{i}_{evidence.get('event_id', 'unknown')}"
                                        st.text_area("Event Message:", msg, height=120, disabled=True, key=unique_key)

    with view_tabs[1]:
        # Evidence Table View
        st.subheader("All Evidence Table")

        if table_data:
            df = pd.DataFrame(table_data)
            df = df.sort_values(by="Score", ascending=False)

            # Add severity indicator for dark mode compatibility
            sev_indicators = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
            df['Severity'] = df['Severity'].apply(lambda x: f"{sev_indicators.get(x, '⚪')} {x}")

            st.dataframe(
                df,
                width="stretch",
                height=500,
                column_config={
                    "Score": st.column_config.NumberColumn("Score", width="small"),
                    "Technique": st.column_config.TextColumn("Technique", width="small"),
                    "Severity": st.column_config.TextColumn("Severity", width="small"),
                    "Artifact": st.column_config.TextColumn("Artifact", width="medium"),
                    "Location/Details": st.column_config.TextColumn("Location/Details", width="large"),
                },
                hide_index=True
            )

    # Export section
    st.divider()
    st.subheader("Export")

    # Build comprehensive export data
    export_data = {
        "summary": {
            "techniques_detected": len(detected_techniques),
            "total_evidence": total_evidence,
            "tactics_covered": list(tactics) if 'tactics' in dir() else []
        },
        "techniques": {}
    }

    for tech_id in detected_techniques:
        tech_info = techniques_db.get(tech_id, {})
        findings = findings_by_mitre.get(tech_id, [])

        export_data["techniques"][tech_id] = {
            "name": tech_info.get("name", tech_id),
            "tactic": tech_info.get("tactic", "Unknown"),
            "url": tech_info.get("url", ""),
            "evidence": [
                {
                    "category": f.category,
                    "description": f.description,
                    "severity": f.severity,
                    "score": f.score,
                    "source": f.source,
                    "details": f.evidence
                }
                for f in findings
            ]
        }

    col1, col2 = st.columns(2)
    with col1:
        st.download_button(
            label="Export Full Report (JSON)",
            data=json.dumps(export_data, indent=2),
            file_name="mitre_attack_report.json",
            mime="application/json",
            width="stretch"
        )

    with col2:
        # CSV export for table view
        if table_data:
            csv_df = pd.DataFrame(table_data)
            st.download_button(
                label="Export Evidence Table (CSV)",
                data=csv_df.to_csv(index=False),
                file_name="mitre_evidence.csv",
                mime="text/csv",
                width="stretch"
            )
