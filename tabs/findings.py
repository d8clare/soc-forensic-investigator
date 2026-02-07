"""
Security Findings Tab - Clean Table View.
Displays all detected security findings in a professional table format.
"""
import json
import streamlit as st
import pandas as pd

from core.risk_engine import RiskEngine
from core.security import mask_credentials
from components.ui_components import no_findings_message


def render(evidence_folder: str, risk_engine: RiskEngine):
    """Render the Security Findings tab."""
    findings = risk_engine.all_findings

    if not findings:
        no_findings_message()
        return

    # Count by severity
    critical = len([f for f in findings if f.severity == 'critical'])
    high = len([f for f in findings if f.severity == 'high'])
    medium = len([f for f in findings if f.severity == 'medium'])
    low = len([f for f in findings if f.severity in ('low', 'info')])

    # Simple header with blue styling
    st.markdown(f'<div style="color:#e6edf3;font-size:1.1rem;margin-bottom:15px;"><b>Findings</b> | Total: {len(findings)} | Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}</div>', unsafe_allow_html=True)

    # Filters - compact row
    col1, col2, col3 = st.columns([1, 1, 2])

    with col1:
        severity_opt = st.selectbox(
            "Severity",
            ["All", "Critical", "High", "Medium", "Low"],
            key="sev_filter"
        )
        if severity_opt == "All":
            severity_filter = ["critical", "high", "medium", "low", "info"]
        else:
            severity_filter = [severity_opt.lower()]

    with col2:
        sources = sorted(list(set(f.source for f in findings)))
        source_filter = st.selectbox("Source", ["All"] + sources, key="src_filter")
        if source_filter == "All":
            source_filter = sources
        else:
            source_filter = [source_filter]

    with col3:
        search_term = st.text_input("Search", placeholder="Search findings...", key="find_search")

    # Apply filters
    filtered = [
        f for f in findings
        if f.severity in severity_filter and f.source in source_filter
    ]

    if search_term:
        search_lower = search_term.lower()
        filtered = [
            f for f in filtered
            if search_lower in f.category.lower()
            or search_lower in f.description.lower()
            or search_lower in str(f.evidence).lower()
        ]

    if not filtered:
        st.info("No findings match the selected filters.")
        return

    # Sort by score
    sorted_findings = sorted(filtered, key=lambda x: x.score, reverse=True)

    # Build table data
    table_data = []
    for f in sorted_findings:
        ev = f.evidence or {}

        # Get path/location
        path = ev.get('path') or ev.get('exe') or ev.get('remote_addr') or ev.get('domain') or ''
        if len(str(path)) > 60:
            path = "..." + str(path)[-57:]

        # Get artifact name
        artifact = ev.get('name') or ev.get('filename') or ev.get('event_id') or ''
        if isinstance(artifact, int):
            artifact = f"Event {artifact}"

        table_data.append({
            "Score": f.score,
            "Severity": f.severity.upper(),
            "Category": f.category,
            "Description": mask_credentials(f.description)[:80],
            "Path": str(path),
            "Source": f.source,
            "MITRE": ", ".join(f.mitre_techniques[:2]) if f.mitre_techniques else ""
        })

    df = pd.DataFrame(table_data)

    # Display table
    st.dataframe(
        df,
        width="stretch",
        height=500,
        hide_index=True,
        column_config={
            "Score": st.column_config.NumberColumn("Score", width="small"),
            "Severity": st.column_config.TextColumn("Severity", width="small"),
            "Category": st.column_config.TextColumn("Category", width="medium"),
            "Description": st.column_config.TextColumn("Description", width="large"),
            "Path": st.column_config.TextColumn("Path", width="medium"),
            "Source": st.column_config.TextColumn("Source", width="small"),
            "MITRE": st.column_config.TextColumn("MITRE", width="small"),
        }
    )

    st.caption(f"Showing {len(sorted_findings)} findings")

    # Detailed view with expander
    st.markdown("---")
    st.markdown("**Details**")

    for i, finding in enumerate(sorted_findings[:50]):
        ev = finding.evidence or {}
        path = ev.get('path') or ev.get('exe') or ev.get('remote_addr') or ''
        cmdline = ev.get('cmdline', '')

        with st.expander(f"{finding.severity.upper()} | {finding.category} (Score: {finding.score})"):
            st.markdown(f"**Description:** {mask_credentials(finding.description)}")
            if path:
                st.code(str(path), language=None)
            if cmdline:
                st.markdown("**Command:**")
                st.code(str(cmdline)[:500], language=None)
            if finding.mitre_techniques:
                st.markdown(f"**MITRE:** {', '.join(finding.mitre_techniques)}")
            st.markdown(f"**Source:** {finding.source}")

    if len(sorted_findings) > 50:
        st.caption(f"Showing details for first 50 of {len(sorted_findings)} findings.")

    # Export
    st.markdown("---")
    col1, col2 = st.columns(2)

    with col1:
        export_csv = []
        for f in filtered:
            ev = f.evidence or {}
            export_csv.append({
                "Score": f.score,
                "Severity": f.severity.upper(),
                "Category": f.category,
                "Description": f.description,
                "Path": ev.get('path') or ev.get('exe') or '',
                "Source": f.source,
                "MITRE": ", ".join(f.mitre_techniques) if f.mitre_techniques else "",
            })
        if export_csv:
            csv_df = pd.DataFrame(export_csv)
            st.download_button("Export CSV", csv_df.to_csv(index=False), "findings.csv", "text/csv", width="stretch")

    with col2:
        export_data = [
            {
                "score": f.score,
                "severity": f.severity,
                "category": f.category,
                "description": f.description,
                "source": f.source,
                "mitre": f.mitre_techniques,
                "evidence": f.evidence
            }
            for f in filtered
        ]
        st.download_button(
            "Export JSON",
            json.dumps(export_data, indent=2, default=str),
            "findings.json",
            "application/json",
            width="stretch"
        )
