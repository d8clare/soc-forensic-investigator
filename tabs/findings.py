"""
Security Findings Tab - Clean Table View.
Displays all detected security findings in a professional table format.
"""
import os
import json
import streamlit as st
import pandas as pd

from core.risk_engine import RiskEngine
from core.security import mask_credentials
from components.ui_components import no_findings_message


@st.cache_data
def build_findings_table(_folder_hash: str, findings_data: list) -> pd.DataFrame:
    """Build findings table DataFrame. Cached for performance."""
    if not findings_data:
        return pd.DataFrame()

    table_data = []
    for f in findings_data:
        ev = f.get('evidence') or {}

        # Get path/location (show full path)
        path = ev.get('path') or ev.get('exe') or ev.get('remote_addr') or ev.get('domain') or ''

        # Get artifact name
        artifact = ev.get('name') or ev.get('filename') or ''
        event_id = ev.get('event_id')
        if event_id:
            artifact = f"Event {event_id}" if not artifact else artifact

        table_data.append({
            "Score": f.get('score', 0),
            "Severity": f.get('severity', 'info').upper(),
            "Category": f.get('category', ''),
            "Artifact": str(artifact)[:30] if artifact else "",
            "Description": mask_credentials(f.get('description', ''))[:70],
            "Path": str(path)[:50] if path else "",
            "Source": f.get('source', ''),
            "MITRE": ", ".join(f.get('mitre_techniques', [])[:2]) if f.get('mitre_techniques') else ""
        })

    return pd.DataFrame(table_data)


@st.cache_data
def get_findings_stats(_folder_hash: str, findings_data: list) -> dict:
    """Calculate findings statistics. Cached for performance."""
    stats = {
        'total': len(findings_data),
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'sources': set()
    }

    for f in findings_data:
        severity = f.get('severity', 'info')
        if severity == 'critical':
            stats['critical'] += 1
        elif severity == 'high':
            stats['high'] += 1
        elif severity == 'medium':
            stats['medium'] += 1
        elif severity in ('low', 'info'):
            stats['low'] += 1
        stats['sources'].add(f.get('source', ''))

    stats['sources'] = sorted(list(stats['sources']))
    return stats


def render(evidence_folder: str, risk_engine: RiskEngine):
    """Render the Security Findings tab."""
    findings = risk_engine.all_findings

    if not findings:
        no_findings_message()
        return

    # Convert findings to serializable format for caching
    folder_hash = os.path.basename(evidence_folder)
    findings_data = [
        {
            'score': f.score,
            'severity': f.severity,
            'category': f.category,
            'description': f.description,
            'source': f.source,
            'mitre_techniques': f.mitre_techniques,
            'evidence': f.evidence
        }
        for f in findings
    ]

    # Get cached statistics
    stats = get_findings_stats(folder_hash, findings_data)

    # Simple header with blue styling
    st.markdown(f'<div style="color:#e6edf3;font-size:1.1rem;margin-bottom:15px;"><b>Findings</b> | Total: {stats["total"]} | Critical: {stats["critical"]} | High: {stats["high"]} | Medium: {stats["medium"]} | Low: {stats["low"]}</div>', unsafe_allow_html=True)

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
        source_filter = st.selectbox("Source", ["All"] + stats['sources'], key="src_filter")
        if source_filter == "All":
            source_filter = stats['sources']
        else:
            source_filter = [source_filter]

    with col3:
        search_term = st.text_input("Search", placeholder="Search findings...", key="find_search")

    # Apply filters
    filtered = [
        f for f in findings_data
        if f['severity'] in severity_filter and f['source'] in source_filter
    ]

    if search_term:
        search_lower = search_term.lower()
        filtered = [
            f for f in filtered
            if search_lower in f['category'].lower()
            or search_lower in f['description'].lower()
            or search_lower in str(f['evidence']).lower()
        ]

    if not filtered:
        st.info("No findings match the selected filters.")
        return

    # Sort by score
    sorted_findings = sorted(filtered, key=lambda x: x['score'], reverse=True)

    # Build cached table DataFrame
    df = build_findings_table(folder_hash + "_table", sorted_findings)

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
            "Artifact": st.column_config.TextColumn("Artifact", width="small"),
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
        ev = finding.get('evidence') or {}
        path = ev.get('path') or ev.get('exe') or ev.get('remote_addr') or ''
        cmdline = ev.get('cmdline', '')

        with st.expander(f"{finding['severity'].upper()} | {finding['category']} (Score: {finding['score']})"):
            st.markdown(f"**Description:** {mask_credentials(finding['description'])}")

            # Context row - show available metadata
            context_parts = []
            if ev.get('username') or ev.get('user'):
                context_parts.append(f"**User:** {ev.get('username') or ev.get('user')}")
            if ev.get('timestamp') or ev.get('create_time') or ev.get('time'):
                ts = ev.get('timestamp') or ev.get('create_time') or ev.get('time')
                context_parts.append(f"**Time:** {ts}")
            if ev.get('pid'):
                context_parts.append(f"**PID:** {ev.get('pid')}")
            if ev.get('source_ip'):
                context_parts.append(f"**Source IP:** {ev.get('source_ip')}")
            if ev.get('remote_addr') and finding['source'] == 'network':
                context_parts.append(f"**Remote:** {ev.get('remote_addr')}")
            if ev.get('event_id'):
                context_parts.append(f"**Event ID:** {ev.get('event_id')}")

            if context_parts:
                st.markdown(" · ".join(context_parts))

            # Path
            if path:
                st.code(str(path), language=None)

            # Command line
            if cmdline:
                st.markdown("**Command:**")
                st.code(str(cmdline)[:500], language=None)

            # Parent process info
            if ev.get('parent'):
                st.markdown(f"**Parent Process:** {ev.get('parent')}")

            # Additional evidence fields in a compact format
            extra_fields = []
            if ev.get('signature'):
                extra_fields.append(f"Signature: {ev.get('signature')}")
            if ev.get('sha256'):
                extra_fields.append(f"SHA256: {ev.get('sha256')[:16]}...")
            if ev.get('logon_type'):
                extra_fields.append(f"Logon Type: {ev.get('logon_type')}")
            if ev.get('workstation'):
                extra_fields.append(f"Workstation: {ev.get('workstation')}")
            if ev.get('domain'):
                extra_fields.append(f"Domain: {ev.get('domain')}")
            if ev.get('failed_attempts'):
                extra_fields.append(f"Failed Attempts: {ev.get('failed_attempts')}")

            if extra_fields:
                st.caption(" | ".join(extra_fields))

            # Footer: MITRE and Source
            footer_parts = []
            if finding.get('mitre_techniques'):
                footer_parts.append(f"**MITRE:** {', '.join(finding['mitre_techniques'])}")
            footer_parts.append(f"**Source:** {finding['source']}")
            st.markdown(" · ".join(footer_parts))

    if len(sorted_findings) > 50:
        st.caption(f"Showing details for first 50 of {len(sorted_findings)} findings.")

    # Export
    st.markdown("---")
    col1, col2 = st.columns(2)

    with col1:
        export_csv = []
        for f in filtered:
            ev = f.get('evidence') or {}
            export_csv.append({
                "Score": f['score'],
                "Severity": f['severity'].upper(),
                "Category": f['category'],
                "Description": f['description'],
                "Path": ev.get('path') or ev.get('exe') or '',
                "Source": f['source'],
                "MITRE": ", ".join(f['mitre_techniques']) if f.get('mitre_techniques') else "",
            })
        if export_csv:
            csv_df = pd.DataFrame(export_csv)
            st.download_button(
                "Export CSV",
                csv_df.to_csv(index=False),
                "findings.csv",
                "text/csv",
                width="stretch",
                key="findings_export_csv"
            )

    with col2:
        # filtered is already in dict format
        st.download_button(
            "Export JSON",
            json.dumps(filtered, indent=2, default=str),
            "findings.json",
            "application/json",
            width="stretch",
            key="findings_export_json"
        )
