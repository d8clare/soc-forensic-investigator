"""
Executive Dashboard / Home Tab.
Clean, professional interface for forensic investigators.
"""
import streamlit as st
import os

from core.data_loader import load_json
from core.risk_engine import RiskEngine
from components.executive_summary import ExecutiveSummary
from components.export import ForensicExporter, render_ioc_extraction
from components.ui_components import section_header, metric_card, info_banner


def render(evidence_folder: str, risk_engine: RiskEngine):
    """Render the Home/Executive Dashboard tab."""
    # Load data for IOC extraction
    processes = load_json(evidence_folder, "processes.json") or []
    network = load_json(evidence_folder, "network_connections.json") or []
    files = load_json(evidence_folder, "recent_files.json") or []
    dns = load_json(evidence_folder, "dns_cache.json") or []
    browser = load_json(evidence_folder, "browser_history.json") or []
    audit_log = load_json(evidence_folder, "audit_log.json")

    # Initialize exporter and extract IOCs
    case_name = evidence_folder.split("\\")[-1] if "\\" in evidence_folder else evidence_folder.split("/")[-1]
    exporter = ForensicExporter(case_name, risk_engine)
    exporter.extract_iocs_from_data(
        processes=processes,
        network=network,
        dns=dns,
        browser=browser,
        files=files
    )
    iocs = exporter.get_iocs()

    # Render hero section (risk score)
    summary = ExecutiveSummary(risk_engine)
    summary.render_hero_section()

    st.markdown("<div style='height:20px;'></div>", unsafe_allow_html=True)

    # Collection Info Section (if audit_log exists)
    if audit_log:
        col_version = audit_log.get('collector_version', 'Unknown')
        col_start = audit_log.get('collection_start', '')
        col_end = audit_log.get('collection_end', '')
        col_duration = audit_log.get('duration_seconds', 0)
        col_hostname = audit_log.get('hostname', 'Unknown')
        col_artifacts = len(audit_log.get('artifacts_collected', []))

        st.markdown(f'''<div style="background:linear-gradient(135deg,#0d1117 0%,#161b22 100%);border-radius:8px;border:1px solid #30363d;padding:12px 16px;margin-bottom:15px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;"><div style="display:flex;align-items:center;gap:15px;flex-wrap:wrap;"><div style="display:flex;align-items:center;gap:8px;"><span style="color:#58a6ff;font-size:0.85rem;">Collector v{col_version}</span></div><div style="color:#30363d;">|</div><div style="color:#8b949e;font-size:0.8rem;">Collected: {col_end[:19] if col_end else "N/A"}</div><div style="color:#30363d;">|</div><div style="color:#8b949e;font-size:0.8rem;">Duration: {col_duration}s</div><div style="color:#30363d;">|</div><div style="color:#8b949e;font-size:0.8rem;">Artifacts: {col_artifacts}</div></div></div>''', unsafe_allow_html=True)

    # Detection Engines
    sigma_stats = st.session_state.get('sigma_stats', {})
    yara_stats = st.session_state.get('yara_stats', {})
    ti_stats = st.session_state.get('threat_intel_stats', {})

    sigma_rules = sigma_stats.get('rules_loaded', 0) or st.session_state.get('sigma_rules_count', 0)
    sigma_matches = sigma_stats.get('total_matches', 0)
    sigma_critical = sigma_stats.get('critical_matches', 0)
    sigma_high = sigma_stats.get('high_matches', 0)

    yara_rules = yara_stats.get('rules_loaded', 0) or st.session_state.get('yara_rules_count', 0)
    yara_matches = yara_stats.get('total_matches', 0)
    yara_files = yara_stats.get('files_matched', 0)
    yara_critical = yara_stats.get('critical_matches', 0)

    ti_total = ti_stats.get('total_matches', 0)
    ti_ips = ti_stats.get('ip_matches', 0)
    ti_domains = ti_stats.get('domain_matches', 0)

    det_col1, det_col2, det_col3 = st.columns(3)

    with det_col1:
        sigma_status = "Active" if sigma_rules > 0 else "Inactive"
        sigma_color = "#3fb950" if sigma_rules > 0 else "#8b949e"
        st.markdown(f'''<div style="background:#0d1117;border-radius:8px;border:1px solid #30363d;padding:14px;">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
<span style="color:#c9d1d9;font-weight:600;">Sigma</span>
<span style="background:{sigma_color}30;color:{sigma_color};padding:2px 8px;border-radius:10px;font-size:0.7rem;">{sigma_status}</span>
</div>
<div style="display:flex;gap:12px;">
<div><span style="color:#58a6ff;font-weight:600;">{sigma_rules}</span> <span style="color:#6e7681;font-size:0.75rem;">rules</span></div>
<div><span style="color:#f85149;font-weight:600;">{sigma_matches}</span> <span style="color:#6e7681;font-size:0.75rem;">hits</span></div>
</div>
</div>''', unsafe_allow_html=True)

    with det_col2:
        yara_status = "Active" if yara_rules > 0 else "Inactive"
        yara_color = "#3fb950" if yara_rules > 0 else "#8b949e"
        match_color = "#f85149" if yara_matches > 0 else "#6e7681"
        st.markdown(f'''<div style="background:#0d1117;border-radius:8px;border:1px solid #30363d;padding:14px;">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
<span style="color:#c9d1d9;font-weight:600;">YARA</span>
<span style="background:{yara_color}30;color:{yara_color};padding:2px 8px;border-radius:10px;font-size:0.7rem;">{yara_status}</span>
</div>
<div style="display:flex;gap:12px;">
<div><span style="color:#a371f7;font-weight:600;">{yara_rules}</span> <span style="color:#6e7681;font-size:0.75rem;">rules</span></div>
<div><span style="color:{match_color};font-weight:600;">{yara_matches}</span> <span style="color:#6e7681;font-size:0.75rem;">hits</span></div>
</div>
</div>''', unsafe_allow_html=True)

    with det_col3:
        st.markdown(f'''<div style="background:#0d1117;border-radius:8px;border:1px solid #30363d;padding:14px;">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
<span style="color:#c9d1d9;font-weight:600;">Threat Intel</span>
<span style="background:#3fb95030;color:#3fb950;padding:2px 8px;border-radius:10px;font-size:0.7rem;">Active</span>
</div>
<div style="display:flex;gap:12px;">
<div><span style="color:#f85149;font-weight:600;">{ti_total}</span> <span style="color:#6e7681;font-size:0.75rem;">hits</span></div>
<div><span style="color:#58a6ff;font-weight:600;">{ti_ips + ti_domains}</span> <span style="color:#6e7681;font-size:0.75rem;">IOCs</span></div>
</div>
</div>''', unsafe_allow_html=True)

    st.markdown("<div style='height:20px;'></div>", unsafe_allow_html=True)

    # Dashboard Navigation Tree and IOC Summary side by side
    col1, col2 = st.columns(2)

    with col1:
        # Navigation Tree
        st.markdown('''<div style="background:#0d1117;border-radius:10px;border:1px solid #30363d;padding:18px 20px;">
<div style="color:#c9d1d9;font-weight:600;margin-bottom:14px;font-size:0.95rem;">Dashboard Structure</div>
<div style="font-family:monospace;font-size:0.78rem;line-height:1.9;color:#8b949e;">
<div><span style="color:#58a6ff;">Home</span> <span style="color:#484f58;">─ Executive overview</span></div>
<div><span style="color:#58a6ff;">Search</span> <span style="color:#484f58;">─ Search, Pivot, Notes, Export</span></div>
<div><span style="color:#58a6ff;">Findings</span> <span style="color:#484f58;">─ Security findings</span></div>
<div><span style="color:#58a6ff;">Timeline</span> <span style="color:#484f58;">─ Activity Chart, Events, Flagged</span></div>
<div><span style="color:#58a6ff;">MITRE</span> <span style="color:#484f58;">─ Techniques, Evidence</span></div>
<div><span style="color:#58a6ff;">Processes</span> <span style="color:#484f58;">─ Table, Tree, Deep Dive, Suspicious</span></div>
<div><span style="color:#58a6ff;">Execution</span> <span style="color:#484f58;">─ Shimcache, UserAssist, Prefetch, LNK, PS</span></div>
<div><span style="color:#58a6ff;">Persistence</span> <span style="color:#484f58;">─ Registry, Tasks, Services, WMI, Startup</span></div>
<div><span style="color:#58a6ff;">Network</span> <span style="color:#484f58;">─ Connections, ARP, Hosts, BITS</span></div>
<div><span style="color:#58a6ff;">Files</span> <span style="color:#484f58;">─ Recent Files, Jump Lists, Shellbags</span></div>
<div><span style="color:#58a6ff;">Browser</span> <span style="color:#484f58;">─ History, Cookies, Downloads, Cache</span></div>
<div><span style="color:#58a6ff;">USB</span> <span style="color:#484f58;">─ Registry, Events, SetupAPI</span></div>
<div><span style="color:#58a6ff;">Logs</span> <span style="color:#484f58;">─ Event Table, Event ID Reference</span></div>
<div><span style="color:#58a6ff;">Software</span> <span style="color:#484f58;">─ Applications, DNS Cache</span></div>
<div><span style="color:#58a6ff;">Integrity</span> <span style="color:#484f58;">─ Hashes, Verify, Manifest, Registry</span></div>
</div>
</div>''', unsafe_allow_html=True)

    with col2:
        summary.render_ioc_summary(iocs, case_name)
