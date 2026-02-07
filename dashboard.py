"""
SOC Forensic Investigator Platform v2.0.0
Slim orchestrator entry point.

This is the main entry point for the dashboard. It initializes the risk engine,
loads evidence data, and renders the appropriate tab modules.
"""
import os
import sys
import re
from datetime import datetime

import streamlit as st
import pandas as pd

# Add the current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.security import escape_html

from core.data_loader import load_json
from components.keyboard_shortcuts import inject_keyboard_shortcuts
from components.quick_actions import init_quick_actions_state, render_flagged_sidebar
from components.auth import check_auth, render_login_screen, render_logout_button
from components.case_header import render_case_header
from components.activity_log import init_activity_log, render_activity_sidebar
from core.risk_engine import RiskEngine
from core.correlator import ArtifactCorrelator
from core.evidence_cache import load_all_evidence, get_evidence
from core.sigma_engine import SigmaEngine, YAML_AVAILABLE
from core.threat_intel import ThreatIntelEngine
from core.yara_engine import YaraEngine, YARA_AVAILABLE
from tabs import home, findings, timeline, processes, network, persistence, execution, files, usb, logs, software, browser, mitre, integrity, search

# Page configuration
st.set_page_config(
    layout="wide",
    page_title="SOC Investigator v2.0.0",
    page_icon="🛡️"
)

# Authentication check - must pass before accessing dashboard
if not check_auth():
    render_login_screen()
    st.stop()

# Initialize quick actions state and inject keyboard shortcuts
init_quick_actions_state()
inject_keyboard_shortcuts()
init_activity_log()

# Add logout button and activity log to sidebar
render_logout_button()
render_activity_sidebar()

# Custom CSS for consistent styling and responsiveness
st.markdown('''<style>
/* Global spacing */
.block-container {padding-top: 1rem; padding-bottom: 2rem;}

/* Tab styling */
div[data-testid="stTabs"] button {font-size: 0.9rem; padding: 8px 16px;}
div[data-testid="stTabs"] [data-baseweb="tab-list"] {gap: 4px;}

/* Table improvements */
div[data-testid="stDataFrame"] {border-radius: 8px; overflow: hidden;}

/* Button consistency */
.stButton > button {border-radius: 6px; transition: all 0.2s ease;}
.stDownloadButton > button {border-radius: 6px;}

/* Expander styling */
div[data-testid="stExpander"] {border-radius: 8px; border: 1px solid rgba(255,255,255,0.1);}

/* Metric cards */
div[data-testid="stMetric"] {background: rgba(30,30,46,0.5); padding: 12px; border-radius: 8px;}

/* Mobile responsiveness */
@media (max-width: 768px) {
    .block-container {padding-left: 1rem; padding-right: 1rem;}
    div[data-testid="stTabs"] button {font-size: 0.8rem; padding: 6px 10px;}
    div[data-testid="stHorizontalBlock"] {flex-wrap: wrap;}
}

/* Scrollbar styling for dark mode */
::-webkit-scrollbar {width: 8px; height: 8px;}
::-webkit-scrollbar-track {background: #1e1e2e;}
::-webkit-scrollbar-thumb {background: #4a4a6a; border-radius: 4px;}
::-webkit-scrollbar-thumb:hover {background: #5a5a7a;}

/* Toast notifications */
div[data-testid="stToast"] {border-radius: 8px;}

/* Input fields */
div[data-testid="stTextInput"] input {border-radius: 6px;}
div[data-testid="stSelectbox"] > div {border-radius: 6px;}
</style>''', unsafe_allow_html=True)

# Header Banner with Logo
st.markdown('''<div style="background:linear-gradient(135deg,#0a0a15 0%,#1a1a2e 40%,#16213e 70%,#0f3460 100%);border-radius:12px;padding:20px 30px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:15px;border:1px solid rgba(102,126,234,0.3);box-shadow:0 4px 20px rgba(0,0,0,0.3);">
<div style="display:flex;align-items:center;gap:18px;">
<div style="background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);width:60px;height:60px;border-radius:12px;display:flex;align-items:center;justify-content:center;box-shadow:0 4px 15px rgba(102,126,234,0.4);">
<span style="font-size:2rem;filter:drop-shadow(0 2px 4px rgba(0,0,0,0.3));">🛡️</span>
</div>
<div>
<div style="display:flex;align-items:center;gap:12px;">
<span style="font-size:1.5rem;font-weight:bold;color:white;letter-spacing:0.5px;">SOC Forensic Investigator</span>
<span style="background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;padding:3px 10px;border-radius:12px;font-size:0.7rem;font-weight:600;">v2.0.0</span>
</div>
<div style="color:#888;font-size:0.85rem;margin-top:4px;">Advanced Threat Detection & Analysis Platform</div>
</div>
</div>
<div style="display:flex;align-items:center;gap:15px;">
<div style="text-align:right;">
<div style="color:#667eea;font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;">Powered by</div>
<div style="color:white;font-size:0.9rem;font-weight:600;">DFIR Analytics Engine</div>
</div>
<div style="width:1px;height:35px;background:rgba(255,255,255,0.1);"></div>
<div style="display:flex;gap:8px;">
<div style="width:8px;height:8px;border-radius:50%;background:#28a745;box-shadow:0 0 10px #28a745;"></div>
<span style="color:#888;font-size:0.8rem;">Online</span>
</div>
</div>
</div>''', unsafe_allow_html=True)

# ============================================================================
# CASE SELECTION SECTION
# ============================================================================

def parse_case_info(folder_path: str) -> dict:
    """Parse case information from folder name and contents."""
    folder_name = os.path.basename(folder_path)
    info = {
        "name": folder_name,
        "hostname": "Unknown",
        "date": None,
        "date_str": "Unknown",
        "file_count": 0,
        "size_mb": 0,
        "path": folder_path
    }

    # Parse folder name: Evidence_HOSTNAME_YYYYMMDD_HHMMSS
    match = re.match(r'Evidence_([^_]+)_(\d{8})_(\d{6})', folder_name)
    if match:
        info["hostname"] = match.group(1)
        date_str = match.group(2)
        time_str = match.group(3)
        try:
            info["date"] = datetime.strptime(f"{date_str}{time_str}", "%Y%m%d%H%M%S")
            info["date_str"] = info["date"].strftime("%Y-%m-%d %H:%M")
        except ValueError:
            pass

    # Count JSON files and calculate size
    try:
        total_size = 0
        file_count = 0
        for f in os.listdir(folder_path):
            if f.endswith('.json'):
                file_count += 1
                file_path = os.path.join(folder_path, f)
                total_size += os.path.getsize(file_path)
        info["file_count"] = file_count
        info["size_mb"] = round(total_size / (1024 * 1024), 2)
    except Exception:
        pass

    return info


# Find evidence folders in the tool's directory (not current working directory)
# This ensures the tool works from USB regardless of where it's launched from
TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
subfolders = [f.path for f in os.scandir(TOOL_DIR) if f.is_dir() and "Evidence" in f.name]

# Check if we have any folders
if not subfolders:
    st.markdown('''<div style="background:rgba(220,53,69,0.1);border:1px solid #dc3545;border-radius:10px;padding:25px;text-align:center;">
<div style="font-size:2.5rem;margin-bottom:10px;">📭</div>
<div style="color:#dc3545;font-size:1.1rem;font-weight:600;">No Evidence Folders Found</div>
<div style="color:#888;font-size:0.9rem;margin-top:8px;">Run <code style="background:#333;padding:2px 8px;border-radius:4px;">SOC_Collector.exe</code> to collect evidence first.</div>
</div>''', unsafe_allow_html=True)
    st.stop()

# Parse case info for all folders
cases = [parse_case_info(f) for f in subfolders]
cases.sort(key=lambda x: x["date"] or datetime.min, reverse=True)

# Build options for selectbox with rich info
case_options = []
for case in cases:
    hostname = escape_html(case["hostname"])
    date_str = escape_html(case["date_str"])
    file_count = case["file_count"]
    size_mb = case["size_mb"]
    label = f"🖥️ {hostname}  •  📅 {date_str}  •  📄 {file_count} artifacts  •  💾 {size_mb} MB"
    case_options.append(label)

# Initialize selected case in session state
if "selected_case_idx" not in st.session_state:
    st.session_state.selected_case_idx = 0

# Get current selection for display
current_case = cases[st.session_state.selected_case_idx]
current_label = case_options[st.session_state.selected_case_idx]

# Enhanced Case Selection Bar
st.markdown(f'''<div style="background:linear-gradient(135deg,#12121a 0%,#1a1a2e 100%);border-radius:10px;padding:18px 24px;margin-bottom:20px;border:1px solid rgba(102,126,234,0.2);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:15px;">
<div style="display:flex;align-items:center;gap:20px;">
<div style="position:relative;">
<div style="background:linear-gradient(135deg,#28a745 0%,#20c997 100%);width:50px;height:50px;border-radius:10px;display:flex;align-items:center;justify-content:center;">
<span style="font-size:1.5rem;">🖥️</span>
</div>
<div style="position:absolute;bottom:-3px;right:-3px;width:14px;height:14px;background:#28a745;border-radius:50%;border:2px solid #12121a;"></div>
</div>
<div>
<div style="color:#888;font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">Active Investigation</div>
<div style="color:white;font-size:1.2rem;font-weight:600;">{escape_html(current_case["hostname"])}</div>
<div style="color:#667eea;font-size:0.8rem;margin-top:2px;">{escape_html(current_case["date_str"])}</div>
</div>
</div>
<div style="display:flex;gap:20px;align-items:center;">
<div style="text-align:center;padding:8px 15px;background:rgba(72,219,251,0.1);border-radius:8px;border:1px solid rgba(72,219,251,0.2);">
<div style="color:#48dbfb;font-size:1.3rem;font-weight:bold;">{current_case["file_count"]}</div>
<div style="color:#888;font-size:0.65rem;text-transform:uppercase;">Artifacts</div>
</div>
<div style="text-align:center;padding:8px 15px;background:rgba(254,202,87,0.1);border-radius:8px;border:1px solid rgba(254,202,87,0.2);">
<div style="color:#feca57;font-size:1.3rem;font-weight:bold;">{current_case["size_mb"]}</div>
<div style="color:#888;font-size:0.65rem;text-transform:uppercase;">MB</div>
</div>
<div style="text-align:center;padding:8px 15px;background:rgba(102,126,234,0.1);border-radius:8px;border:1px solid rgba(102,126,234,0.2);">
<div style="color:#667eea;font-size:1.3rem;font-weight:bold;">{len(cases)}</div>
<div style="color:#888;font-size:0.65rem;text-transform:uppercase;">Cases</div>
</div>
</div>
</div>''', unsafe_allow_html=True)

# Case switcher dropdown (only show if multiple cases)
if len(cases) > 1:
    with st.expander("🔄 Switch Case", expanded=False):
        cols = st.columns([4, 1])
        with cols[0]:
            selected_idx = st.radio(
                "Select Case",
                range(len(case_options)),
                index=st.session_state.selected_case_idx,
                format_func=lambda i: case_options[i],
                label_visibility="collapsed"
            )
        if selected_idx != st.session_state.selected_case_idx:
            st.session_state.selected_case_idx = selected_idx
            st.rerun()

selected_case = cases[st.session_state.selected_case_idx]
selected_folder = selected_case["path"]

# Track folder changes and clear cache when switching cases
if "current_evidence_folder" not in st.session_state:
    st.session_state.current_evidence_folder = selected_folder
elif st.session_state.current_evidence_folder != selected_folder:
    # Folder changed - clear data cache for the old folder
    from core.data_loader import clear_data_cache
    clear_data_cache(st.session_state.current_evidence_folder)
    st.session_state.current_evidence_folder = selected_folder

# Initialize risk engine with rules and whitelist
rules_path = os.path.join(os.path.dirname(__file__), "config", "risk_rules.json")
whitelist_path = os.path.join(os.path.dirname(__file__), "config", "whitelist.json")
risk_engine = RiskEngine(
    rules_path if os.path.exists(rules_path) else None,
    whitelist_path if os.path.exists(whitelist_path) else None
)

# Preload all evidence data into session state cache (runs once per folder selection)
with st.spinner("Loading evidence data..."):
    evidence_data = load_all_evidence(selected_folder)

# Sigma rules path and engine (defined at module level)
SIGMA_RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "sigma_rules")
YARA_RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules", "yara")
ANALYSIS_VERSION = "2.6.0"  # Increment to invalidate cache when detection logic changes

# Initialize Sigma engine once at module level
if YAML_AVAILABLE and os.path.exists(SIGMA_RULES_PATH):
    _sigma_engine_global = SigmaEngine(SIGMA_RULES_PATH)
else:
    _sigma_engine_global = SigmaEngine()

# Initialize YARA engine once at module level
if YARA_AVAILABLE and os.path.exists(YARA_RULES_PATH):
    _yara_engine_global = YaraEngine(YARA_RULES_PATH)
else:
    _yara_engine_global = YaraEngine()

# Store in session state
st.session_state.sigma_rules_count = len(_sigma_engine_global.rules)
st.session_state.sigma_yaml_available = YAML_AVAILABLE
st.session_state.sigma_path_exists = os.path.exists(SIGMA_RULES_PATH)
st.session_state.yara_rules_count = _yara_engine_global.rules_count
st.session_state.yara_available = YARA_AVAILABLE

# Pre-analyze data for global risk scoring
@st.cache_resource
def analyze_evidence(folder_path: str, _evidence_hash: str = None, _version: str = ANALYSIS_VERSION):
    """Analyze evidence and return risk data. Uses preloaded data from cache."""
    engine = RiskEngine(
        rules_path if os.path.exists(rules_path) else None,
        whitelist_path if os.path.exists(whitelist_path) else None
    )

    # Initialize Sigma engine with rules
    sigma_engine = SigmaEngine(SIGMA_RULES_PATH if os.path.exists(SIGMA_RULES_PATH) else None)

    # Initialize YARA engine with rules
    yara_engine = YaraEngine(YARA_RULES_PATH if os.path.exists(YARA_RULES_PATH) else None)

    # Initialize Threat Intel engine
    threat_intel = ThreatIntelEngine()

    # Get preloaded data from cache
    procs = get_evidence(folder_path, "processes")
    net = get_evidence(folder_path, "network")
    events = get_evidence(folder_path, "events")
    files_data = get_evidence(folder_path, "recent_files")
    dns = get_evidence(folder_path, "dns")
    wmi = get_evidence(folder_path, "wmi")
    shimcache = get_evidence(folder_path, "shimcache")
    startup = get_evidence(folder_path, "startup")
    bits = get_evidence(folder_path, "bits_jobs")

    # Analyze processes
    if procs:
        df_p = pd.DataFrame(procs)
        if 'cmdline' in df_p.columns:
            df_p['cmdline'] = df_p['cmdline'].apply(
                lambda x: " ".join(x) if isinstance(x, list) else (str(x) if x else "")
            )
        for _, row in df_p.iterrows():
            engine.assess_process(row)

            # Sigma rule matching for processes
            if YAML_AVAILABLE and sigma_engine.rules:
                proc_dict = row.to_dict()
                sigma_matches = sigma_engine.match_process(proc_dict)
                for match in sigma_matches:
                    # Convert Sigma match to Finding
                    from core.risk_engine import Finding
                    severity_scores = {'critical': 55, 'high': 40, 'medium': 25, 'low': 10, 'info': 5}
                    finding = Finding(
                        category=f"Sigma: {match.rule_name}",
                        description=match.description,
                        score=severity_scores.get(match.severity, 25),
                        severity=match.severity,
                        mitre_techniques=match.mitre_techniques,
                        source="sigma",
                        evidence={
                            "rule_id": match.rule_id,
                            "matched_field": match.matched_field,
                            "matched_value": match.matched_value,
                            **{k: str(v)[:200] for k, v in match.evidence.items() if v}
                        }
                    )
                    engine._add_finding(finding)

    # Analyze network connections
    if net:
        df_n = pd.DataFrame(net)
        for _, row in df_n.iterrows():
            engine.assess_network(row)

        # Threat Intel checks for network connections
        ti_results = threat_intel.analyze_network_connections(net)
        for indicator in ti_results:
            from core.risk_engine import Finding
            confidence_scores = {'high': 50, 'medium': 35, 'low': 20}
            finding = Finding(
                category=f"Threat Intel: {indicator.threat_type.replace('_', ' ').title()}",
                description=indicator.description,
                score=confidence_scores.get(indicator.confidence, 35),
                severity='high' if indicator.confidence == 'high' else 'medium',
                mitre_techniques=["T1071"] if indicator.indicator_type == 'domain' else ["T1090"],
                source="threat_intel",
                evidence={
                    "indicator_type": indicator.indicator_type,
                    "value": indicator.value,
                    "source": indicator.source,
                    "tags": ", ".join(indicator.tags) if indicator.tags else ""
                }
            )
            engine._add_finding(finding)

    # Analyze events
    if events:
        df_e = pd.DataFrame(events)
        if 'Id' in df_e.columns:
            assessed_ids = set()
            for _, row in df_e.iterrows():
                try:
                    event_id = int(row.get('Id', 0))
                    if event_id and event_id not in assessed_ids:
                        engine.assess_event(event_id, row.to_dict())
                        assessed_ids.add(event_id)
                except (ValueError, TypeError):
                    pass

    # Analyze files
    if files_data:
        df_f = pd.DataFrame(files_data)
        for _, row in df_f.iterrows():
            engine.assess_file(row)

    # YARA scanning on files within evidence folder only (not external system files)
    if YARA_AVAILABLE and yara_engine.is_available():
        yara_matches = yara_engine.scan_directory(folder_path, recursive=True)
        for match in yara_matches:
            from core.risk_engine import Finding
            severity_scores = {'critical': 60, 'high': 45, 'medium': 30, 'low': 15}
            finding = Finding(
                category=f"YARA: {match.rule_name}",
                description=match.description or f"YARA rule {match.rule_name} matched on {match.file_name}",
                score=severity_scores.get(match.severity, 45),
                severity=match.severity,
                mitre_techniques=match.mitre_techniques if match.mitre_techniques else ["T1027"],
                source="yara",
                evidence={
                    "rule": match.rule_name,
                    "namespace": match.rule_namespace,
                    "file": match.file_name,
                    "file_path": match.file_path,
                    "matched_strings": ", ".join(match.matched_strings[:5]) if match.matched_strings else "",
                    "tags": ", ".join(match.tags[:5]) if match.tags else ""
                }
            )
            engine._add_finding(finding)

    # Analyze DNS
    if dns:
        for record in dns:
            name = record.get('Entry') or record.get('Record Name', '')
            if name:
                engine.assess_dns(name)

        # Threat Intel checks for DNS
        ti_dns_results = threat_intel.analyze_dns_cache(dns)
        for indicator in ti_dns_results:
            from core.risk_engine import Finding
            confidence_scores = {'high': 50, 'medium': 35, 'low': 20}
            finding = Finding(
                category=f"Threat Intel: {indicator.threat_type.replace('_', ' ').title()}",
                description=indicator.description,
                score=confidence_scores.get(indicator.confidence, 35),
                severity='critical' if indicator.confidence == 'high' else 'medium',
                mitre_techniques=["T1071.004"] if 'dns' in indicator.threat_type else ["T1071"],
                source="threat_intel",
                evidence={
                    "indicator_type": indicator.indicator_type,
                    "value": indicator.value,
                    "source": indicator.source,
                    "tags": ", ".join(indicator.tags) if indicator.tags else ""
                }
            )
            engine._add_finding(finding)

    # Analyze WMI persistence
    if wmi:
        for entry in wmi:
            engine.assess_wmi_persistence(entry)

    # Analyze shimcache
    if shimcache:
        for entry in shimcache:
            engine.assess_shimcache(entry)

    # Analyze startup files
    if startup:
        for entry in startup:
            engine.assess_startup_file(entry)

    # Analyze BITS jobs
    if bits:
        for entry in bits:
            engine.assess_bits_job(entry)

    # Analyze events for brute force attacks (requires all events)
    if events:
        engine.assess_brute_force(events)

    return {
        'score': engine.get_global_score(),
        'severity': engine.get_severity(),
        'findings': engine.all_findings,
        'techniques': list(engine.mitre_techniques),
        'category_scores': dict(engine._category_scores),  # Store category scores for proper restoration
        'sigma_stats': sigma_engine.get_stats() if YAML_AVAILABLE and sigma_engine.rules else {},
        'yara_stats': yara_engine.get_stats() if YARA_AVAILABLE and yara_engine.is_available() else {},
        'threat_intel_stats': threat_intel.get_stats()
    }


# Show warning if some files failed to load
load_stats = st.session_state.get('evidence_load_stats', {})
if load_stats.get('failed', 0) > 0:
    failed_files = load_stats.get('failed_files', [])
    st.warning(f"⚠️ {load_stats['failed']} file(s) could not be loaded: {', '.join(failed_files[:3])}" +
               (f" (+{len(failed_files) - 3} more)" if len(failed_files) > 3 else ""))

# Get cached analysis (use folder basename and version as cache key)
with st.spinner("Analyzing evidence..."):
    analysis = analyze_evidence(selected_folder, _evidence_hash=os.path.basename(selected_folder), _version=ANALYSIS_VERSION)

# Reconstruct risk engine with cached findings and scores
risk_engine.all_findings = analysis['findings']
risk_engine.mitre_techniques = set(analysis['techniques'])
risk_engine._category_scores = analysis.get('category_scores', {})

# Store detection engine stats in session state for display in tabs
st.session_state.sigma_stats = analysis.get('sigma_stats', {})
st.session_state.yara_stats = analysis.get('yara_stats', {})
st.session_state.threat_intel_stats = analysis.get('threat_intel_stats', {})

# Tab navigation - ordered by forensic investigation flow
tabs = st.tabs([
    "Home",           # 0 - Overview
    "Search",         # 1 - Quick search
    "Findings",       # 2 - Security findings
    "Timeline",       # 3 - Event sequence
    "MITRE",          # 4 - Attack mapping
    "Processes",      # 5 - Running processes
    "Execution",      # 6 - Execution artifacts
    "Persistence",    # 7 - Persistence mechanisms
    "Network",        # 8 - Network connections
    "Files",          # 9 - File artifacts
    "Browser",        # 10 - Web activity
    "USB",            # 11 - External devices
    "Logs",           # 12 - Event logs
    "Software",       # 13 - Installed software
    "Integrity"       # 14 - System integrity
])

# Helper to safely render tabs with error handling
def safe_render_tab(tab_module, tab_name: str, folder: str, engine):
    """Render a tab with error handling."""
    try:
        tab_module.render(folder, engine)
    except Exception as e:
        import traceback
        error_msg = str(e)[:200]
        st.markdown(f'''
            <div style="background:rgba(248,81,73,0.1);border:1px solid #f85149;border-radius:10px;padding:25px;text-align:center;margin:20px 0;">
                <div style="font-size:2rem;margin-bottom:10px;">⚠️</div>
                <div style="color:#f85149;font-size:1.1rem;font-weight:600;">Error Loading {tab_name}</div>
                <div style="color:#888;font-size:0.9rem;margin-top:8px;">An error occurred while rendering this tab.</div>
                <div style="font-family:monospace;font-size:0.75rem;color:#888;margin-top:10px;padding:8px;background:#0d1117;border-radius:4px;">{escape_html(error_msg)}</div>
            </div>
        ''', unsafe_allow_html=True)
        with st.expander("Show error details"):
            st.code(traceback.format_exc())

# Render each tab with error handling
with tabs[0]:
    safe_render_tab(home, "Home", selected_folder, risk_engine)

with tabs[1]:
    safe_render_tab(search, "Search", selected_folder, risk_engine)

with tabs[2]:
    safe_render_tab(findings, "Findings", selected_folder, risk_engine)

with tabs[3]:
    safe_render_tab(timeline, "Timeline", selected_folder, risk_engine)

with tabs[4]:
    safe_render_tab(mitre, "MITRE", selected_folder, risk_engine)

with tabs[5]:
    safe_render_tab(processes, "Processes", selected_folder, risk_engine)

with tabs[6]:
    safe_render_tab(execution, "Execution", selected_folder, risk_engine)

with tabs[7]:
    safe_render_tab(persistence, "Persistence", selected_folder, risk_engine)

with tabs[8]:
    safe_render_tab(network, "Network", selected_folder, risk_engine)

with tabs[9]:
    safe_render_tab(files, "Files", selected_folder, risk_engine)

with tabs[10]:
    safe_render_tab(browser, "Browser", selected_folder, risk_engine)

with tabs[11]:
    safe_render_tab(usb, "USB", selected_folder, risk_engine)

with tabs[12]:
    safe_render_tab(logs, "Logs", selected_folder, risk_engine)

with tabs[13]:
    safe_render_tab(software, "Software", selected_folder, risk_engine)

with tabs[14]:
    safe_render_tab(integrity, "Integrity", selected_folder, risk_engine)

# Render flagged indicators sidebar
render_flagged_sidebar()
