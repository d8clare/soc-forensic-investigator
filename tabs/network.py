"""
Network Intelligence Tab - Professional Forensic Investigation View.
Displays network connections, ARP table, and hosts file analysis.
"""
import os
import streamlit as st
import pandas as pd
import re

from core.data_loader import load_json, load_text_file, sanitize_dataframe, parse_dotnet_date
from core.risk_engine import RiskEngine
from core.security import escape_html, safe_html_value, logger
from components.data_table import create_abuseipdb_link
from components.ui_components import no_data_message, info_banner


# Suspicious ports commonly used by malware/C2
SUSPICIOUS_PORTS = {
    # C2 / RAT ports
    4444: "Metasploit Default",
    5555: "Android ADB / RAT",
    6666: "IRC Bot / Backdoor",
    6667: "IRC C2",
    1337: "Leet / Backdoor",
    31337: "Back Orifice",
    12345: "NetBus",
    27374: "SubSeven",
    65535: "RC1 Trojan",
    # Remote Access
    3389: "RDP",
    5900: "VNC",
    5938: "TeamViewer",
    22: "SSH",
    23: "Telnet",
    # Suspicious services
    4443: "Alt HTTPS / C2",
    8443: "Alt HTTPS",
    9001: "Tor / C2",
    9050: "Tor SOCKS",
    9150: "Tor Browser",
    # Mining
    3333: "Crypto Mining",
    14444: "Crypto Mining",
    45700: "Crypto Mining",
}

# Private IP ranges
PRIVATE_RANGES = [
    (r'^10\.', 'Private (10.x.x.x)'),
    (r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', 'Private (172.16-31.x.x)'),
    (r'^192\.168\.', 'Private (192.168.x.x)'),
    (r'^127\.', 'Loopback'),
    (r'^0\.0\.0\.0', 'Any'),
    (r'^169\.254\.', 'Link-Local'),
]


def render(evidence_folder: str, risk_engine: RiskEngine):
    """Render the Network Intelligence tab."""

    # Load all data first for stats
    net_data = load_json(evidence_folder, "network_connections.json")
    proc_data = load_json(evidence_folder, "processes.json")
    arp_data = load_json(evidence_folder, "arp_table.json")
    hosts_content = load_text_file(evidence_folder, "hosts_file_backup")
    bits_data = load_json(evidence_folder, "bits_jobs.json")

    # Analyze network stats (cached)
    folder_name = os.path.basename(evidence_folder)
    net_stats = analyze_network_stats(net_data, folder_name) if net_data else {}

    total_connections = len(net_data) if net_data else 0
    established = net_stats.get('established', 0)
    external = net_stats.get('external', 0)
    suspicious = net_stats.get('suspicious', 0)
    total_bits = len(bits_data) if bits_data else 0

    # Simple header with blue styling
    st.markdown(f'<div style="color:#e6edf3;font-size:1.1rem;margin-bottom:15px;"><b>Network</b> | Connections: {total_connections} | External: {external} | Suspicious: {suspicious} | BITS: {total_bits}</div>', unsafe_allow_html=True)

    # Create subtabs
    net_tabs = st.tabs([
        f"Connections ({total_connections})",
        "ARP Table",
        "Hosts File",
        f"BITS Jobs ({total_bits})"
    ])

    # Tab 1: Active Connections
    with net_tabs[0]:
        render_connections_tab(net_data, proc_data, risk_engine)

    # Tab 2: ARP Table
    with net_tabs[1]:
        render_arp_tab(arp_data)

    # Tab 3: Hosts File
    with net_tabs[2]:
        render_hosts_tab(hosts_content)

    # Tab 4: BITS Jobs
    with net_tabs[3]:
        render_bits_tab(bits_data)

    # Export section
    st.markdown("---")
    col1, col2 = st.columns(2)

    with col1:
        if net_data:
            df_export = pd.DataFrame(net_data)
            st.download_button("🔌 Export Connections", df_export.to_csv(index=False), "network_connections.csv", "text/csv", key="net_export")
        else:
            st.button("🔌 No Connection Data", disabled=True, key="net_export_disabled")

    with col2:
        if arp_data:
            raw = arp_data[0].get('raw_content', '') if arp_data else ''
            st.download_button("📋 Export ARP Table", raw, "arp_table.txt", "text/plain", key="arp_export")
        else:
            st.button("📋 No ARP Data", disabled=True, key="arp_export_disabled")


@st.cache_data
def analyze_network_stats(net_data, _folder_name: str = ""):
    """Analyze network data for statistics. Cached for performance."""
    stats = {'established': 0, 'external': 0, 'suspicious': 0, 'listening': 0}

    for conn in net_data:
        status = conn.get('status', '')
        raddr = str(conn.get('raddr', ''))

        if status == 'ESTABLISHED':
            stats['established'] += 1
        elif status == 'LISTEN':
            stats['listening'] += 1

        # Check if external
        if raddr and ':' in raddr:
            ip = raddr.split(':')[0]
            port_str = raddr.split(':')[1] if len(raddr.split(':')) > 1 else '0'
            try:
                port = int(port_str)
            except:
                port = 0

            if not is_private_ip(ip) and ip not in ['', '0.0.0.0', '::', '*']:
                stats['external'] += 1

            # Check suspicious port
            if port in SUSPICIOUS_PORTS:
                stats['suspicious'] += 1

    return stats


def is_private_ip(ip):
    """Check if an IP address is private/internal."""
    for pattern, _ in PRIVATE_RANGES:
        if re.match(pattern, ip):
            return True
    return False


def get_ip_type(ip):
    """Get the type/classification of an IP address."""
    for pattern, label in PRIVATE_RANGES:
        if re.match(pattern, ip):
            return label
    return "External"


def render_connections_tab(net_data, proc_data, risk_engine):
    """Render the Active Connections subtab."""

    if not net_data:
        st.info("No network connection data collected.")
        return

    df_net = pd.DataFrame(net_data)

    # Correlate with process names
    if proc_data:
        pid_map = {p['pid']: p['name'] for p in proc_data}
        df_net['Process'] = df_net['pid'].map(pid_map).fillna("Unknown")
    else:
        df_net['Process'] = "Unknown"

    # Filter Section
    col_search, col_status, col_type = st.columns([2, 1.5, 1.5])

    with col_search:
        search_net = st.text_input("🔍 Search IP / Port / Process", placeholder="Enter keywords...", key="net_search")

    with col_status:
        statuses = ["All Status"]
        if 'status' in df_net.columns:
            statuses += df_net['status'].unique().tolist()
        status_filter = st.selectbox("Connection Status", statuses, key="net_status_filter")

    with col_type:
        type_filter = st.selectbox("Connection Type", ["All Connections", "Suspicious Only", "External Only", "Internal Only"], key="net_type_filter")

    # Enhanced risk and type analysis
    def analyze_connection(row):
        raddr = str(row.get('raddr', ''))
        laddr = str(row.get('laddr', ''))

        if not raddr or raddr in ['None', '']:
            return "⚪ No Remote", "N/A", ""

        # Parse remote address
        if ':' in raddr:
            parts = raddr.rsplit(':', 1)
            ip = parts[0]
            try:
                port = int(parts[1])
            except:
                port = 0
        else:
            ip = raddr
            port = 0

        # Determine IP type
        ip_type = get_ip_type(ip)

        # Check for suspicious ports
        if port in SUSPICIOUS_PORTS:
            port_desc = SUSPICIOUS_PORTS[port]
            if port in [4444, 5555, 6666, 6667, 1337, 31337, 12345, 27374]:
                return f"🔴 C2/Backdoor", ip_type, port_desc
            elif port in [3389, 5900, 5938]:
                return f"🟠 Remote Access", ip_type, port_desc
            elif port in [3333, 14444, 45700]:
                return f"🔴 Crypto Mining", ip_type, port_desc
            elif port in [9001, 9050, 9150]:
                return f"🟠 Tor/Anonymizer", ip_type, port_desc
            else:
                return f"🟡 Notable Port", ip_type, port_desc

        # Check base risk from engine
        base_risk = risk_engine.assess_network(row)
        if "High" in str(base_risk):
            return "🔴 High Risk", ip_type, ""
        if "Suspicious" in str(base_risk) or "RDP" in str(base_risk):
            return "🟠 Suspicious", ip_type, ""

        # External connections
        if ip_type == "External":
            return "🟡 External", ip_type, ""

        return "✅ Normal", ip_type, ""

    # Apply analysis
    analysis_results = df_net.apply(analyze_connection, axis=1)
    df_net['Risk'] = [r[0] for r in analysis_results]
    df_net['Network'] = [r[1] for r in analysis_results]
    df_net['Port Info'] = [r[2] for r in analysis_results]

    # Extract remote IP for threat intel
    def get_remote_ip(addr):
        if addr and ':' in str(addr):
            ip = str(addr).rsplit(':', 1)[0]
            if ip not in ['0.0.0.0', '127.0.0.1', '::', 'localhost', '', 'None']:
                return ip
        return None

    df_net['Remote IP'] = df_net['raddr'].apply(get_remote_ip)
    df_net['Intel'] = df_net['Remote IP'].apply(lambda x: create_abuseipdb_link(x) if x else "")

    # Apply search filter
    if search_net:
        search_lower = search_net.lower()
        mask = df_net.astype(str).apply(lambda x: x.str.lower().str.contains(search_lower, na=False)).any(axis=1)
        df_net = df_net[mask]

    # Apply status filter
    if status_filter != "All Status" and 'status' in df_net.columns:
        df_net = df_net[df_net['status'] == status_filter]

    # Apply type filter
    if type_filter == "Suspicious Only":
        df_net = df_net[df_net['Risk'].str.contains("🔴|🟠", regex=True)]
    elif type_filter == "External Only":
        df_net = df_net[df_net['Network'] == "External"]
    elif type_filter == "Internal Only":
        df_net = df_net[df_net['Network'].str.contains("Private|Loopback|Link-Local", regex=True)]

    # Sort by risk
    risk_order = {"🔴": 0, "🟠": 1, "🟡": 2, "✅": 3, "⚪": 4}
    df_net['_sort'] = df_net['Risk'].apply(lambda x: min([risk_order.get(k, 5) for k in risk_order if k in x], default=5))
    df_net = df_net.sort_values('_sort').drop('_sort', axis=1)

    st.markdown(f'<div style="color:#888;font-size:0.8rem;margin:10px 0;">Showing {len(df_net)} connections</div>', unsafe_allow_html=True)

    # Data table
    column_order = ["Risk", "Process", "pid", "laddr", "raddr", "status", "Network", "Intel"]

    st.dataframe(
        sanitize_dataframe(df_net),
        column_order=[c for c in column_order if c in df_net.columns],
        width="stretch",
        height=400,
        column_config={
            "Risk": st.column_config.TextColumn("Risk", width="small"),
            "Process": st.column_config.TextColumn("Process", width="medium"),
            "pid": st.column_config.NumberColumn("PID", format="%d", width="small"),
            "laddr": st.column_config.TextColumn("Local Address", width="medium"),
            "raddr": st.column_config.TextColumn("Remote Address", width="medium"),
            "status": st.column_config.TextColumn("State", width="small"),
            "Network": st.column_config.TextColumn("Network", width="small"),
            "Intel": st.column_config.LinkColumn("Threat Intel", display_text="Check IP")
        },
        hide_index=True
    )

    # IP Enrichment Section
    st.markdown("---")
    st.markdown("### 🔍 IP Enrichment")

    # Get unique external IPs
    external_ips = df_net[df_net['Remote IP'].notna()]['Remote IP'].unique().tolist()
    external_ips = [ip for ip in external_ips if not is_private_ip(ip)][:50]  # Limit to 50

    if external_ips:
        col1, col2 = st.columns([3, 1])
        with col1:
            selected_ip = st.selectbox(
                "Select IP to enrich:",
                external_ips,
                key="ip_enrich_select"
            )
        with col2:
            enrich_btn = st.button("🔍 Check IP", key="enrich_ip_btn")

        if enrich_btn and selected_ip:
            try:
                from core.threat_intel_api import ThreatIntelEnricher
                from core.security import get_api_key

                # Load API key from secure storage
                abuseipdb_key = get_api_key('abuseipdb_api_key') or ''

                enricher = ThreatIntelEnricher(
                    abuseipdb_api_key=abuseipdb_key
                )

                if enricher.abuseipdb.is_configured():
                    with st.spinner(f"Checking {selected_ip}..."):
                        result = enricher.enrich_ip(selected_ip)

                    if result:
                        score = result.abuse_confidence_score
                        score_color = "#28a745" if score < 25 else "#ffd93d" if score < 50 else "#ff9f43" if score < 75 else "#ff6b6b"

                        tor_text = "Yes" if result.is_tor else "No"
                        isp_text = result.isp[:30] if result.isp else "Unknown"
                        st.success(f"**{selected_ip}** - Abuse Score: {score}% | Country: {result.country_code or 'Unknown'} | ISP: {isp_text} | Reports: {result.total_reports} | Tor Exit: {tor_text}")
                    else:
                        st.info(f"No data found for {selected_ip}")
                else:
                    st.warning("AbuseIPDB API key not configured. Add your key via Settings.")
            except Exception as e:
                st.error(f"Error enriching IP: {str(e)}")
    else:
        st.info("No external IPs found to enrich.")


def render_arp_tab(arp_data):
    """Render the ARP Table subtab."""

    if not arp_data or len(arp_data) == 0:
        st.info("No ARP table data available.")
        return

    raw_content = arp_data[0].get('raw_content', '')

    if not raw_content:
        st.info("ARP table is empty.")
        return

    # Parse ARP entries for analysis
    lines = raw_content.strip().split('\n')
    arp_entries = []
    mac_counts = {}

    for line in lines:
        # Skip header lines
        if 'Interface' in line or 'Internet Address' in line or not line.strip():
            continue

        parts = line.split()
        if len(parts) >= 3:
            ip = parts[0]
            mac = parts[1].lower()
            entry_type = parts[2] if len(parts) > 2 else 'unknown'

            # Count MAC addresses for duplicate detection
            if mac != 'ff-ff-ff-ff-ff-ff' and mac not in ['(incomplete)', '']:
                mac_counts[mac] = mac_counts.get(mac, 0) + 1

            arp_entries.append({
                'IP Address': ip,
                'MAC Address': mac,
                'Type': entry_type
            })

    # Detect potential ARP spoofing (same MAC, different IPs)
    duplicate_macs = {mac: count for mac, count in mac_counts.items() if count > 1}

    if duplicate_macs:
        info_banner(f"Potential ARP Spoofing Detected - {len(duplicate_macs)} MAC address(es) associated with multiple IP addresses.", "error")

    # Search
    search_arp = st.text_input("search_arp", placeholder="🔍 Search IP or MAC address...", key="arp_search", label_visibility="collapsed")

    if arp_entries:
        df_arp = pd.DataFrame(arp_entries)

        # Add risk indicator
        def analyze_arp_entry(row):
            mac = row.get('MAC Address', '').lower()
            if mac in duplicate_macs:
                return "🔴 Duplicate MAC"
            if mac == 'ff-ff-ff-ff-ff-ff':
                return "📡 Broadcast"
            if '(incomplete)' in mac:
                return "⚠️ Incomplete"
            return "✅ Normal"

        df_arp['Status'] = df_arp.apply(analyze_arp_entry, axis=1)

        # Apply search
        if search_arp:
            search_lower = search_arp.lower()
            df_arp = df_arp[
                df_arp['IP Address'].str.lower().str.contains(search_lower, na=False) |
                df_arp['MAC Address'].str.lower().str.contains(search_lower, na=False)
            ]

        # Sort by status
        status_order = {"🔴": 0, "⚠️": 1, "📡": 2, "✅": 3}
        df_arp['_sort'] = df_arp['Status'].apply(lambda x: min([status_order.get(k, 4) for k in status_order if k in x], default=4))
        df_arp = df_arp.sort_values('_sort').drop('_sort', axis=1)

        st.markdown(f'<div style="color:#888;font-size:0.8rem;margin:10px 0;">Showing {len(df_arp)} ARP entries</div>', unsafe_allow_html=True)

        st.dataframe(
            sanitize_dataframe(df_arp),
            column_order=["Status", "IP Address", "MAC Address", "Type"],
            width="stretch",
            height=350,
            column_config={
                "Status": st.column_config.TextColumn("Status", width="small"),
                "IP Address": st.column_config.TextColumn("IP Address", width="medium"),
                "MAC Address": st.column_config.TextColumn("MAC Address", width="medium"),
                "Type": st.column_config.TextColumn("Type", width="small")
            },
            hide_index=True
        )

    # Raw content expander
    with st.expander("📄 View Raw ARP Table"):
        st.code(raw_content, language="text")


def render_hosts_tab(hosts_content):
    """Render the Hosts File subtab."""

    if not hosts_content:
        st.info("No hosts file backup found.")
        return

    # Parse hosts file
    lines = hosts_content.strip().split('\n')
    entries = []
    suspicious_entries = []

    # Known suspicious patterns
    suspicious_domains = ['update', 'microsoft', 'windows', 'google', 'facebook', 'bank', 'paypal', 'antivirus', 'kaspersky', 'norton', 'mcafee', 'avast']

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue

        parts = stripped.split()
        if len(parts) >= 2:
            ip = parts[0]
            domains = parts[1:]

            for domain in domains:
                is_suspicious = False
                reason = ""

                # Check for suspicious redirections
                if ip not in ['127.0.0.1', '::1', '0.0.0.0']:
                    # Redirecting to external IP
                    if any(kw in domain.lower() for kw in suspicious_domains):
                        is_suspicious = True
                        reason = "Suspicious redirect"
                elif ip in ['127.0.0.1', '0.0.0.0']:
                    # Blocking legitimate services
                    if any(kw in domain.lower() for kw in ['update', 'microsoft', 'antivirus', 'kaspersky', 'norton', 'mcafee', 'avast']):
                        is_suspicious = True
                        reason = "Blocking security/updates"

                entry = {
                    'IP Address': ip,
                    'Domain': domain,
                    'Status': "🔴 Suspicious" if is_suspicious else "✅ Normal",
                    'Reason': reason
                }
                entries.append(entry)
                if is_suspicious:
                    suspicious_entries.append(entry)

    # Alert if suspicious entries found
    if suspicious_entries:
        info_banner(f"{len(suspicious_entries)} Suspicious Host Entry(s) Detected - Potential DNS hijacking or security software blocking.", "error")

    # Search
    search_hosts = st.text_input("search_hosts", placeholder="🔍 Search IP or domain...", key="hosts_search", label_visibility="collapsed")

    st.markdown(f'<div style="color:#888;font-size:0.75rem;margin:5px 0;">📍 C:\\Windows\\System32\\drivers\\etc\\hosts</div>', unsafe_allow_html=True)

    if entries:
        df_hosts = pd.DataFrame(entries)

        # Apply search
        if search_hosts:
            search_lower = search_hosts.lower()
            df_hosts = df_hosts[
                df_hosts['IP Address'].str.lower().str.contains(search_lower, na=False) |
                df_hosts['Domain'].str.lower().str.contains(search_lower, na=False)
            ]

        # Sort suspicious first
        df_hosts['_sort'] = df_hosts['Status'].apply(lambda x: 0 if "🔴" in x else 1)
        df_hosts = df_hosts.sort_values('_sort').drop('_sort', axis=1)

        st.markdown(f'<div style="color:#888;font-size:0.8rem;margin:10px 0;">Showing {len(df_hosts)} custom entries</div>', unsafe_allow_html=True)

        st.dataframe(
            sanitize_dataframe(df_hosts),
            column_order=["Status", "IP Address", "Domain", "Reason"],
            width="stretch",
            height=300,
            column_config={
                "Status": st.column_config.TextColumn("Status", width="small"),
                "IP Address": st.column_config.TextColumn("IP Address", width="small"),
                "Domain": st.column_config.TextColumn("Domain", width="large"),
                "Reason": st.column_config.TextColumn("Notes", width="medium")
            },
            hide_index=True
        )
    else:
        st.success("No custom entries in hosts file (default configuration).")

    # Raw content expander
    with st.expander("📄 View Raw Hosts File"):
        st.code(hosts_content, language="text")


def render_bits_tab(bits_data):
    """Render the BITS Jobs subtab."""

    if not bits_data:
        st.info("No BITS jobs data collected. This usually means no active or recent BITS transfers.")
        return

    df_bits = pd.DataFrame(bits_data)

    # BITS JobState enum mapping (in case we get numbers from older collections)
    job_state_map = {
        '0': 'Queued', '1': 'Connecting', '2': 'Transferring', '3': 'Suspended',
        '4': 'Error', '5': 'TransientError', '6': 'Transferred', '7': 'Acknowledged', '8': 'Cancelled'
    }

    # TransferType enum mapping
    transfer_type_map = {
        '0': 'Download', '1': 'Upload', '2': 'UploadReply'
    }

    # Convert .NET JSON date format to readable datetime
    for time_col in ['CreationTime', 'TransferCompletionTime']:
        if time_col in df_bits.columns:
            df_bits[time_col] = df_bits[time_col].apply(parse_dotnet_date)

    # Convert numeric enums to strings if needed
    if 'JobState' in df_bits.columns:
        df_bits['JobState'] = df_bits['JobState'].astype(str).apply(
            lambda x: job_state_map.get(x.strip(), x) if x.strip().isdigit() else x
        )
    if 'TransferType' in df_bits.columns:
        df_bits['TransferType'] = df_bits['TransferType'].astype(str).apply(
            lambda x: transfer_type_map.get(x.strip(), x) if x.strip().isdigit() else x
        )

    # Format bytes for display
    def format_bytes(b):
        try:
            b = int(float(b))
            if b >= 1024*1024*1024:
                return f"{b/(1024*1024*1024):.1f} GB"
            elif b >= 1024*1024:
                return f"{b/(1024*1024):.1f} MB"
            elif b >= 1024:
                return f"{b/1024:.1f} KB"
            return f"{b} B"
        except:
            return ""

    # Add formatted progress column if byte info available
    if 'BytesTransferred' in df_bits.columns and 'BytesTotal' in df_bits.columns:
        df_bits['Progress'] = df_bits.apply(
            lambda row: f"{format_bytes(row.get('BytesTransferred', 0))} / {format_bytes(row.get('BytesTotal', 0))}"
            if row.get('BytesTotal') else "", axis=1
        )

    # Dangerous file extensions for downloads
    dangerous_extensions = ['.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.hta', '.msi', '.scr']

    # Suspicious URL patterns
    suspicious_url_patterns = ['pastebin', 'githubusercontent', 'discord', 'telegram', 'ngrok', 'duckdns', 'no-ip']

    # Analyze each BITS job for risk
    def analyze_bits_job(row):
        files = str(row.get('Files', '') or row.get('LocalFiles', '') or '').lower()
        job_type = str(row.get('TransferType', '') or '').lower()
        job_state = str(row.get('JobState', '') or '').lower()

        risk_level = "✅ Normal"

        # Check for executable downloads
        if any(ext in files for ext in dangerous_extensions):
            risk_level = "🔴 Critical"
        # Check for suspicious URL patterns
        elif any(pattern in files for pattern in suspicious_url_patterns):
            risk_level = "🟠 Suspicious"
        # Check for suspicious paths
        elif any(p in files for p in ['temp', 'appdata', 'programdata', 'public']):
            risk_level = "🟡 Notable"
        # Download transfers
        elif 'download' in job_type:
            risk_level = "🟡 Notable"
        # Error states
        elif 'error' in job_state:
            risk_level = "🟡 Notable"

        return risk_level

    # Apply analysis
    df_bits['Risk'] = df_bits.apply(analyze_bits_job, axis=1)

    # Count suspicious jobs
    critical_count = len(df_bits[df_bits['Risk'].str.contains("🔴")])
    suspicious_count = len(df_bits[df_bits['Risk'].str.contains("🟠")])

    if critical_count > 0 or suspicious_count > 0:
        info_banner(f"{critical_count + suspicious_count} Suspicious BITS Job(s) Detected - BITS can be abused by attackers to download payloads or exfiltrate data stealthily.", "error")

    # Search and filter
    col_search, col_filter = st.columns([2, 1])

    with col_search:
        search_bits = st.text_input("🔍 Search BITS Jobs", placeholder="Search job name, URL, path...", key="bits_search")

    with col_filter:
        filter_bits = st.selectbox("Filter", ["All Jobs", "Suspicious Only", "Downloads Only"], key="bits_filter")

    # Apply search filter
    if search_bits:
        search_lower = search_bits.lower()
        mask = df_bits.astype(str).apply(lambda x: x.str.lower().str.contains(search_lower, na=False)).any(axis=1)
        df_bits = df_bits[mask]

    # Apply type filter - use actual collector field: TransferType
    if filter_bits == "Suspicious Only":
        df_bits = df_bits[df_bits['Risk'].str.contains("🔴|🟠", regex=True)]
    elif filter_bits == "Downloads Only":
        if 'TransferType' in df_bits.columns:
            df_bits = df_bits[df_bits['TransferType'].astype(str).str.lower().str.contains('download', na=False)]

    # Sort by risk
    risk_order = {"🔴": 0, "🟠": 1, "🟡": 2, "✅": 3}
    df_bits['_sort'] = df_bits['Risk'].apply(lambda x: min([risk_order.get(k, 4) for k in risk_order if k in x], default=4))
    df_bits = df_bits.sort_values('_sort').drop('_sort', axis=1)

    st.markdown(f'<div style="color:#888;font-size:0.8rem;margin:10px 0;">Showing {len(df_bits)} BITS jobs</div>', unsafe_allow_html=True)

    # Helper to format owner (extract from nested object and clean up)
    def format_owner(owner_data):
        if not owner_data:
            return "Unknown"

        # Handle nested object like {"Value": "DOMAIN\\user"}
        if isinstance(owner_data, dict):
            owner = str(owner_data.get('Value', '') or '')
        else:
            owner = str(owner_data)

        if not owner:
            return "Unknown"

        # Check if it's a SID (starts with S-1-)
        if owner.startswith('S-1-'):
            if owner.endswith('-500'):
                return "Administrator"
            elif owner.endswith('-501'):
                return "Guest"
            elif '-18' in owner:
                return "SYSTEM"
            elif '-19' in owner:
                return "LOCAL SERVICE"
            elif '-20' in owner:
                return "NETWORK SERVICE"
            else:
                return f"SID:...{owner[-12:]}"

        # If it contains backslash, extract just the username
        if '\\' in owner:
            return owner.split('\\')[-1]
        return owner

    # Prepare display columns
    display_cols = ['Risk']

    # Format OwnerAccount column before mapping
    if 'OwnerAccount' in df_bits.columns:
        df_bits['OwnerFormatted'] = df_bits['OwnerAccount'].apply(format_owner)

    # Map collector fields to display names
    col_mappings = {
        'Job Name': ['DisplayName'],
        'Owner': ['OwnerFormatted', 'OwnerAccount'],
        'State': ['JobState'],
        'Type': ['TransferType'],
        'Progress': ['Progress'],
        'Remote Files': ['Files'],
        'Local Files': ['LocalFiles'],
        'Created': ['CreationTime'],
        'Completed': ['TransferCompletionTime'],
    }

    for display_name, possible_cols in col_mappings.items():
        for col in possible_cols:
            if col in df_bits.columns:
                df_bits[display_name] = df_bits[col]
                display_cols.append(display_name)
                break

    # Data table
    st.dataframe(
        sanitize_dataframe(df_bits),
        column_order=[c for c in display_cols if c in df_bits.columns],
        width="stretch",
        height=400,
        column_config={
            "Risk": st.column_config.TextColumn("Risk", width="small"),
            "Job Name": st.column_config.TextColumn("Job Name", width="medium"),
            "Owner": st.column_config.TextColumn("Owner", width="small"),
            "State": st.column_config.TextColumn("State", width="small"),
            "Type": st.column_config.TextColumn("Type", width="small"),
            "Progress": st.column_config.TextColumn("Progress", width="small"),
            "Remote Files": st.column_config.TextColumn("Remote URL", width="large"),
            "Local Files": st.column_config.TextColumn("Local Path", width="medium"),
            "Created": st.column_config.TextColumn("Created", width="medium"),
            "Completed": st.column_config.TextColumn("Completed", width="medium"),
        },
        hide_index=True
    )

