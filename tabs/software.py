"""
Software & DNS Analysis Tab - Professional Forensic Investigation View.
Displays installed applications and DNS cache with risk analysis.
"""
import datetime

import streamlit as st
import pandas as pd

from core.data_loader import load_json, sanitize_dataframe
from core.risk_engine import RiskEngine


# Suspicious software keywords for detection
SUSPICIOUS_SOFTWARE = {
    "remote_access": ['teamviewer', 'anydesk', 'ammyy', 'logmein', 'vnc', 'radmin', 'supremo', 'rustdesk', 'meshagent', 'screenconnect', 'splashtop'],
    "hacking_tools": ['mimikatz', 'nmap', 'wireshark', 'metasploit', 'cobalt', 'burp', 'hashcat', 'john', 'hydra', 'sqlmap', 'nikto', 'aircrack'],
    "crypto_mining": ['xmrig', 'nicehash', 'minergate', 'claymore', 'phoenixminer', 'nbminer', 'trex', 'gminer', 'lolminer'],
    "torrent": ['utorrent', 'bittorrent', 'qbittorrent', 'deluge', 'transmission', 'vuze', 'tixati'],
    "anonymizers": ['tor browser', 'protonvpn', 'nordvpn', 'expressvpn', 'mullvad', 'windscribe', 'psiphon', 'ultrasurf'],
    "data_exfil": ['megasync', 'rclone', 'winscp', 'filezilla', 'cyberduck', 'cobian']
}

# Trusted publishers
TRUSTED_PUBLISHERS = ['microsoft', 'adobe', 'google', 'intel', 'apple', 'dell', 'hp', 'nvidia', 'oracle', 'cisco', 'vmware', 'mozilla', 'realtek', 'logitech', 'samsung']

# Suspicious DNS indicators
SUSPICIOUS_TLDS = ['.ru', '.cn', '.tk', '.top', '.xyz', '.pw', '.cc', '.su', '.ws', '.click', '.link', '.gq', '.ml', '.ga', '.cf']
DNS_TUNNELING_KEYWORDS = ['dnscat', 'iodine', 'dns2tcp', 'dnsexfil', 'tunnel']


def render(evidence_folder: str, risk_engine: RiskEngine):
    """Render the Software & DNS tab."""

    # Load all data first for stats
    soft_data = load_json(evidence_folder, "installed_software.json")
    dns_data = load_json(evidence_folder, "dns_cache.json")

    # Analyze software for stats
    soft_stats = analyze_software_stats(soft_data) if soft_data else {}
    dns_stats = analyze_dns_stats(dns_data, risk_engine) if dns_data else {}

    total_software = len(soft_data) if soft_data else 0
    total_dns = len(dns_data) if dns_data else 0
    suspicious_software = soft_stats.get('suspicious', 0)
    unknown_publishers = soft_stats.get('unknown', 0)
    suspicious_dns = dns_stats.get('suspicious', 0)
    recent_installs = soft_stats.get('recent', 0)

    # Simple header
    st.markdown(f'<div style="color:#e6edf3;font-size:1.1rem;margin-bottom:15px;"><b>Software</b> | Apps: {total_software} | Suspicious: {suspicious_software} | Unknown: {unknown_publishers} | DNS: {total_dns}</div>', unsafe_allow_html=True)

    # Create subtabs
    app_dns_tabs = st.tabs([
        f"Applications ({total_software})",
        f"DNS Cache ({total_dns})"
    ])

    # Tab 1: Installed Applications
    with app_dns_tabs[0]:
        render_software_tab(soft_data)

    # Tab 2: DNS Cache Analysis
    with app_dns_tabs[1]:
        render_dns_tab(dns_data, risk_engine)

    # Export section
    st.markdown("---")
    col1, col2 = st.columns(2)

    with col1:
        if soft_data:
            df_export = pd.DataFrame(soft_data)
            st.download_button("📦 Export Software List", df_export.to_csv(index=False), "installed_software.csv", "text/csv", key="soft_export")
        else:
            st.button("📦 No Software Data", disabled=True, key="soft_export_disabled")

    with col2:
        if dns_data:
            df_export = pd.DataFrame(dns_data)
            st.download_button("🌐 Export DNS Cache", df_export.to_csv(index=False), "dns_cache.csv", "text/csv", key="dns_export")
        else:
            st.button("🌐 No DNS Data", disabled=True, key="dns_export_disabled")


def analyze_software_stats(soft_data):
    """Analyze software data for statistics."""
    stats = {'suspicious': 0, 'unknown': 0, 'trusted': 0, 'third_party': 0, 'recent': 0}

    limit = datetime.datetime.now() - datetime.timedelta(days=30)

    for soft in soft_data:
        name = str(soft.get('DisplayName', '')).lower()
        publisher = str(soft.get('Publisher', '')).lower()
        install_date = soft.get('InstallDate')

        # Check suspicious
        is_suspicious = False
        for category, keywords in SUSPICIOUS_SOFTWARE.items():
            if any(kw in name for kw in keywords):
                stats['suspicious'] += 1
                is_suspicious = True
                break

        # Check publisher reputation
        if not is_suspicious:
            if any(t in publisher for t in TRUSTED_PUBLISHERS):
                stats['trusted'] += 1
            elif not publisher or publisher == 'none' or publisher == '' or 'unknown' in publisher:
                stats['unknown'] += 1
            else:
                stats['third_party'] += 1

        # Check recent installs
        if install_date:
            try:
                if len(str(install_date)) == 8:
                    dt = datetime.datetime.strptime(str(install_date), '%Y%m%d')
                    if dt > limit:
                        stats['recent'] += 1
            except:
                pass

    return stats


def analyze_dns_stats(dns_data, risk_engine):
    """Analyze DNS data for statistics."""
    stats = {'suspicious': 0, 'normal': 0}

    for entry in dns_data:
        domain = str(entry.get('Entry', entry.get('Name', ''))).lower()
        risk = risk_engine.assess_dns(domain)

        if 'High' in str(risk) or 'Suspicious' in str(risk):
            stats['suspicious'] += 1
        else:
            # Additional checks
            if any(tld in domain for tld in SUSPICIOUS_TLDS):
                stats['suspicious'] += 1
            elif any(kw in domain for kw in DNS_TUNNELING_KEYWORDS):
                stats['suspicious'] += 1
            else:
                stats['normal'] += 1

    return stats


def render_software_tab(soft_data):
    """Render the Installed Applications subtab."""


    if not soft_data:
        st.info("No software list found.")
        return

    df_soft = pd.DataFrame(soft_data)

    # Search and filter row
    col_search, col_filter, col_time = st.columns([2, 1.5, 1.5])

    with col_search:
        search_soft = st.text_input("search_soft", placeholder="🔍 Search software...", key="soft_search", label_visibility="collapsed")

    with col_filter:
        rep_filter = st.selectbox("rep_filter", ["All Software", "Suspicious Only", "Unknown Publisher", "Third Party", "Trusted"], key="soft_rep_filter", label_visibility="collapsed")

    with col_time:
        time_filter = st.selectbox("time_filter", ["All Time", "Last 7 Days", "Last 30 Days", "Last 90 Days"], key="soft_time_filter", label_visibility="collapsed")

    # Analyze each software
    def analyze_software(row):
        name = str(row.get('DisplayName', '')).lower()
        publisher = str(row.get('Publisher', '')).lower()

        # Check suspicious categories
        for category, keywords in SUSPICIOUS_SOFTWARE.items():
            if any(kw in name for kw in keywords):
                category_labels = {
                    'remote_access': '🔴 Remote Access',
                    'hacking_tools': '🔴 Hacking Tool',
                    'crypto_mining': '🔴 Crypto Miner',
                    'torrent': '🟠 Torrent Client',
                    'anonymizers': '🟠 Anonymizer/VPN',
                    'data_exfil': '🟠 Data Transfer'
                }
                return category_labels.get(category, '🔴 Suspicious')

        # Publisher reputation
        if any(t in publisher for t in TRUSTED_PUBLISHERS):
            return "✅ Trusted"
        if not publisher or publisher == 'none' or publisher == '' or 'unknown' in publisher:
            return "⚠️ Unknown Publisher"
        return "📦 Third Party"

    df_soft['Status'] = df_soft.apply(analyze_software, axis=1)

    # Check for recent installs
    if 'InstallDate' in df_soft.columns:
        df_soft['InstallDate'] = pd.to_datetime(df_soft['InstallDate'], format='%Y%m%d', errors='coerce')

        def check_recency(install_date):
            if pd.isnull(install_date):
                return ""
            days_ago = (datetime.datetime.now() - install_date).days
            if days_ago <= 7:
                return "🆕 This Week"
            elif days_ago <= 30:
                return "📅 This Month"
            return ""

        df_soft['Recency'] = df_soft['InstallDate'].apply(check_recency)

    # Apply search filter
    if search_soft:
        search_lower = search_soft.lower()
        df_soft = df_soft[
            df_soft['DisplayName'].str.lower().str.contains(search_lower, na=False) |
            df_soft['Publisher'].str.lower().str.contains(search_lower, na=False)
        ]

    # Apply reputation filter
    if rep_filter == "Suspicious Only":
        df_soft = df_soft[df_soft['Status'].str.contains("🔴|🟠", regex=True)]
    elif rep_filter == "Unknown Publisher":
        df_soft = df_soft[df_soft['Status'].str.contains("⚠️")]
    elif rep_filter == "Third Party":
        df_soft = df_soft[df_soft['Status'].str.contains("📦")]
    elif rep_filter == "Trusted":
        df_soft = df_soft[df_soft['Status'].str.contains("✅")]

    # Apply time filter
    if time_filter != "All Time" and 'InstallDate' in df_soft.columns:
        now = datetime.datetime.now()
        if time_filter == "Last 7 Days":
            cutoff = now - datetime.timedelta(days=7)
        elif time_filter == "Last 30 Days":
            cutoff = now - datetime.timedelta(days=30)
        elif time_filter == "Last 90 Days":
            cutoff = now - datetime.timedelta(days=90)
        df_soft = df_soft[df_soft['InstallDate'] >= cutoff]

    # Sort by status (suspicious first)
    status_order = {"🔴": 0, "🟠": 1, "⚠️": 2, "📦": 3, "✅": 4}
    df_soft['_sort'] = df_soft['Status'].apply(lambda x: min([status_order.get(k, 5) for k in status_order if k in x], default=5))
    df_soft = df_soft.sort_values('_sort').drop('_sort', axis=1)

    st.markdown(f'<div style="color:#888;font-size:0.8rem;margin:10px 0;">Showing {len(df_soft)} applications</div>', unsafe_allow_html=True)

    # Data table
    column_order = ["Status", "DisplayName", "Publisher", "InstallDate", "Recency", "DisplayVersion"]

    st.dataframe(
        sanitize_dataframe(df_soft),
        column_order=[c for c in column_order if c in df_soft.columns],
        width="stretch",
        height=400,
        column_config={
            "Status": st.column_config.TextColumn("Status", width="small"),
            "DisplayName": st.column_config.TextColumn("Software Name", width="large"),
            "Publisher": st.column_config.TextColumn("Publisher", width="medium"),
            "InstallDate": st.column_config.DatetimeColumn("Install Date", format="D/M/Y"),
            "Recency": st.column_config.TextColumn("Alert", width="small"),
            "DisplayVersion": st.column_config.TextColumn("Version", width="small")
        },
        hide_index=True
    )



def render_dns_tab(dns_data, risk_engine):
    """Render the DNS Cache Analysis subtab."""


    if not dns_data:
        st.info("No DNS cache data found.")
        return

    df_dns = pd.DataFrame(dns_data)

    if df_dns.empty:
        st.info("DNS Cache is empty.")
        return

    # Rename columns for clarity
    column_mapping = {
        "Entry": "Domain",
        "Name": "Record Type",
        "Data": "Resolved Address"
    }
    df_dns = df_dns.rename(columns={k: v for k, v in column_mapping.items() if k in df_dns.columns})

    # Search and filter row
    col_search, col_filter = st.columns([3, 2])

    with col_search:
        search_dns = st.text_input("search_dns", placeholder="🔍 Search domain or IP...", key="dns_search", label_visibility="collapsed")

    with col_filter:
        risk_filter = st.selectbox("dns_risk_filter", ["All Entries", "Suspicious Only", "High Risk Only"], key="dns_risk_filter", label_visibility="collapsed")

    # Enhanced DNS risk analysis
    def analyze_dns_risk(row):
        domain = str(row.get('Domain', row.get('Record Name', ''))).lower()
        base_risk = risk_engine.assess_dns(domain)

        # Check suspicious TLDs
        has_suspicious_tld = any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)

        # Check for tunneling indicators
        has_tunneling = any(kw in domain for kw in DNS_TUNNELING_KEYWORDS)

        # Check for encoded/long subdomains (potential exfiltration)
        parts = domain.split('.')
        has_long_subdomain = any(len(part) > 40 for part in parts)
        has_many_subdomains = len(parts) > 5

        # Check for IP-like patterns in domain
        has_ip_pattern = any(part.isdigit() for part in parts[:-1]) if len(parts) > 1 else False

        if has_tunneling or has_long_subdomain:
            return "🔴 High Risk - Potential Tunneling"
        if 'High' in str(base_risk) or 'Critical' in str(base_risk):
            return "🔴 High Risk"
        if has_suspicious_tld:
            return "🟠 Suspicious TLD"
        if has_many_subdomains or has_ip_pattern:
            return "🟡 Unusual Pattern"
        if 'Suspicious' in str(base_risk) or 'Medium' in str(base_risk):
            return "🟡 Suspicious"
        return "✅ Normal"

    domain_col = 'Domain' if 'Domain' in df_dns.columns else 'Record Name' if 'Record Name' in df_dns.columns else None
    if domain_col:
        df_dns['Risk'] = df_dns.apply(analyze_dns_risk, axis=1)
    else:
        df_dns['Risk'] = "✅ Normal"

    # Apply search filter
    if search_dns:
        search_lower = search_dns.lower()
        mask = df_dns.astype(str).apply(lambda x: x.str.lower().str.contains(search_lower, na=False)).any(axis=1)
        df_dns = df_dns[mask]

    # Apply risk filter
    if risk_filter == "Suspicious Only":
        df_dns = df_dns[df_dns['Risk'].str.contains("🔴|🟠|🟡", regex=True)]
    elif risk_filter == "High Risk Only":
        df_dns = df_dns[df_dns['Risk'].str.contains("🔴")]

    # Sort by risk
    risk_order = {"🔴": 0, "🟠": 1, "🟡": 2, "✅": 3}
    df_dns['_sort'] = df_dns['Risk'].apply(lambda x: min([risk_order.get(k, 4) for k in risk_order if k in x], default=4))
    df_dns = df_dns.sort_values('_sort').drop('_sort', axis=1)

    st.markdown(f'<div style="color:#888;font-size:0.8rem;margin:10px 0;">Showing {len(df_dns)} DNS entries</div>', unsafe_allow_html=True)

    # Data table
    st.dataframe(
        sanitize_dataframe(df_dns),
        width="stretch",
        height=400,
        column_config={
            "Risk": st.column_config.TextColumn("Risk", width="medium"),
            "Domain": st.column_config.TextColumn("Domain", width="large"),
            "Record Name": st.column_config.TextColumn("Domain", width="large"),
            "Record Type": st.column_config.TextColumn("Type", width="small"),
            "Resolved Address": st.column_config.TextColumn("Resolved IP", width="medium")
        },
        hide_index=True
    )

