"""
Browser Forensics Tab.
Displays browser history and cookies with comprehensive forensic analysis.
"""
import os
import streamlit as st
import pandas as pd
import re
from datetime import datetime
from urllib.parse import urlparse

from core.data_loader import load_json, sanitize_dataframe
from core.risk_engine import RiskEngine
from config.theme import THEME


# MITRE ATT&CK Techniques for Browser Forensics
MITRE_TECHNIQUES = {
    "T1217": {"name": "Browser Bookmark Discovery", "tactic": "Discovery", "url": "https://attack.mitre.org/techniques/T1217/"},
    "T1539": {"name": "Steal Web Session Cookie", "tactic": "Credential Access", "url": "https://attack.mitre.org/techniques/T1539/"},
    "T1185": {"name": "Browser Session Hijacking", "tactic": "Collection", "url": "https://attack.mitre.org/techniques/T1185/"},
    "T1189": {"name": "Drive-by Compromise", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1189/"},
    "T1566": {"name": "Phishing", "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1566/"},
    "T1204": {"name": "User Execution", "tactic": "Execution", "url": "https://attack.mitre.org/techniques/T1204/"},
}

# Suspicious URL patterns
SUSPICIOUS_URL_PATTERNS = {
    "credential_harvesting": {
        "patterns": [
            r"login.*\.(ru|cn|tk|ml|ga|cf|gq|xyz)$",
            r"secure.*bank.*\.(com|net|org)(?!/)",
            r"verify.*account",
            r"update.*payment",
            r"confirm.*identity",
            r"signin.*\.(ru|cn|tk)",
            r"password.*reset.*(?!microsoft|google|apple)",
        ],
        "risk": "critical",
        "mitre": "T1566"
    },
    "file_download": {
        "patterns": [
            r"\.(exe|msi|bat|cmd|ps1|vbs|js|jar|scr|pif)($|\?)",
            r"download.*\.(exe|zip|rar|7z)",
            r"drive\.google\.com.*download",
            r"dropbox\.com.*dl=1",
            r"mega\.nz",
            r"mediafire\.com",
            r"anonfiles\.",
            r"file\.io",
        ],
        "risk": "high",
        "mitre": "T1204"
    },
    "suspicious_hosting": {
        "patterns": [
            r"pastebin\.(com|pl)",
            r"paste\.ee",
            r"hastebin\.",
            r"ghostbin\.",
            r"rentry\.co",
            r"raw\.githubusercontent\.com",
            r"gist\.github\.com",
            r"transfer\.sh",
            r"catbox\.moe",
        ],
        "risk": "medium",
        "mitre": "T1102"
    },
    "c2_infrastructure": {
        "patterns": [
            r"ngrok\.io",
            r"serveo\.net",
            r"localhost\.run",
            r"portmap\.io",
            r"hopto\.org",
            r"ddns\.(net|org)",
            r"duckdns\.org",
            r"no-ip\.(com|org)",
        ],
        "risk": "critical",
        "mitre": "T1572"
    },
    "crypto_fraud": {
        "patterns": [
            r"crypto.*giveaway",
            r"bitcoin.*double",
            r"ethereum.*airdrop",
            r"wallet.*connect.*\.(ru|cn|tk)",
            r"metamask.*\.(ru|cn|tk)",
            r"uniswap.*\.(ru|cn|tk)",
        ],
        "risk": "high",
        "mitre": "T1566"
    },
    "admin_access": {
        "patterns": [
            r"/admin[/$?]",
            r"/wp-admin",
            r"/administrator",
            r"/phpmyadmin",
            r"/cpanel",
            r"/webmail",
            r"panel\.",
            r"control\.",
        ],
        "risk": "medium",
        "mitre": "T1217"
    },
    "tor_privacy": {
        "patterns": [
            r"\.onion",
            r"torproject\.org",
            r"duckduckgo.*onion",
            r"ahmia\.",
        ],
        "risk": "high",
        "mitre": "T1090"
    },
    "vpn_proxy": {
        "patterns": [
            r"whatismyip",
            r"whatismyipaddress",
            r"ipleak\.",
            r"browserleaks\.",
            r"dnsleaktest\.",
            r"hide\.me",
            r"hidemyass",
            r"protonvpn",
            r"nordvpn",
        ],
        "risk": "low",
        "mitre": "T1090"
    }
}

# Suspicious TLDs
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw', '.cc', '.su', '.ru', '.cn']

# Sensitive cookie names indicating authentication/session
SENSITIVE_COOKIE_PATTERNS = {
    "session": {
        "patterns": ["session", "sid", "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "connect.sid"],
        "risk": "high",
        "description": "Session identifier - can be used for session hijacking"
    },
    "authentication": {
        "patterns": ["auth", "token", "jwt", "bearer", "access_token", "refresh_token", "id_token"],
        "risk": "critical",
        "description": "Authentication token - enables account access"
    },
    "credentials": {
        "patterns": ["user", "login", "passwd", "password", "credential", "remember"],
        "risk": "critical",
        "description": "Credential data - may contain stored login info"
    },
    "oauth": {
        "patterns": ["oauth", "state", "nonce", "code_verifier"],
        "risk": "high",
        "description": "OAuth flow data - can enable token theft"
    },
    "tracking": {
        "patterns": ["_ga", "_gid", "fbp", "_fbp", "fr", "uuid", "visitor", "tracking"],
        "risk": "low",
        "description": "Tracking cookie - privacy concern"
    },
    "csrf": {
        "patterns": ["csrf", "xsrf", "_token", "authenticity"],
        "risk": "medium",
        "description": "CSRF token - security mechanism"
    }
}

# High-value domains for cookie theft
HIGH_VALUE_DOMAINS = [
    "google.com", "gmail.com", "facebook.com", "microsoft.com", "outlook.com",
    "office.com", "amazon.com", "apple.com", "icloud.com", "twitter.com",
    "linkedin.com", "github.com", "gitlab.com", "bitbucket.org", "slack.com",
    "discord.com", "paypal.com", "stripe.com", "chase.com", "bankofamerica.com",
    "wellsfargo.com", "dropbox.com", "box.com", "salesforce.com", "okta.com"
]


def analyze_url(url: str) -> dict:
    """Analyze a URL for suspicious patterns."""
    result = {
        "indicator": "🌐",
        "risk": "info",
        "category": "Normal",
        "findings": [],
        "mitre": []
    }

    if not url or pd.isna(url):
        return result

    url_lower = str(url).lower()

    # Check for suspicious patterns
    for category, data in SUSPICIOUS_URL_PATTERNS.items():
        for pattern in data["patterns"]:
            if re.search(pattern, url_lower):
                risk_level = data["risk"]
                if risk_level == "critical":
                    result["indicator"] = "🔴"
                    result["risk"] = "critical"
                elif risk_level == "high" and result["risk"] not in ["critical"]:
                    result["indicator"] = "🟠"
                    result["risk"] = "high"
                elif risk_level == "medium" and result["risk"] not in ["critical", "high"]:
                    result["indicator"] = "🟡"
                    result["risk"] = "medium"

                result["category"] = category.replace("_", " ").title()
                result["findings"].append(f"{category}: matched pattern")
                if data["mitre"] not in result["mitre"]:
                    result["mitre"].append(data["mitre"])
                break

    # Check TLD
    try:
        parsed = urlparse(url_lower if url_lower.startswith("http") else f"http://{url_lower}")
        domain = parsed.netloc or parsed.path.split('/')[0]
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                if result["risk"] not in ["critical"]:
                    result["indicator"] = "🟠"
                    result["risk"] = "high"
                result["findings"].append(f"Suspicious TLD: {tld}")
                break
    except:
        pass

    return result


def analyze_cookie(cookie_name: str, domain: str, value: str = None) -> dict:
    """Analyze a cookie for security implications."""
    result = {
        "indicator": "🍪",
        "risk": "info",
        "category": "Standard",
        "description": "Regular cookie",
        "mitre": []
    }

    if not cookie_name or pd.isna(cookie_name):
        return result

    name_lower = str(cookie_name).lower()
    domain_lower = str(domain).lower() if domain else ""

    # Check cookie type
    for ctype, data in SENSITIVE_COOKIE_PATTERNS.items():
        for pattern in data["patterns"]:
            if pattern.lower() in name_lower:
                risk_level = data["risk"]
                if risk_level == "critical":
                    result["indicator"] = "🔴"
                    result["risk"] = "critical"
                    result["mitre"] = ["T1539"]
                elif risk_level == "high":
                    result["indicator"] = "🟠"
                    result["risk"] = "high"
                    result["mitre"] = ["T1539"]
                elif risk_level == "medium":
                    result["indicator"] = "🟡"
                    result["risk"] = "medium"
                else:
                    result["indicator"] = "🔵"
                    result["risk"] = "low"

                result["category"] = ctype.title()
                result["description"] = data["description"]
                return result

    # Check high-value domain
    for hvd in HIGH_VALUE_DOMAINS:
        if hvd in domain_lower:
            if result["risk"] == "info":
                result["indicator"] = "⭐"
                result["risk"] = "medium"
                result["category"] = "High-Value Domain"
                result["description"] = f"Cookie from high-value domain: {hvd}"
                result["mitre"] = ["T1539"]
            break

    return result


@st.cache_data
def analyze_history_stats(_df_hash: str, df_records: list) -> dict:
    """Analyze browser history for statistics and suspicious items. Cached for performance."""
    df = pd.DataFrame(df_records) if df_records else pd.DataFrame()
    stats = {
        "total_urls": len(df),
        "unique_domains": 0,
        "browsers": [],
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "suspicious_urls": [],
        "download_urls": [],
        "admin_urls": []
    }

    if df.empty:
        return stats

    # Count unique domains
    if 'URL' in df.columns:
        domains = set()
        for url in df['URL'].dropna():
            try:
                parsed = urlparse(str(url) if str(url).startswith("http") else f"http://{url}")
                domain = parsed.netloc or parsed.path.split('/')[0]
                if domain:
                    domains.add(domain)
            except:
                pass
        stats["unique_domains"] = len(domains)

    # Count browsers
    if 'Browser' in df.columns:
        stats["browsers"] = df['Browser'].dropna().unique().tolist()

    # Analyze each URL
    for idx, row in df.iterrows():
        url = row.get('URL', '')
        analysis = analyze_url(url)

        if analysis["risk"] == "critical":
            stats["critical_count"] += 1
            stats["suspicious_urls"].append({
                "url": url,
                "category": analysis["category"],
                "mitre": analysis["mitre"],
                "browser": row.get('Browser', 'Unknown'),
                "time": row.get('Time', row.get('VisitTime', ''))
            })
        elif analysis["risk"] == "high":
            stats["high_count"] += 1
            if len(stats["suspicious_urls"]) < 20:
                stats["suspicious_urls"].append({
                    "url": url,
                    "category": analysis["category"],
                    "mitre": analysis["mitre"],
                    "browser": row.get('Browser', 'Unknown'),
                    "time": row.get('Time', row.get('VisitTime', ''))
                })
        elif analysis["risk"] == "medium":
            stats["medium_count"] += 1

        # Track file downloads
        if 'file_download' in analysis["category"].lower():
            stats["download_urls"].append({
                "url": url,
                "browser": row.get('Browser', 'Unknown'),
                "time": row.get('Time', row.get('VisitTime', ''))
            })

        # Track admin access
        if 'admin' in analysis["category"].lower():
            stats["admin_urls"].append({
                "url": url,
                "browser": row.get('Browser', 'Unknown'),
                "time": row.get('Time', row.get('VisitTime', ''))
            })

    return stats


@st.cache_data
def analyze_cookie_stats(_df_hash: str, df_records: list) -> dict:
    """Analyze cookies for statistics and sensitive items. Cached for performance."""
    df = pd.DataFrame(df_records) if df_records else pd.DataFrame()
    stats = {
        "total_cookies": len(df),
        "unique_domains": 0,
        "browsers": [],
        "critical_count": 0,
        "high_count": 0,
        "session_cookies": [],
        "auth_cookies": [],
        "high_value_cookies": []
    }

    if df.empty:
        return stats

    # Count unique domains
    if 'Host' in df.columns:
        stats["unique_domains"] = df['Host'].dropna().nunique()

    # Count browsers
    if 'Browser' in df.columns:
        stats["browsers"] = df['Browser'].dropna().unique().tolist()

    # Analyze each cookie
    for idx, row in df.iterrows():
        name = row.get('CookieName', row.get('Name', ''))
        domain = row.get('Host', row.get('Domain', ''))
        value = row.get('Value', '')

        analysis = analyze_cookie(name, domain, value)

        if analysis["risk"] == "critical":
            stats["critical_count"] += 1
            stats["auth_cookies"].append({
                "name": name,
                "domain": domain,
                "category": analysis["category"],
                "description": analysis["description"],
                "browser": row.get('Browser', 'Unknown')
            })
        elif analysis["risk"] == "high":
            stats["high_count"] += 1
            if analysis["category"] == "Session":
                stats["session_cookies"].append({
                    "name": name,
                    "domain": domain,
                    "browser": row.get('Browser', 'Unknown')
                })

        if analysis["category"] == "High-Value Domain":
            stats["high_value_cookies"].append({
                "name": name,
                "domain": domain,
                "browser": row.get('Browser', 'Unknown')
            })

    return stats


def render(evidence_folder: str, risk_engine: RiskEngine):
    """
    Render the Browser Forensics tab.

    Args:
        evidence_folder: Path to the evidence folder
        risk_engine: RiskEngine instance
    """
    # Load data for tab counts
    hist_data = load_json(evidence_folder, "browser_history.json") or []
    firefox_hist = load_json(evidence_folder, "firefox_history.json") or []
    all_history = hist_data + firefox_hist

    cookies_data = load_json(evidence_folder, "browser_cookies.json") or []
    firefox_cookies = load_json(evidence_folder, "firefox_cookies.json") or []
    all_cookies = cookies_data + firefox_cookies

    downloads_data = load_json(evidence_folder, "browser_downloads.json") or []

    cache_data = load_json(evidence_folder, "browser_cache_metadata.json") or {}
    cache_entries = cache_data.get("entries", [])
    cache_summary = cache_data.get("summary", {})

    # Simple header with blue styling
    st.markdown(f'<div style="color:#e6edf3;font-size:1.1rem;margin-bottom:15px;"><b>Browser</b> | History: {len(all_history)} | Cookies: {len(all_cookies)} | Downloads: {len(downloads_data)} | Cache: {cache_summary.get("total_entries", 0)}</div>', unsafe_allow_html=True)

    # Create subtabs
    tab_hist, tab_cook, tab_downloads, tab_cache, tab_analysis = st.tabs([
        f"History ({len(all_history)})",
        f"Cookies ({len(all_cookies)})",
        f"Downloads ({len(downloads_data)})",
        f"Cache ({cache_summary.get('total_entries', 0)})",
        "Analysis"
    ])

    # ==================== TAB 1: Browser History ====================
    with tab_hist:
        render_history_tab(all_history)

    # ==================== TAB 2: Cookies ====================
    with tab_cook:
        render_cookies_tab(all_cookies)

    # ==================== TAB 3: Downloads ====================
    with tab_downloads:
        render_downloads_tab(downloads_data)

    # ==================== TAB 4: Cache ====================
    with tab_cache:
        render_cache_tab(cache_entries, cache_summary)

    # ==================== TAB 5: Analysis ====================
    with tab_analysis:
        render_analysis_tab(evidence_folder)


def render_history_tab(hist_data):
    """Render the browser history subtab."""
    if not hist_data:
        st.info("No Browser History found.")
        return

    df_hist = pd.DataFrame(hist_data)
    original_count = len(df_hist)

    # Analyze statistics (cached using folder_name as hash)
    folder_name = st.session_state.get('current_evidence_folder', 'default')
    stats = analyze_history_stats(os.path.basename(folder_name) + "_hist", hist_data)

    # Stats - single line
    st.caption(f"URLs: {stats['total_urls']:,} | Domains: {stats['unique_domains']:,} | Critical: {stats['critical_count']} | High: {stats['high_count']}")

    # Filter Section
    col1, col2, col3 = st.columns([2, 1, 1])

    with col1:
        search_hist = st.text_input("🔍 Search URL / Title", placeholder="Enter keywords...", key="hist_search")

    with col2:
        if 'Browser' in df_hist.columns:
            browsers = ['All'] + df_hist['Browser'].dropna().unique().tolist()
            sel_browser = st.selectbox("Browser", browsers, key="hist_browser")
        else:
            sel_browser = 'All'

    with col3:
        risk_filter = st.selectbox("Risk Level", ['All', 'Critical', 'High', 'Medium', 'Info'], key="hist_risk")

    # Apply search filter
    if search_hist:
        mask = df_hist.astype(str).apply(
            lambda x: x.str.contains(search_hist, case=False, na=False)
        ).any(axis=1)
        df_hist = df_hist[mask]

    # Apply browser filter
    if sel_browser != 'All' and 'Browser' in df_hist.columns:
        df_hist = df_hist[df_hist['Browser'] == sel_browser]

    # Analyze and add risk column
    def analyze_row(row):
        analysis = analyze_url(row.get('URL', ''))
        return pd.Series({
            'Indicator': analysis['indicator'],
            'Risk': analysis['risk'],
            'Category': analysis['category']
        })

    analysis_df = df_hist.apply(analyze_row, axis=1)
    df_hist = pd.concat([analysis_df, df_hist], axis=1)

    # Apply risk filter
    if risk_filter != 'All':
        df_hist = df_hist[df_hist['Risk'] == risk_filter.lower()]

    # Suspicious URLs section - show as filtered table
    suspicious = df_hist[df_hist['Risk'].isin(['critical', 'high'])]

    # Reorder columns
    priority_cols = ['Indicator', 'Risk', 'Category']
    other_cols = [c for c in df_hist.columns if c not in priority_cols]
    df_display = df_hist[priority_cols + other_cols]

    st.dataframe(
        sanitize_dataframe(df_display),
        width="stretch",
        column_config={
            "Indicator": st.column_config.TextColumn("", width="small"),
            "Risk": st.column_config.TextColumn("Risk", width="small"),
            "Category": st.column_config.TextColumn("Category", width="medium"),
            "URL": st.column_config.LinkColumn("URL"),
            "Time": st.column_config.DatetimeColumn("Visit Time", format="D/M/Y H:mm:ss"),
            "VisitTime": st.column_config.DatetimeColumn("Visit Time", format="D/M/Y H:mm:ss")
        },
        hide_index=True
    )

    st.caption(f"Showing {len(df_display):,} of {original_count:,} | Risk: 🔴 Critical 🟠 High 🟡 Medium 🌐 Info")


def render_cookies_tab(cookies_data):
    """Render the cookies subtab."""
    if not cookies_data:
        st.info("No Cookies collected or decrypted yet.")
        return

    df_cook = pd.DataFrame(cookies_data)
    original_count = len(df_cook)

    # Check decryption status
    decrypted_count = 0
    encrypted_count = 0
    if 'Decrypted' in df_cook.columns:
        decrypted_count = df_cook['Decrypted'].sum()
        encrypted_count = len(df_cook) - decrypted_count

    # Convert time columns
    for col in ['Created', 'Expires', 'LastAccessed']:
        if col in df_cook.columns:
            df_cook[col] = pd.to_datetime(df_cook[col], errors='coerce')

    # Clean malformed values - handle encrypted indicator
    if 'Value' in df_cook.columns:
        def clean_value(x):
            x = str(x)
            if x.startswith('[Encrypted') or x.startswith('[Key') or x.startswith('[DPAPI'):
                return x  # Keep error messages as-is
            return x.encode('ascii', 'ignore').decode('ascii')[:100] + ('...' if len(x) > 100 else '')
        df_cook['Value'] = df_cook['Value'].apply(clean_value)

    # Analyze statistics (cached using folder_name as hash)
    folder_name = st.session_state.get('current_evidence_folder', 'default')
    stats = analyze_cookie_stats(os.path.basename(folder_name) + "_cook", cookies_data)

    # Stats - single line
    enc_text = f" | Encrypted: {encrypted_count}" if encrypted_count > 0 else ""
    st.caption(f"Cookies: {stats['total_cookies']:,} | Domains: {stats['unique_domains']:,} | Auth: {stats['critical_count']} | Session: {stats['high_count']}{enc_text}")

    # Filter Section
    col1, col2, col3 = st.columns([2, 1, 1])

    with col1:
        search_cookie = st.text_input("🔍 Search Name / Domain", placeholder="Enter keywords...", key="cook_search")

    with col2:
        if 'Browser' in df_cook.columns:
            browsers = ['All'] + df_cook['Browser'].dropna().unique().tolist()
            sel_browser = st.selectbox("Browser", browsers, key="cook_browser")
        else:
            sel_browser = 'All'

    with col3:
        cookie_type = st.selectbox("Cookie Type", ['All', 'Authentication', 'Session', 'Tracking', 'High-Value Domain'], key="cook_type")

    # Apply search filter
    if search_cookie:
        mask = df_cook.astype(str).apply(
            lambda x: x.str.contains(search_cookie, case=False, na=False)
        ).any(axis=1)
        df_cook = df_cook[mask]

    # Apply browser filter
    if sel_browser != 'All' and 'Browser' in df_cook.columns:
        df_cook = df_cook[df_cook['Browser'] == sel_browser]

    # Analyze and add columns
    def analyze_cookie_row(row):
        name = row.get('CookieName', row.get('Name', ''))
        domain = row.get('Host', row.get('Domain', ''))
        analysis = analyze_cookie(name, domain)
        return pd.Series({
            'Indicator': analysis['indicator'],
            'Risk': analysis['risk'],
            'Type': analysis['category']
        })

    analysis_df = df_cook.apply(analyze_cookie_row, axis=1)
    df_cook = pd.concat([analysis_df, df_cook], axis=1)

    # Apply type filter
    if cookie_type != 'All':
        df_cook = df_cook[df_cook['Type'].str.lower() == cookie_type.lower()]

    # Sensitive cookies section - show as filtered table
    sensitive = df_cook[df_cook['Risk'].isin(['critical', 'high'])]

    # Add decryption status indicator
    if 'Decrypted' in df_cook.columns:
        df_cook['Status'] = df_cook['Decrypted'].apply(lambda x: '✅' if x else '🔒')
    else:
        df_cook['Status'] = '✅'

    # Reorder columns for display
    priority_cols = ['Indicator', 'Risk', 'Type', 'Status']
    display_cols = ['Browser', 'User', 'Host', 'CookieName', 'Value', 'Created', 'Expires']
    existing = [c for c in display_cols if c in df_cook.columns]
    df_display = df_cook[[c for c in priority_cols if c in df_cook.columns] + existing]

    st.dataframe(
        sanitize_dataframe(df_display),
        width="stretch",
        column_config={
            "Indicator": st.column_config.TextColumn("", width="small"),
            "Risk": st.column_config.TextColumn("Risk", width="small"),
            "Type": st.column_config.TextColumn("Type", width="medium"),
            "Status": st.column_config.TextColumn("🔑", width="small", help="✅ = Decrypted, 🔒 = Encrypted"),
            "Created": st.column_config.DatetimeColumn("Created", format="D/M/Y H:mm:ss"),
            "Expires": st.column_config.DatetimeColumn("Expires", format="D/M/Y H:mm:ss"),
            "Value": st.column_config.TextColumn("Value (truncated)", width="large")
        },
        hide_index=True
    )

    st.caption(f"Showing {len(df_display):,} of {original_count:,} | Types: 🔴 Auth 🟠 Session 🟡 CSRF 🔵 Tracking 🍪 Standard")


def render_analysis_tab(evidence_folder: str):
    """Render the analysis and IOC extraction tab."""
    # Load both data sources
    hist_data = load_json(evidence_folder, "browser_history.json")
    cookies_data = load_json(evidence_folder, "browser_cookies.json")

    all_domains = set()
    suspicious_domains = set()
    iocs_urls = set()
    iocs_ips = set()

    if hist_data:
        df_hist = pd.DataFrame(hist_data)
        if 'URL' in df_hist.columns:
            for url in df_hist['URL'].dropna():
                url_str = str(url)
                try:
                    parsed = urlparse(url_str if url_str.startswith("http") else f"http://{url_str}")
                    domain = parsed.netloc or parsed.path.split('/')[0]
                    if domain:
                        all_domains.add(domain)
                        analysis = analyze_url(url_str)
                        if analysis["risk"] in ["critical", "high"]:
                            suspicious_domains.add(domain)
                            iocs_urls.add(url_str)
                except:
                    pass
                # Extract IPs
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', url_str)
                iocs_ips.update(ips)

    st.caption(f"Domains: {len(all_domains)} | Suspicious: {len(suspicious_domains)} | IPs: {len(iocs_ips)}")

    # Simple text areas for IOC export
    if suspicious_domains:
        st.text_area("Suspicious Domains", '\n'.join(sorted(suspicious_domains)), height=150)
    if iocs_ips:
        st.text_area("IP Addresses", '\n'.join(sorted(iocs_ips)), height=100)


def render_downloads_tab(downloads_data):
    """Render the browser downloads subtab."""


    if not downloads_data:
        st.info("No browser downloads collected.")
        return

    df = pd.DataFrame(downloads_data)
    original_count = len(df)

    # Dangerous file extensions
    dangerous_extensions = ['.exe', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.scr', '.pif', '.dll', '.hta']
    archive_extensions = ['.zip', '.rar', '.7z', '.tar', '.gz', '.iso', '.img']
    script_extensions = ['.ps1', '.vbs', '.js', '.bat', '.cmd', '.wsf', '.hta']

    # Risk analysis - handle collector field names: FilePath, URL
    def analyze_download_risk(row):
        # Handle both old and new field names
        filepath = str(row.get('FilePath', row.get('filename', row.get('target_path', '')))).lower()
        url = str(row.get('URL', row.get('url', row.get('tab_url', '')))).lower()
        danger_type = str(row.get('DangerType', '')).lower()

        # Check Chrome's own danger assessment first
        if 'dangerous' in danger_type:
            return "🔴 Flagged Dangerous"
        if 'unwanted' in danger_type:
            return "🟠 Potentially Unwanted"

        # Get file extension from filepath
        ext = ''
        if '.' in filepath:
            ext = '.' + filepath.rsplit('.', 1)[-1]

        # Check dangerous extensions
        if ext in dangerous_extensions:
            return "🔴 Executable"
        if ext in script_extensions:
            return "🔴 Script"

        # Check archives (could contain malware)
        if ext in archive_extensions:
            return "🟠 Archive"

        # Check suspicious URLs
        if any(p in url for p in ['temp', 'pastebin', 'anonfiles', 'mediafire', 'mega.nz', 'discord', 'raw.githubusercontent', 'cdn.discordapp']):
            return "🟠 Suspicious Source"

        # Check for IP-based URLs
        import re
        if re.search(r'https?://(?:\d{1,3}\.){3}\d{1,3}', url):
            return "🟡 IP-Based URL"

        return "✅ Normal"

    df['Risk'] = df.apply(analyze_download_risk, axis=1)

    # Extract filename from path for display - handle collector's FilePath field
    def get_filename(row):
        # Try collector field names first, then fallback
        filepath = row.get('FilePath', row.get('filename', row.get('target_path', '')))
        if filepath:
            # Handle both Windows and Unix paths, also file:// URIs
            filepath = str(filepath).replace('file:///', '').replace('file://', '')
            return filepath.split('\\')[-1].split('/')[-1]
        return 'Unknown'

    df['File'] = df.apply(get_filename, axis=1)

    # Extract domain from URL - handle collector's URL field
    def get_domain(url):
        if not url or pd.isna(url):
            return 'Unknown'
        try:
            url_str = str(url)
            parsed = urlparse(url_str if url_str.startswith("http") else f"http://{url_str}")
            return parsed.netloc or 'Unknown'
        except:
            return 'Unknown'

    # Use collector's URL field, fallback to others
    if 'URL' in df.columns:
        df['Domain'] = df['URL'].apply(get_domain)
    elif 'url' in df.columns:
        df['Domain'] = df['url'].apply(get_domain)
    elif 'tab_url' in df.columns:
        df['Domain'] = df['tab_url'].apply(get_domain)
    else:
        df['Domain'] = 'Unknown'

    # Format file size for display
    def format_size(row):
        total = row.get('TotalBytes', row.get('total_bytes', 0)) or 0
        received = row.get('ReceivedBytes', row.get('received_bytes', 0)) or 0
        try:
            total = int(total)
            received = int(received)
            if total >= 1024*1024:
                return f"{total/(1024*1024):.1f} MB"
            elif total >= 1024:
                return f"{total/1024:.1f} KB"
            elif total > 0:
                return f"{total} B"
            return ""
        except:
            return ""

    df['Size'] = df.apply(format_size, axis=1)

    # Stats
    total = len(df)
    executables = len(df[df['Risk'].str.contains("Executable|Script", regex=True)])
    suspicious = len(df[df['Risk'].str.contains("🔴|🟠", regex=True)])

    st.caption(f"Downloads: {total} | Executables: {executables} | Suspicious: {suspicious}")

    # Filter Section
    col1, col2, col3 = st.columns([2, 1, 1])

    with col1:
        search_dl = st.text_input("🔍 Search filename or URL", placeholder="Enter keywords...", key="dl_search")

    with col2:
        # Handle collector's Browser field (capitalized)
        browser_col = 'Browser' if 'Browser' in df.columns else 'browser' if 'browser' in df.columns else None
        if browser_col:
            browsers = ['All'] + df[browser_col].dropna().unique().tolist()
            sel_browser = st.selectbox("Browser", browsers, key="dl_browser")
        else:
            sel_browser = 'All'

    with col3:
        risk_filter = st.selectbox("Risk Level", ['All', 'Dangerous Only', 'Suspicious Only'], key="dl_risk")

    # Apply search filter
    if search_dl:
        mask = df.astype(str).apply(
            lambda x: x.str.contains(search_dl, case=False, na=False)
        ).any(axis=1)
        df = df[mask]

    # Apply browser filter
    if sel_browser != 'All' and browser_col:
        df = df[df[browser_col] == sel_browser]

    # Apply risk filter
    if risk_filter == 'Dangerous Only':
        df = df[df['Risk'].str.contains("🔴")]
    elif risk_filter == 'Suspicious Only':
        df = df[df['Risk'].str.contains("🔴|🟠", regex=True)]

    # Sort by risk
    risk_order = {"🔴": 0, "🟠": 1, "🟡": 2, "✅": 3}
    df['_sort'] = df['Risk'].apply(lambda x: min([risk_order.get(k, 4) for k in risk_order if k in x], default=4))
    df = df.sort_values('_sort').drop('_sort', axis=1)

    # Dangerous downloads - shown in the filtered table below
    dangerous = df[df['Risk'].str.contains("🔴")]

    st.caption(f"Showing {len(df)} of {original_count} downloads")

    # Create display-friendly columns - map collector fields to display names
    display_df = df.copy()

    # Standardize column names for display
    col_mapping = {
        'URL': 'Download URL',
        'FilePath': 'Full Path',
        'StartTime': 'Time',
        'Time': 'Time',
        'Browser': 'Browser',
        'User': 'User',
        'State': 'Status',
        'DangerType': 'Safety',
        'MimeType': 'Type',
        'Referrer': 'Referrer',
    }

    for old_col, new_col in col_mapping.items():
        if old_col in display_df.columns and new_col not in display_df.columns:
            display_df[new_col] = display_df[old_col]

    # Data table with correct column order - include new fields
    column_order = ["Risk", "File", "Size", "Domain", "Status", "Safety", "Browser", "User", "Time", "Download URL", "Referrer", "Full Path"]

    st.dataframe(
        sanitize_dataframe(display_df),
        column_order=[c for c in column_order if c in display_df.columns],
        width="stretch",
        height=400,
        column_config={
            "Risk": st.column_config.TextColumn("Risk", width="small"),
            "File": st.column_config.TextColumn("Filename", width="medium"),
            "Size": st.column_config.TextColumn("Size", width="small"),
            "Domain": st.column_config.TextColumn("Source", width="medium"),
            "Status": st.column_config.TextColumn("Status", width="small"),
            "Safety": st.column_config.TextColumn("Safety", width="small"),
            "Browser": st.column_config.TextColumn("Browser", width="small"),
            "User": st.column_config.TextColumn("User", width="small"),
            "Time": st.column_config.TextColumn("Time", width="medium"),
            "Download URL": st.column_config.LinkColumn("Download URL", width="large"),
            "Referrer": st.column_config.TextColumn("Referrer", width="medium"),
            "Full Path": st.column_config.TextColumn("Local Path", width="large")
        },
        hide_index=True
    )

    st.caption("Risk: 🔴 Executable/Script | 🟠 Archive/Suspicious | ✅ Normal")


def render_cache_tab(cache_entries, cache_summary):
    """Render the browser cache metadata subtab."""


    if not cache_entries and not cache_summary:
        st.info("No browser cache metadata collected. Run the collector to gather cache information.")
        return

    # Summary statistics
    total_entries = cache_summary.get('total_entries', 0)
    total_size = cache_summary.get('total_size_formatted', '0 MB')
    by_browser = cache_summary.get('by_browser', {})

    st.caption(f"Cache: {total_entries:,} entries | Size: {total_size} | Browsers: {len(by_browser)}")

    if not cache_entries:
        st.info("Cache entry details not available.")
        return

    df = pd.DataFrame(cache_entries)
    original_count = len(df)

    # Convert timestamps
    for col in ['Created', 'Modified', 'Accessed']:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors='coerce')

    # Format file size
    def format_size(size):
        try:
            size = int(size)
            if size >= 1024*1024:
                return f"{size/(1024*1024):.1f} MB"
            elif size >= 1024:
                return f"{size/1024:.1f} KB"
            return f"{size} B"
        except:
            return ""

    if 'Size' in df.columns:
        df['SizeFormatted'] = df['Size'].apply(format_size)

    # Filter Section
    col1, col2, col3 = st.columns([2, 1, 1])

    with col1:
        search_cache = st.text_input("🔍 Search filename", placeholder="Enter keywords...", key="cache_search")

    with col2:
        if 'Browser' in df.columns:
            browsers = ['All'] + df['Browser'].dropna().unique().tolist()
            sel_browser = st.selectbox("Browser", browsers, key="cache_browser")
        else:
            sel_browser = 'All'

    with col3:
        time_filter = st.selectbox("Time Filter", ['All', 'Last 24 Hours', 'Last 7 Days', 'Last 30 Days'], key="cache_time")

    # Apply filters
    if search_cache:
        mask = df['FileName'].str.contains(search_cache, case=False, na=False)
        df = df[mask]

    if sel_browser != 'All' and 'Browser' in df.columns:
        df = df[df['Browser'] == sel_browser]

    if time_filter != 'All' and 'Accessed' in df.columns:
        now = pd.Timestamp.now()
        if time_filter == 'Last 24 Hours':
            df = df[df['Accessed'] >= now - pd.Timedelta(days=1)]
        elif time_filter == 'Last 7 Days':
            df = df[df['Accessed'] >= now - pd.Timedelta(days=7)]
        elif time_filter == 'Last 30 Days':
            df = df[df['Accessed'] >= now - pd.Timedelta(days=30)]

    # Sort by most recent
    if 'Accessed' in df.columns:
        df = df.sort_values('Accessed', ascending=False)

    st.caption(f"Showing {len(df)} of {original_count} cache entries")

    # Data table
    display_cols = ['Browser', 'User', 'FileName', 'SizeFormatted', 'Accessed', 'Modified', 'CachePath']

    st.dataframe(
        sanitize_dataframe(df),
        column_order=[c for c in display_cols if c in df.columns],
        width="stretch",
        height=400,
        column_config={
            "Browser": st.column_config.TextColumn("Browser", width="small"),
            "User": st.column_config.TextColumn("User", width="small"),
            "FileName": st.column_config.TextColumn("Cache File", width="medium"),
            "SizeFormatted": st.column_config.TextColumn("Size", width="small"),
            "Accessed": st.column_config.DatetimeColumn("Last Accessed", format="D/M/Y H:mm"),
            "Modified": st.column_config.DatetimeColumn("Modified", format="D/M/Y H:mm"),
            "CachePath": st.column_config.TextColumn("Cache Path", width="medium")
        },
        hide_index=True
    )

