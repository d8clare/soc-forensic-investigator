"""
Export functionality for forensic reports (HTML/JSON).
"""
import json
import re
from datetime import datetime
from typing import List, Dict, Any, Set

import streamlit as st

from core.risk_engine import RiskEngine, Finding
from config.theme import THEME, get_risk_color


class ForensicExporter:
    """
    Export forensic investigation results to HTML and JSON formats.
    """

    def __init__(self, case_name: str, risk_engine: RiskEngine):
        """
        Initialize the exporter.

        Args:
            case_name: Name of the case/evidence folder
            risk_engine: RiskEngine with findings
        """
        self.case_name = case_name
        self.engine = risk_engine
        self.iocs: Dict[str, Set[str]] = {
            "IP Addresses": set(),
            "Domains": set(),
            "Hashes (SHA256)": set(),
            "URLs": set(),
            "Email Addresses": set()
        }

    def extract_iocs_from_data(
        self,
        processes: List[Dict] = None,
        network: List[Dict] = None,
        dns: List[Dict] = None,
        browser: List[Dict] = None,
        files: List[Dict] = None
    ):
        """
        Extract IOCs from various data sources.

        Args:
            processes: Process data
            network: Network connection data
            dns: DNS cache data
            browser: Browser history data
            files: File data with hashes
        """
        # Extract IPs from network connections
        if network:
            for conn in network:
                raddr = str(conn.get('raddr', ''))
                if ':' in raddr:
                    ip = raddr.split(':')[0]
                    if self._is_valid_ip(ip):
                        self.iocs["IP Addresses"].add(ip)

        # Extract domains from DNS
        if dns:
            for record in dns:
                domain = record.get('Entry') or record.get('Record Name', '')
                if domain and '.' in domain:
                    self.iocs["Domains"].add(domain)

        # Extract URLs and domains from browser history
        if browser:
            for entry in browser:
                url = entry.get('URL', '')
                if url:
                    self.iocs["URLs"].add(url)
                    # Extract domain from URL
                    domain = self._extract_domain(url)
                    if domain:
                        self.iocs["Domains"].add(domain)

        # Extract hashes from files and processes
        if files:
            for f in files:
                sha256 = f.get('sha256', '')
                if sha256 and len(str(sha256)) == 64:
                    self.iocs["Hashes (SHA256)"].add(sha256)

        if processes:
            for p in processes:
                sha256 = p.get('sha256', '')
                if sha256 and len(str(sha256)) == 64:
                    self.iocs["Hashes (SHA256)"].add(sha256)

    def _is_valid_ip(self, ip: str) -> bool:
        """Check if IP is valid and not local."""
        local_ips = ['0.0.0.0', '127.0.0.1', '::', 'localhost', '']
        if ip in local_ips:
            return False

        # Basic IPv4 check
        parts = ip.split('.')
        if len(parts) == 4:
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                return False

        return False

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            # Remove protocol
            if '://' in url:
                url = url.split('://')[1]

            # Get domain part
            domain = url.split('/')[0]

            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]

            return domain if '.' in domain else ''
        except Exception:
            return ''

    def get_iocs(self) -> Dict[str, List[str]]:
        """
        Get extracted IOCs as sorted lists.

        Returns:
            Dictionary of IOC types to sorted value lists
        """
        return {k: sorted(list(v)) for k, v in self.iocs.items() if v}

    def generate_html_report(self) -> str:
        """
        Generate a styled HTML forensic report.

        Returns:
            HTML string
        """
        score = self.engine.get_global_score()
        severity = self.engine.get_severity()
        findings = self.engine.get_top_findings(10)
        techniques = sorted(self.engine.mitre_techniques)
        iocs = self.get_iocs()

        score_color = get_risk_color(score)

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Forensic Report - {self.case_name}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2em;
        }}
        .header .meta {{
            opacity: 0.8;
            margin-top: 10px;
        }}
        .risk-score {{
            text-align: center;
            padding: 30px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        .risk-score .score {{
            font-size: 4em;
            font-weight: bold;
            color: {score_color};
        }}
        .risk-score .label {{
            color: #666;
            font-size: 1.2em;
        }}
        .severity-badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            background-color: {score_color};
            color: white;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .section {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .section h2 {{
            color: #1a1a2e;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }}
        .finding {{
            border-left: 4px solid {THEME.SEVERITY_DANGER};
            padding: 10px 15px;
            margin: 10px 0;
            background: #fafafa;
        }}
        .finding.critical {{ border-color: {THEME.SEVERITY_CRITICAL}; }}
        .finding.high {{ border-color: {THEME.SEVERITY_DANGER}; }}
        .finding.medium {{ border-color: {THEME.SEVERITY_WARNING}; }}
        .finding .score {{
            font-weight: bold;
            color: #666;
        }}
        .mitre-tags {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }}
        .mitre-tag {{
            background: #1a73e8;
            color: white;
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 0.9em;
        }}
        .ioc-section {{
            margin-top: 15px;
        }}
        .ioc-type {{
            font-weight: bold;
            color: #333;
            margin-top: 15px;
        }}
        .ioc-list {{
            font-family: monospace;
            background: #f5f5f5;
            padding: 10px;
            border-radius: 4px;
            max-height: 200px;
            overflow-y: auto;
        }}
        .footer {{
            text-align: center;
            color: #666;
            padding: 20px;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SOC Forensic Investigation Report</h1>
        <div class="meta">
            <strong>Case:</strong> {self.case_name}<br>
            <strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
            <strong>Tool:</strong> SOC Forensic Investigator Platform v2.0.0
        </div>
    </div>

    <div class="risk-score">
        <div class="score">{score}</div>
        <div class="label">Risk Score</div>
        <div style="margin-top: 10px;">
            <span class="severity-badge">{severity}</span>
        </div>
    </div>

    <div class="section">
        <h2>Key Findings ({len(findings)})</h2>
        {''.join([f'''
        <div class="finding {f.severity}">
            <span class="score">[{f.score}]</span>
            <strong>{f.category}</strong>: {f.description}
            {f'<br><small>MITRE: {", ".join(f.mitre_techniques)}</small>' if f.mitre_techniques else ''}
        </div>
        ''' for f in findings]) or '<p>No critical findings detected.</p>'}
    </div>

    <div class="section">
        <h2>MITRE ATT&CK Techniques ({len(techniques)})</h2>
        <div class="mitre-tags">
            {''.join([f'<span class="mitre-tag">{t}</span>' for t in techniques]) or '<p>No techniques detected.</p>'}
        </div>
    </div>

    <div class="section">
        <h2>Extracted IOCs</h2>
        {''.join([f'''
        <div class="ioc-section">
            <div class="ioc-type">{ioc_type} ({len(values)})</div>
            <div class="ioc-list">{chr(10).join(values)}</div>
        </div>
        ''' for ioc_type, values in iocs.items()]) or '<p>No IOCs extracted.</p>'}
    </div>

    <div class="footer">
        Generated by SOC Forensic Investigator Platform<br>
        This report contains confidential forensic data.
    </div>
</body>
</html>
"""
        return html

    def generate_json_report(self) -> str:
        """
        Generate a JSON forensic report.

        Returns:
            JSON string
        """
        report = {
            "metadata": {
                "case_name": self.case_name,
                "generated_at": datetime.now().isoformat(),
                "tool": "SOC Forensic Investigator Platform v2.0.0"
            },
            "risk_assessment": {
                "score": self.engine.get_global_score(),
                "severity": self.engine.get_severity(),
                "finding_count": len(self.engine.all_findings)
            },
            "findings": [
                {
                    "category": f.category,
                    "description": f.description,
                    "score": f.score,
                    "severity": f.severity,
                    "mitre_techniques": f.mitre_techniques,
                    "source": f.source
                }
                for f in self.engine.all_findings
            ],
            "mitre_techniques": sorted(self.engine.mitre_techniques),
            "iocs": self.get_iocs()
        }

        return json.dumps(report, indent=2)

    def render_export_buttons(self):
        """Render download buttons for HTML and JSON reports."""
        col1, col2 = st.columns(2)

        with col1:
            html_report = self.generate_html_report()
            st.download_button(
                label="Download HTML Report",
                data=html_report,
                file_name=f"forensic_report_{self.case_name}.html",
                mime="text/html"
            )

        with col2:
            json_report = self.generate_json_report()
            st.download_button(
                label="Download JSON Report",
                data=json_report,
                file_name=f"forensic_report_{self.case_name}.json",
                mime="application/json"
            )


def render_ioc_extraction(iocs: Dict[str, List[str]]):
    """
    Standalone function to render IOC extraction UI.

    Args:
        iocs: Dictionary of IOC types to value lists
    """
    st.subheader("Extracted IOCs")

    if not any(iocs.values()):
        st.info("No IOCs extracted from current evidence.")
        return

    tabs = st.tabs(list(iocs.keys()))

    for tab, (ioc_type, values) in zip(tabs, iocs.items()):
        with tab:
            if values:
                ioc_text = "\n".join(values)
                st.text_area(
                    f"{len(values)} {ioc_type} found",
                    ioc_text,
                    height=150,
                    key=f"ioc_{ioc_type}"
                )

                st.download_button(
                    label=f"Download {ioc_type}",
                    data=ioc_text,
                    file_name=f"iocs_{ioc_type.lower().replace(' ', '_')}.txt",
                    mime="text/plain",
                    key=f"dl_{ioc_type}"
                )
            else:
                st.info(f"No {ioc_type} found.")
