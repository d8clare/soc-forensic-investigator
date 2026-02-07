"""
Executive summary component with risk gauge, metrics, and top findings.
Clean, professional design for SOC Dashboard.
"""
from typing import List, Dict, Any

import streamlit as st

from config.theme import style_score_display, style_risk_badge, get_risk_color, THEME
from core.risk_engine import RiskEngine, Finding


class ExecutiveSummary:
    """
    Executive dashboard component showing risk overview and key metrics.
    """

    def __init__(self, risk_engine: RiskEngine):
        self.engine = risk_engine

    def render_hero_section(self):
        """Render the main risk assessment panel - clean and focused."""
        score = self.engine.get_global_score()
        color = get_risk_color(score)

        # Determine threat status
        if score >= 80:
            status_text, status_icon, status_desc = "CRITICAL THREAT", "🚨", "Immediate action required"
        elif score >= 60:
            status_text, status_icon, status_desc = "HIGH RISK", "⚠️", "Significant threats detected"
        elif score >= 30:
            status_text, status_icon, status_desc = "ELEVATED", "🔶", "Suspicious activity found"
        else:
            status_text, status_icon, status_desc = "LOW RISK", "✅", "No critical indicators"

        critical_count = len([f for f in self.engine.all_findings if f.severity == 'critical'])
        high_count = len([f for f in self.engine.all_findings if f.severity == 'high'])
        medium_count = len([f for f in self.engine.all_findings if f.severity == 'medium'])
        tech_count = len(self.engine.mitre_techniques)

        hero_html = f'''<div style="background:linear-gradient(135deg,#0d1117 0%,#161b22 50%,#21262d 100%);border-radius:12px;padding:24px;margin-bottom:20px;border:1px solid rgba(48,54,61,0.8);">
<div style="display:flex;align-items:center;gap:30px;flex-wrap:wrap;">
<div style="text-align:center;">
<div style="width:120px;height:120px;border-radius:50%;border:6px solid {color};display:flex;flex-direction:column;align-items:center;justify-content:center;background:rgba(0,0,0,0.3);box-shadow:0 0 25px {color}30;">
<span style="font-size:2.5rem;font-weight:700;color:{color};line-height:1;">{min(score,100)}</span>
<span style="color:#8b949e;font-size:0.7rem;text-transform:uppercase;letter-spacing:1px;">Risk Score</span>
</div>
</div>
<div style="flex:1;min-width:200px;">
<div style="font-size:1.5rem;font-weight:600;color:{color};margin-bottom:4px;">{status_icon} {status_text}</div>
<div style="color:#8b949e;font-size:0.9rem;margin-bottom:12px;">{status_desc}</div>
<div style="display:flex;gap:20px;flex-wrap:wrap;">
<div><span style="color:#ff6b6b;font-weight:700;font-size:1.2rem;">{critical_count}</span> <span style="color:#6e7681;font-size:0.8rem;">Critical</span></div>
<div><span style="color:#feca57;font-weight:700;font-size:1.2rem;">{high_count}</span> <span style="color:#6e7681;font-size:0.8rem;">High</span></div>
<div><span style="color:#48dbfb;font-weight:700;font-size:1.2rem;">{medium_count}</span> <span style="color:#6e7681;font-size:0.8rem;">Medium</span></div>
<div><span style="color:#1a73e8;font-weight:700;font-size:1.2rem;">{tech_count}</span> <span style="color:#6e7681;font-size:0.8rem;">MITRE Techniques</span></div>
</div>
</div>
</div>
</div>'''
        st.markdown(hero_html, unsafe_allow_html=True)

    def render_findings_panel(self, n: int = 5):
        """Render top findings in a clean, actionable panel."""
        findings = self.engine.get_top_findings(n)

        if not findings:
            st.markdown('''<div style="background:#0d1117;border:1px solid #238636;border-radius:8px;padding:20px;text-align:center;">
<div style="color:#3fb950;font-size:1.1rem;font-weight:600;">✓ No Critical Findings</div>
<div style="color:#8b949e;font-size:0.85rem;margin-top:4px;">No high-priority security issues detected</div>
</div>''', unsafe_allow_html=True)
            return

        st.markdown(f'''<div style="background:#0d1117;border-radius:8px;border:1px solid #30363d;overflow:hidden;">
<div style="background:#161b22;padding:12px 16px;border-bottom:1px solid #30363d;">
<span style="color:#c9d1d9;font-weight:600;font-size:0.9rem;">Priority Findings</span>
<span style="background:#f8514930;color:#f85149;padding:2px 6px;border-radius:10px;font-size:0.7rem;margin-left:8px;">{len(findings)}</span>
</div>''', unsafe_allow_html=True)

        for i, finding in enumerate(findings):
            sev_colors = {
                'critical': ('#f85149', '#f8514920'),
                'high': ('#d29922', '#d2992220'),
                'medium': ('#58a6ff', '#58a6ff20'),
                'low': ('#3fb950', '#3fb95020'),
            }
            color, bg = sev_colors.get(finding.severity, ('#8b949e', '#8b949e20'))

            border_style = "border-bottom:1px solid #21262d;" if i < len(findings) - 1 else ""

            mitre_html = ""
            if finding.mitre_techniques:
                for t in finding.mitre_techniques[:2]:
                    mitre_html += f'<span style="background:#388bfd20;color:#58a6ff;padding:2px 6px;border-radius:3px;font-size:0.7rem;margin-right:4px;">{t}</span>'

            desc = finding.description[:90] + '...' if len(finding.description) > 90 else finding.description
            st.markdown(f'''<div style="padding:12px 16px;{border_style}display:flex;align-items:center;gap:12px;">
<div style="background:{bg};color:{color};padding:4px 8px;border-radius:4px;font-weight:600;font-size:0.8rem;min-width:32px;text-align:center;">{finding.score}</div>
<div style="flex:1;min-width:0;">
<div style="color:#c9d1d9;font-weight:500;font-size:0.85rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{finding.category}</div>
<div style="color:#8b949e;font-size:0.75rem;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{desc}</div>
</div>
<div style="flex-shrink:0;">{mitre_html}</div>
</div>''', unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)

    def render_mitre_coverage(self):
        """Render MITRE ATT&CK techniques as compact tags with view button."""
        techniques = self.engine.mitre_techniques
        if not techniques:
            return

        tech_html = ""
        for tech in sorted(techniques)[:8]:  # Show first 8
            tech_html += f'<span style="background:#388bfd20;color:#58a6ff;padding:4px 8px;border-radius:4px;font-size:0.75rem;font-weight:500;display:inline-block;margin:2px;">{tech}</span>'

        if len(techniques) > 8:
            tech_html += f'<span style="color:#6e7681;font-size:0.75rem;padding:4px;">+{len(techniques) - 8} more</span>'

        st.markdown(f'''<div style="background:#0d1117;border-radius:8px;border:1px solid #30363d;overflow:hidden;">
<div style="background:#161b22;padding:10px 14px;border-bottom:1px solid #30363d;">
<span style="color:#c9d1d9;font-weight:600;font-size:0.85rem;">MITRE ATT&CK</span>
<span style="background:#388bfd30;color:#58a6ff;padding:2px 6px;border-radius:10px;font-size:0.7rem;margin-left:8px;">{len(techniques)}</span>
</div>
<div style="padding:12px;display:flex;flex-wrap:wrap;gap:4px;">{tech_html}</div>
</div>''', unsafe_allow_html=True)

        # Expander to view all techniques with MITRE links
        with st.expander("View All Techniques"):
            for tech in sorted(techniques):
                url = f"https://attack.mitre.org/techniques/{tech.replace('.', '/')}/"
                st.markdown(f"- [{tech}]({url})")

    def render_ioc_summary(self, iocs: Dict[str, List[str]], case_name: str = "case"):
        """Render IOC extraction summary with export button."""
        total_iocs = sum(len(v) for v in iocs.values())
        if total_iocs == 0:
            return

        ioc_config = {
            "IP Addresses": ("IPs", "#58a6ff"),
            "Domains": ("Domains", "#a371f7"),
            "Hashes": ("Hashes", "#3fb950"),
            "URLs": ("URLs", "#d29922"),
            "Email Addresses": ("Emails", "#f85149"),
        }

        items_html = ""
        for ioc_type, values in iocs.items():
            if values:
                label, color = ioc_config.get(ioc_type, ("Other", "#8b949e"))
                items_html += f'<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid #21262d;"><span style="color:#8b949e;font-size:0.8rem;">{label}</span><span style="color:{color};font-weight:600;font-size:0.85rem;">{len(values)}</span></div>'

        st.markdown(f'''<div style="background:#0d1117;border-radius:8px;border:1px solid #30363d;overflow:hidden;">
<div style="background:#161b22;padding:10px 14px;border-bottom:1px solid #30363d;">
<span style="color:#c9d1d9;font-weight:600;font-size:0.85rem;">Extracted IOCs</span>
<span style="background:#3fb95030;color:#3fb950;padding:2px 6px;border-radius:10px;font-size:0.7rem;margin-left:8px;">{total_iocs}</span>
</div>
<div style="padding:8px 14px;">{items_html}</div>
</div>''', unsafe_allow_html=True)

        # Small export button
        all_iocs = []
        for ioc_type, values in iocs.items():
            if values:
                all_iocs.append(f"=== {ioc_type} ===")
                all_iocs.extend(values)
                all_iocs.append("")
        st.download_button(
            f"Export IOCs ({total_iocs})",
            "\n".join(all_iocs),
            f"iocs_{case_name}.txt",
            "text/plain",
            key="dl_iocs",
            type="secondary"
        )

    def render_full(self, iocs: Dict[str, List[str]] = None, case_name: str = "case"):
        """Render the complete executive summary - clean and focused."""
        self.render_hero_section()
        self.render_findings_panel(5)

        st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)

        col1, col2 = st.columns(2)
        with col1:
            self.render_mitre_coverage()
        with col2:
            if iocs:
                self.render_ioc_summary(iocs, case_name)
