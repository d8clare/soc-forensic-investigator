"""
Unified risk scoring engine with MITRE ATT&CK integration.

Implements bounded, weighted scoring with:
- Category-based score caps to prevent unbounded accumulation
- Finding deduplication to avoid counting same issue multiple times
- Weighted normalization for reliable 0-100 scores
- Configurable thresholds via risk_rules.json
"""
import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set

import pandas as pd

# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """Represents a single security finding."""
    category: str
    description: str
    score: int
    severity: str
    mitre_techniques: List[str] = field(default_factory=list)
    source: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    confidence: str = "medium"  # high, medium, low
    whitelisted: bool = False
    whitelist_reason: str = ""
    original_score: int = 0  # Score before whitelist reduction

    def get_dedup_key(self) -> str:
        """Generate a unique key for deduplication."""
        # Use category + source + first 100 chars of description
        key_str = f"{self.category}|{self.source}|{self.description[:100]}"
        return hashlib.md5(key_str.encode()).hexdigest()


@dataclass
class RiskAssessment:
    """Aggregated risk assessment for a data source."""
    source: str
    total_score: int
    normalized_score: int  # 0-100
    severity: str
    findings: List[Finding] = field(default_factory=list)


class RiskEngine:
    """
    Unified risk scoring engine that applies configurable rules
    across all data sources with MITRE ATT&CK tagging.

    Features:
    - Bounded scoring with category caps
    - Finding deduplication
    - Weighted category scoring
    - Configurable severity thresholds
    """

    # Default scoring configuration
    DEFAULT_SCORING_CONFIG = {
        "max_global_score": 100,
        "category_weights": {
            "credential_access": 1.5,
            "ransomware": 1.5,
            "malicious_process": 1.3,
            "default": 1.0
        },
        "category_max_scores": {
            "credential_access": 30,
            "ransomware": 30,
            "malicious_process": 25,
            "default": 15
        },
        "severity_thresholds": {
            "critical": 70,
            "high": 50,
            "medium": 25,
            "low": 10
        },
        "deduplication": {"enabled": True}
    }

    def __init__(self, rules_path: Optional[str] = None, whitelist_path: Optional[str] = None):
        """
        Initialize the risk engine with rules.

        Args:
            rules_path: Path to risk_rules.json (optional, uses default if not provided)
            whitelist_path: Path to whitelist.json (optional)
        """
        self.rules = self._load_rules(rules_path)
        self.whitelist = self._load_whitelist(whitelist_path)
        self.scoring_config = self.rules.get('scoring_config', self.DEFAULT_SCORING_CONFIG)
        self.all_findings: List[Finding] = []
        self.mitre_techniques: Set[str] = set()
        self._finding_keys: Set[str] = set()  # For deduplication
        self._category_scores: Dict[str, int] = {}  # Track scores per category
        self._suppressed_findings: Set[str] = set()  # User-suppressed finding keys
        logger.info("RiskEngine initialized with %d rule categories, whitelist: %s",
                   len(self.rules), "loaded" if self.whitelist else "none")

    def _load_rules(self, rules_path: Optional[str]) -> Dict:
        """Load risk rules from JSON file."""
        if rules_path and os.path.exists(rules_path):
            with open(rules_path, 'r', encoding='utf-8') as f:
                return json.load(f)

        # Default rules if file not found
        return self._get_default_rules()

    def _load_whitelist(self, whitelist_path: Optional[str]) -> Dict:
        """Load whitelist configuration."""
        # Try explicit path first
        if whitelist_path and os.path.exists(whitelist_path):
            try:
                with open(whitelist_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning("Failed to load whitelist from %s: %s", whitelist_path, e)

        # Try default location
        default_path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                    'config', 'whitelist.json')
        if os.path.exists(default_path):
            try:
                with open(default_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning("Failed to load default whitelist: %s", e)

        return {}

    def _check_process_whitelist(self, name: str, parent: str, path: str, cmdline: str) -> tuple:
        """
        Check if a process matches whitelist patterns.

        Returns:
            Tuple of (is_whitelisted, reason, score_modifier)
        """
        if not self.whitelist:
            return False, "", 1.0

        proc_wl = self.whitelist.get('processes', {})
        name_lower = name.lower()
        parent_lower = parent.lower()
        path_lower = path.lower()
        cmdline_lower = cmdline.lower()

        # Check known good LOLBins
        for pattern in proc_wl.get('known_good_lolbins', {}).get('patterns', []):
            if pattern.get('process', '').lower() in name_lower:
                if pattern.get('parent', '').lower() in parent_lower:
                    # Check negative cmdline patterns
                    cmdline_not = pattern.get('cmdline_not', [])
                    if not any(neg.lower() in cmdline_lower for neg in cmdline_not):
                        return True, pattern.get('reason', 'Whitelisted LOLBin'), 0.2

        # Check known good encoded commands
        for pattern in proc_wl.get('known_good_encoded', {}).get('patterns', []):
            cmdline_contains = pattern.get('cmdline_contains', [])
            if any(p.lower() in cmdline_lower for p in cmdline_contains):
                if pattern.get('parent') and pattern['parent'].lower() in parent_lower:
                    return True, pattern.get('reason', 'Whitelisted encoded command'), 0.2
                if pattern.get('path') and pattern['path'].lower() in path_lower:
                    return True, pattern.get('reason', 'Whitelisted encoded command'), 0.2

        # Check system paths (with valid signature)
        system_paths = proc_wl.get('system_processes', {}).get('paths', [])
        for sys_path in system_paths:
            if sys_path.lower() in path_lower:
                return True, "System path", 0.5

        return False, "", 1.0

    def _check_network_whitelist(self, port: int, process: str, remote_ip: str) -> tuple:
        """
        Check if a network connection matches whitelist patterns.

        Returns:
            Tuple of (is_whitelisted, reason, score_modifier)
        """
        if not self.whitelist:
            return False, "", 1.0

        net_wl = self.whitelist.get('network', {})
        process_lower = process.lower()

        # Check known good ports for specific processes
        for pattern in net_wl.get('known_good_ports', {}).get('patterns', []):
            if pattern.get('port') == port:
                if pattern.get('process', '').lower() in process_lower:
                    return True, pattern.get('reason', 'Known good port/process'), 0.1

        # Check internal ranges (reduced score, not fully whitelisted)
        internal_ranges = net_wl.get('internal_ranges', {}).get('ranges', [])
        if self._is_internal_ip(remote_ip, internal_ranges):
            modifier = net_wl.get('internal_ranges', {}).get('score_modifier', 0.5)
            return False, "Internal network", modifier

        return False, "", 1.0

    def _is_internal_ip(self, ip: str, ranges: List[str]) -> bool:
        """Check if IP is in internal ranges."""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            octets = [int(p) for p in parts]

            # Quick check for common internal ranges
            if octets[0] == 10:
                return True
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return True
            if octets[0] == 192 and octets[1] == 168:
                return True
            if octets[0] == 127:
                return True
        except:
            pass
        return False

    def _check_dns_whitelist(self, domain: str) -> tuple:
        """
        Check if a DNS domain matches whitelist patterns.

        Returns:
            Tuple of (is_whitelisted, reason, score_modifier)
        """
        if not self.whitelist:
            return False, "", 1.0

        dns_wl = self.whitelist.get('dns', {})
        domain_lower = domain.lower()

        # Check known good domains
        known_good = dns_wl.get('known_good_domains', {}).get('patterns', [])
        for good_domain in known_good:
            if domain_lower.endswith(good_domain.lower()):
                return True, f"Known good domain ({good_domain})", 0.0

        # Check enterprise services
        enterprise = dns_wl.get('enterprise_services', {}).get('patterns', [])
        for ent_domain in enterprise:
            if domain_lower.endswith(ent_domain.lower()):
                return True, f"Enterprise service ({ent_domain})", 0.0

        return False, "", 1.0

    def _determine_confidence(self, match_type: str, evidence: Dict = None) -> str:
        """
        Determine confidence level for a finding.

        Args:
            match_type: Type of match (exact_tool, pattern, heuristic, behavioral)
            evidence: Optional evidence dictionary

        Returns:
            Confidence level: 'high', 'medium', 'low'
        """
        # Exact tool name matches = high confidence
        exact_tools = ['mimikatz', 'cobalt', 'metasploit', 'bloodhound', 'rubeus',
                       'lazagne', 'sharphound', 'covenant', 'sliver', 'havoc']
        if match_type == 'exact_tool':
            return 'high'

        # Behavioral patterns (multiple indicators) = high
        if match_type == 'behavioral':
            return 'high'

        # Specific API calls or event IDs = high
        if match_type == 'api_call' or match_type == 'event_id':
            return 'high'

        # Pattern matching = medium
        if match_type == 'pattern':
            return 'medium'

        # Heuristics (entropy, path analysis) = low
        if match_type == 'heuristic':
            return 'low'

        return 'medium'

    def suppress_finding(self, finding_key: str):
        """Add a finding to the suppression list (user-marked false positive)."""
        self._suppressed_findings.add(finding_key)

    def unsuppress_finding(self, finding_key: str):
        """Remove a finding from the suppression list."""
        self._suppressed_findings.discard(finding_key)

    def is_suppressed(self, finding: Finding) -> bool:
        """Check if a finding is suppressed."""
        return finding.get_dedup_key() in self._suppressed_findings

    def get_findings_not_suppressed(self) -> List[Finding]:
        """Get all findings that are not suppressed."""
        return [f for f in self.all_findings if not self.is_suppressed(f)]

    def _get_default_rules(self) -> Dict:
        """Return default risk detection rules."""
        return {
            "process_rules": {
                "malicious_keywords": {
                    "patterns": ["mimikatz", "ncat", "psexec", "cobalt", "metasploit"],
                    "score": 50,
                    "severity": "critical",
                    "mitre_techniques": ["T1003", "T1059"]
                },
                "encoded_commands": {
                    "patterns": ["-enc", "-encodedcommand", "frombase64"],
                    "score": 45,
                    "severity": "high",
                    "mitre_techniques": ["T1059.001", "T1027"]
                },
                "office_spawn_shell": {
                    "parent_patterns": ["winword", "excel", "outlook", "powerpnt"],
                    "child_patterns": ["cmd", "powershell", "wscript", "cscript"],
                    "score": 60,
                    "severity": "critical",
                    "mitre_techniques": ["T1566.001", "T1204.002"]
                }
            },
            "network_rules": {
                "suspicious_ports": {
                    "ports": [4444, 1337, 6667, 9001, 8888],
                    "score": 35,
                    "severity": "high",
                    "mitre_techniques": ["T1571"]
                }
            },
            "event_rules": {
                "log_clearing": {
                    "event_ids": [1102, 104],
                    "score": 50,
                    "severity": "critical",
                    "mitre_techniques": ["T1070.001"]
                },
                "user_creation": {
                    "event_ids": [4720],
                    "score": 25,
                    "severity": "medium",
                    "mitre_techniques": ["T1136.001"]
                }
            }
        }

    def _add_finding(self, finding: Finding) -> bool:
        """
        Add a finding with deduplication and category score tracking.

        Args:
            finding: The Finding to add

        Returns:
            True if finding was added, False if duplicate
        """
        # Check for deduplication
        dedup_config = self.scoring_config.get('deduplication', {})
        if dedup_config.get('enabled', True):
            dedup_key = finding.get_dedup_key()
            if dedup_key in self._finding_keys:
                logger.debug("Duplicate finding skipped: %s", finding.category)
                return False
            self._finding_keys.add(dedup_key)

        # Get category key (normalize to lowercase, replace spaces)
        category_key = finding.category.lower().replace(' ', '_').replace('-', '_')

        # Check category score cap
        category_max = self.scoring_config.get('category_max_scores', {})
        max_score = category_max.get(category_key, category_max.get('default', 15))
        current_category_score = self._category_scores.get(category_key, 0)

        if current_category_score >= max_score:
            logger.debug("Category %s at max score (%d), finding noted but not scored",
                        category_key, max_score)
            # Still add finding for visibility, but don't add to score
            finding_copy = Finding(
                category=finding.category,
                description=finding.description,
                score=0,  # Capped - no additional score
                severity=finding.severity,
                mitre_techniques=finding.mitre_techniques,
                source=finding.source,
                evidence=finding.evidence
            )
            self.all_findings.append(finding_copy)
            self.mitre_techniques.update(finding.mitre_techniques)
            return True

        # Apply category weight
        weights = self.scoring_config.get('category_weights', {})
        weight = weights.get(category_key, weights.get('default', 1.0))
        weighted_score = int(finding.score * weight)

        # Cap the score to not exceed category max
        remaining_capacity = max_score - current_category_score
        actual_score = min(weighted_score, remaining_capacity)

        # Update category tracking
        self._category_scores[category_key] = current_category_score + actual_score

        # Create finding with actual score
        scored_finding = Finding(
            category=finding.category,
            description=finding.description,
            score=actual_score,
            severity=finding.severity,
            mitre_techniques=finding.mitre_techniques,
            source=finding.source,
            evidence=finding.evidence
        )

        self.all_findings.append(scored_finding)
        self.mitre_techniques.update(finding.mitre_techniques)
        logger.debug("Finding added: %s (score: %d, weighted: %d, category total: %d/%d)",
                    finding.category, actual_score, weighted_score,
                    self._category_scores[category_key], max_score)
        return True

    def assess_process(self, row: pd.Series) -> int:
        """
        Assess risk for a single process.

        Args:
            row: DataFrame row containing process data

        Returns:
            Risk score for this process
        """
        score = 0

        # Original values for evidence
        name_orig = str(row.get('name', ''))
        parent_orig = str(row.get('parent_name', ''))
        path_orig = str(row.get('exe', ''))
        cmd_orig = str(row.get('cmdline', ''))
        pid = row.get('pid', '')

        # Lowercase for matching
        cmd = cmd_orig.lower()
        name = name_orig.lower()
        parent = parent_orig.lower()
        path = path_orig.lower()
        sig = row.get('SignatureStatus', 'Unknown')

        rules = self.rules.get('process_rules', {})

        # Check whitelist first
        is_wl, wl_reason, wl_modifier = self._check_process_whitelist(name, parent, path, cmd)

        # Check malicious keywords
        mal_rule = rules.get('malicious_keywords', {})
        for pattern in mal_rule.get('patterns', []):
            if pattern in cmd:
                base_score = mal_rule.get('score', 50)
                # Determine confidence - exact tool names = high
                exact_tools = ['mimikatz', 'cobalt', 'metasploit', 'bloodhound', 'rubeus', 'lazagne']
                confidence = 'high' if pattern in exact_tools else 'medium'

                # Apply whitelist modifier
                final_score = int(base_score * wl_modifier) if is_wl else base_score

                finding = Finding(
                    category="Malicious Process",
                    description=f"Detected malicious keyword '{pattern}' in command line",
                    score=final_score,
                    severity=mal_rule.get('severity', 'critical'),
                    mitre_techniques=mal_rule.get('mitre_techniques', []),
                    source="process",
                    evidence={"name": name_orig, "pid": pid, "path": path_orig, "cmdline": cmd_orig[:300]},
                    confidence=confidence,
                    whitelisted=is_wl,
                    whitelist_reason=wl_reason,
                    original_score=base_score
                )
                self._add_finding(finding)
                score += finding.score
                break

        # Check encoded commands
        enc_rule = rules.get('encoded_commands', {})
        for pattern in enc_rule.get('patterns', []):
            if pattern in cmd:
                base_score = enc_rule.get('score', 45)
                # Apply whitelist modifier - encoded commands from SCCM etc are common
                final_score = int(base_score * wl_modifier) if is_wl else base_score

                finding = Finding(
                    category="Encoded Command",
                    description=f"Detected encoded/obfuscated command execution",
                    score=final_score,
                    severity=enc_rule.get('severity', 'high') if not is_wl else 'low',
                    mitre_techniques=enc_rule.get('mitre_techniques', []),
                    source="process",
                    evidence={"name": name_orig, "pid": pid, "path": path_orig, "cmdline": cmd_orig[:300]},
                    confidence='medium',
                    whitelisted=is_wl,
                    whitelist_reason=wl_reason,
                    original_score=base_score
                )
                self._add_finding(finding)
                score += finding.score
                break

        # Check Office spawning shell
        spawn_rule = rules.get('office_spawn_shell', {})
        parent_patterns = spawn_rule.get('parent_patterns', [])
        child_patterns = spawn_rule.get('child_patterns', [])

        if any(p in parent for p in parent_patterns) and any(c in name for c in child_patterns):
            finding = Finding(
                category="Office Spawn Shell",
                description=f"Office application spawned shell process",
                score=spawn_rule.get('score', 60),
                severity=spawn_rule.get('severity', 'critical'),
                mitre_techniques=spawn_rule.get('mitre_techniques', []),
                source="process",
                evidence={"parent": parent_orig, "child": name_orig, "pid": pid, "cmdline": cmd_orig[:300]}
            )
            self._add_finding(finding)
            score += finding.score

        # Check unsigned binaries in system folders
        if sig != 'Valid':
            unsigned_rule = rules.get('unsigned_system_binaries', {})
            for pattern in unsigned_rule.get('path_patterns', ['system32', 'windows']):
                if pattern in path:
                    finding = Finding(
                        category="Unsigned Binary",
                        description=f"Unsigned binary running from system folder ({pattern})",
                        score=unsigned_rule.get('score', 40),
                        severity=unsigned_rule.get('severity', 'high'),
                        mitre_techniques=unsigned_rule.get('mitre_techniques', []),
                        source="process",
                        evidence={"name": name_orig, "pid": pid, "path": path_orig, "signature": sig}
                    )
                    self._add_finding(finding)
                    score += finding.score
                    break

        # Check credential access patterns
        cred_rule = rules.get('credential_access', {})
        for pattern in cred_rule.get('patterns', []):
            if pattern in cmd:
                finding = Finding(
                    category="Credential Access",
                    description=f"Credential dumping/access pattern detected: {pattern}",
                    score=cred_rule.get('score', 60),
                    severity=cred_rule.get('severity', 'critical'),
                    mitre_techniques=cred_rule.get('mitre_techniques', []),
                    source="process",
                    evidence={"name": name_orig, "pid": pid, "path": path_orig, "cmdline": cmd_orig[:300]}
                )
                self._add_finding(finding)
                score += finding.score
                break

        # Check AMSI bypass attempts
        amsi_rule = rules.get('amsi_bypass', {})
        for pattern in amsi_rule.get('patterns', []):
            if pattern in cmd:
                finding = Finding(
                    category="AMSI Bypass",
                    description=f"AMSI bypass attempt detected",
                    score=amsi_rule.get('score', 55),
                    severity=amsi_rule.get('severity', 'critical'),
                    mitre_techniques=amsi_rule.get('mitre_techniques', []),
                    source="process",
                    evidence={"name": name_orig, "pid": pid, "cmdline": cmd_orig[:300]}
                )
                self._add_finding(finding)
                score += finding.score
                break

        # Check Defender evasion
        defender_rule = rules.get('defender_evasion', {})
        for pattern in defender_rule.get('patterns', []):
            if pattern in cmd:
                finding = Finding(
                    category="Defender Evasion",
                    description=f"Windows Defender tampering detected",
                    score=defender_rule.get('score', 55),
                    severity=defender_rule.get('severity', 'critical'),
                    mitre_techniques=defender_rule.get('mitre_techniques', []),
                    source="process",
                    evidence={"name": name_orig, "pid": pid, "cmdline": cmd_orig[:300]}
                )
                self._add_finding(finding)
                score += finding.score
                break

        # Check ransomware indicators
        ransom_rule = rules.get('ransomware_indicators', {})
        for pattern in ransom_rule.get('patterns', []):
            if pattern in cmd:
                finding = Finding(
                    category="Ransomware Indicator",
                    description=f"Ransomware activity detected: {pattern}",
                    score=ransom_rule.get('score', 70),
                    severity=ransom_rule.get('severity', 'critical'),
                    mitre_techniques=ransom_rule.get('mitre_techniques', []),
                    source="process",
                    evidence={"name": name_orig, "pid": pid, "cmdline": cmd_orig[:300]}
                )
                self._add_finding(finding)
                score += finding.score
                break

        # Check lateral movement
        lateral_rule = rules.get('lateral_movement', {})
        for pattern in lateral_rule.get('patterns', []):
            if pattern in cmd:
                finding = Finding(
                    category="Lateral Movement",
                    description=f"Lateral movement technique detected: {pattern}",
                    score=lateral_rule.get('score', 50),
                    severity=lateral_rule.get('severity', 'high'),
                    mitre_techniques=lateral_rule.get('mitre_techniques', []),
                    source="process",
                    evidence={"name": name_orig, "pid": pid, "cmdline": cmd_orig[:300]}
                )
                self._add_finding(finding)
                score += finding.score
                break

        # Check discovery commands
        discovery_rule = rules.get('discovery_commands', {})
        for pattern in discovery_rule.get('patterns', []):
            if pattern in cmd:
                finding = Finding(
                    category="Discovery",
                    description=f"Reconnaissance/discovery command: {pattern}",
                    score=discovery_rule.get('score', 25),
                    severity=discovery_rule.get('severity', 'medium'),
                    mitre_techniques=discovery_rule.get('mitre_techniques', []),
                    source="process",
                    evidence={"name": name_orig, "pid": pid, "cmdline": cmd_orig[:300]}
                )
                self._add_finding(finding)
                score += finding.score
                break

        # Check UAC bypass
        uac_rule = rules.get('uac_bypass', {})
        for pattern in uac_rule.get('patterns', []):
            if pattern in cmd or pattern in path:
                finding = Finding(
                    category="UAC Bypass",
                    description=f"UAC bypass technique detected: {pattern}",
                    score=uac_rule.get('score', 50),
                    severity=uac_rule.get('severity', 'high'),
                    mitre_techniques=uac_rule.get('mitre_techniques', []),
                    source="process",
                    evidence={"name": name_orig, "pid": pid, "path": path_orig, "cmdline": cmd_orig[:300]}
                )
                self._add_finding(finding)
                score += finding.score
                break

        # Check anti-forensics activity
        af_finding = self.assess_anti_forensics(row, source_type="process")
        if af_finding:
            score += af_finding.score

        # Check Kerberos attacks
        kerb_finding = self.assess_kerberos_attack(row, source_type="process")
        if kerb_finding:
            score += kerb_finding.score

        # Check LOLBins usage
        lolbin_rule = rules.get('lolbins', {})
        for pattern in lolbin_rule.get('patterns', []):
            if pattern in name:
                base_score = lolbin_rule.get('score', 35)
                # LOLBins are very common false positives - apply whitelist heavily
                final_score = int(base_score * wl_modifier) if is_wl else base_score

                # Additional context: LOLBin from system path with valid parent = lower score
                if is_wl or ('system32' in path and parent in ['services.exe', 'svchost.exe', 'msiexec.exe']):
                    final_score = int(final_score * 0.3)
                    confidence = 'low'
                else:
                    confidence = 'medium'

                finding = Finding(
                    category="LOLBin Execution",
                    description=f"Living-off-the-Land Binary: {name_orig}",
                    score=final_score,
                    severity='low' if is_wl else lolbin_rule.get('severity', 'high'),
                    mitre_techniques=lolbin_rule.get('mitre_techniques', []),
                    source="process",
                    evidence={"name": name_orig, "pid": pid, "path": path_orig, "cmdline": cmd_orig[:300], "parent": parent_orig},
                    confidence=confidence,
                    whitelisted=is_wl,
                    whitelist_reason=wl_reason if is_wl else ("System path with valid parent" if final_score < base_score else ""),
                    original_score=base_score
                )
                self._add_finding(finding)
                score += finding.score
                break

        return score

    def assess_network(self, row: pd.Series) -> str:
        """
        Assess risk for a network connection.

        Args:
            row: DataFrame row containing network data

        Returns:
            Risk status string
        """
        addr = str(row.get('raddr', ''))
        local_addr = str(row.get('laddr', ''))
        pid = row.get('pid', '')
        status = row.get('status', '')
        rules = self.rules.get('network_rules', {})

        if ':' in addr:
            try:
                port = int(addr.split(':')[-1])
                remote_ip = addr.split(':')[0]

                evidence = {
                    "remote_addr": addr,
                    "remote_ip": remote_ip,
                    "remote_port": port,
                    "local_addr": local_addr,
                    "pid": pid,
                    "status": status
                }

                # Check whitelist first
                process_name = str(row.get('name', ''))
                is_wl, wl_reason, wl_modifier = self._check_network_whitelist(port, process_name, remote_ip)

                # Check suspicious ports (C2/backdoor)
                port_rule = rules.get('suspicious_ports', {})
                if port in port_rule.get('ports', []):
                    if is_wl:
                        return "Whitelisted"

                    base_score = port_rule.get('score', 35)
                    # Internal network = reduced score
                    final_score = int(base_score * wl_modifier)

                    finding = Finding(
                        category="Suspicious Port",
                        description=f"Connection to suspicious port {port} (possible C2/backdoor)",
                        score=final_score,
                        severity=port_rule.get('severity', 'high'),
                        mitre_techniques=port_rule.get('mitre_techniques', []),
                        source="network",
                        evidence=evidence,
                        confidence='medium',
                        original_score=base_score
                    )
                    self._add_finding(finding)
                    return "High Risk Port"

                # Check C2 framework ports
                c2_rule = rules.get('c2_framework_ports', {})
                if port in c2_rule.get('ports', []):
                    finding = Finding(
                        category="C2 Framework Port",
                        description=f"Connection to known C2 framework port {port}",
                        score=c2_rule.get('score', 40),
                        severity=c2_rule.get('severity', 'high'),
                        mitre_techniques=c2_rule.get('mitre_techniques', []),
                        source="network",
                        evidence=evidence
                    )
                    self._add_finding(finding)
                    return "C2 Framework Port"

                # Check Tor ports
                tor_rule = rules.get('tor_ports', {})
                if port in tor_rule.get('ports', []):
                    finding = Finding(
                        category="Tor Connection",
                        description=f"Connection to Tor network port {port}",
                        score=tor_rule.get('score', 45),
                        severity=tor_rule.get('severity', 'high'),
                        mitre_techniques=tor_rule.get('mitre_techniques', []),
                        source="network",
                        evidence=evidence
                    )
                    self._add_finding(finding)
                    return "Tor Connection"

                # Check IRC ports
                irc_rule = rules.get('irc_ports', {})
                if port in irc_rule.get('ports', []):
                    finding = Finding(
                        category="IRC Connection",
                        description=f"Connection to IRC port {port} (possible botnet C2)",
                        score=irc_rule.get('score', 35),
                        severity=irc_rule.get('severity', 'high'),
                        mitre_techniques=irc_rule.get('mitre_techniques', []),
                        source="network",
                        evidence=evidence
                    )
                    self._add_finding(finding)
                    return "IRC Connection"

                # Check WinRM ports
                winrm_rule = rules.get('winrm_connection', {})
                if port in winrm_rule.get('ports', []):
                    finding = Finding(
                        category="WinRM Connection",
                        description=f"WinRM remote management connection",
                        score=winrm_rule.get('score', 25),
                        severity=winrm_rule.get('severity', 'medium'),
                        mitre_techniques=winrm_rule.get('mitre_techniques', []),
                        source="network",
                        evidence=evidence
                    )
                    self._add_finding(finding)
                    return "WinRM Connection"

                # Check SMB ports
                smb_rule = rules.get('smb_connection', {})
                if port in smb_rule.get('ports', []):
                    return "SMB Connection"

                # Check RDP
                rdp_rule = rules.get('rdp_connection', {})
                if port in rdp_rule.get('ports', [3389]):
                    return "RDP Connection"

                # Check SSH
                ssh_rule = rules.get('ssh_connection', {})
                if port in ssh_rule.get('ports', [22]):
                    return "SSH Connection"

            except ValueError:
                pass

        return "Normal"

    def assess_event(self, event_id: int, event_details: Dict = None) -> Optional[Finding]:
        """
        Assess risk for an event log entry.

        Args:
            event_id: Windows Event ID
            event_details: Optional dictionary with full event details

        Returns:
            Finding if suspicious, None otherwise
        """
        rules = self.rules.get('event_rules', {})

        for rule_name, rule in rules.items():
            if event_id in rule.get('event_ids', []):
                # Build evidence from event details
                evidence = {"event_id": event_id}

                if event_details:
                    evidence["log_name"] = event_details.get('LogName', '')
                    evidence["time"] = str(event_details.get('Time', ''))
                    evidence["level"] = event_details.get('LevelDisplayName', '')

                    # Extract full message
                    msg = event_details.get('Message', '')
                    if msg:
                        evidence["message"] = str(msg)

                    # Provider/source
                    if 'ProviderName' in event_details:
                        evidence["provider"] = event_details.get('ProviderName', '')

                    # Additional event fields that might be useful
                    if 'UserId' in event_details:
                        evidence["user_id"] = str(event_details.get('UserId', ''))
                    if 'ProcessId' in event_details:
                        evidence["process_id"] = event_details.get('ProcessId', '')

                # Create descriptive message based on event type
                descriptions = {
                    1102: "Security log was cleared - possible anti-forensics activity",
                    104: "System log was cleared - possible anti-forensics activity",
                    4720: "New local user account was created",
                    4698: "Scheduled task was created - check for persistence",
                    7045: "New service was installed on the system",
                    1149: "RDP session connection detected",
                    4103: "PowerShell module logging - script execution detected",
                    4104: "PowerShell script block logging - script content captured",
                    4688: "New process was created",
                    4624: "Successful logon event",
                    4625: "Failed logon attempt",
                }

                description = descriptions.get(event_id, f"Detected Event ID {event_id}")

                finding = Finding(
                    category=rule_name.replace('_', ' ').title(),
                    description=description,
                    score=rule.get('score', 20),
                    severity=rule.get('severity', 'medium'),
                    mitre_techniques=rule.get('mitre_techniques', []),
                    source="event_log",
                    evidence=evidence
                )
                self._add_finding(finding)
                return finding

        return None

    def assess_file(self, row: pd.Series) -> tuple:
        """
        Assess risk for a file.

        Args:
            row: DataFrame row containing file data

        Returns:
            Tuple of (score, reasons list)
        """
        score = 0
        reasons = []

        # Original values for evidence
        fname_orig = str(row.get('filename', ''))
        path_orig = str(row.get('path', ''))
        sha256 = str(row.get('sha256', ''))
        size = row.get('size_mb', '')
        created = row.get('created', '')

        # Lowercase for matching
        fname = fname_orig.lower()
        path = path_orig.lower()

        rules = self.rules.get('file_rules', {})

        # Check executable extensions
        ext_rule = rules.get('executable_extensions', {})
        if any(fname.endswith(ext) for ext in ext_rule.get('patterns', [])):
            score += ext_rule.get('score', 40)
            reasons.append("Executable in User Space")

            finding = Finding(
                category="Executable File",
                description=f"Executable found in user folder",
                score=ext_rule.get('score', 40),
                severity=ext_rule.get('severity', 'high'),
                mitre_techniques=ext_rule.get('mitre_techniques', []),
                source="file",
                evidence={"filename": fname_orig, "path": path_orig, "sha256": sha256, "size_mb": size, "created": str(created)}
            )
            self._add_finding(finding)

        # Check double extensions - smart detection
        # Only flag when a harmless-looking extension is followed by a dangerous one
        # Example: document.pdf.exe (malicious) vs report.final.docx (legitimate)
        dbl_rule = rules.get('double_extensions', {})

        # Decoy extensions - look harmless to users
        decoy_extensions = {
            # Documents
            'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'rtf', 'odt', 'ods', 'odp',
            # Images
            'jpg', 'jpeg', 'png', 'gif', 'bmp', 'ico', 'tif', 'tiff', 'svg', 'webp',
            # Audio/Video
            'mp3', 'mp4', 'wav', 'avi', 'mov', 'mkv', 'flv', 'wmv', 'wma', 'm4a',
            # Text/Data
            'txt', 'csv', 'xml', 'json', 'html', 'htm', 'log',
            # Archives (sometimes used as decoys)
            'zip', 'rar', '7z', 'tar', 'gz',
        }

        # Dangerous extensions - can execute code
        dangerous_extensions = {
            # Executables
            'exe', 'scr', 'pif', 'com', 'msi', 'msp', 'dll', 'sys', 'drv',
            # Scripts
            'bat', 'cmd', 'ps1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'hta',
            # Other dangerous
            'lnk', 'inf', 'reg', 'jar', 'cpl', 'gadget',
        }

        # Extract all extensions from filename (e.g., "doc.pdf.exe" -> ["doc", "pdf", "exe"])
        parts = fname.split('.')
        if len(parts) >= 3:  # Need at least: name.ext1.ext2
            # Get last two extensions
            second_to_last = parts[-2].lower()
            last_ext = parts[-1].lower()

            # Check if it's a [decoy].[dangerous] pattern - classic masquerading attack
            if second_to_last in decoy_extensions and last_ext in dangerous_extensions:
                score += dbl_rule.get('score', 55)
                reasons.append(f"Double Extension Masquerading (.{second_to_last}.{last_ext})")

                finding = Finding(
                    category="Double Extension",
                    description=f"Malicious double extension: appears as .{second_to_last} but executes as .{last_ext}",
                    score=dbl_rule.get('score', 55),
                    severity=dbl_rule.get('severity', 'critical'),
                    mitre_techniques=dbl_rule.get('mitre_techniques', ['T1036.007']),
                    source="file",
                    evidence={"filename": fname_orig, "path": path_orig, "sha256": sha256,
                              "decoy_ext": second_to_last, "real_ext": last_ext}
                )
                self._add_finding(finding)

            # Check if it's a [dangerous].[harmless] pattern - potentially renamed malware
            elif second_to_last in dangerous_extensions and last_ext in decoy_extensions:
                renamed_score = dbl_rule.get('renamed_score', 40)
                score += renamed_score
                reasons.append(f"Potentially Renamed Executable (.{second_to_last}.{last_ext})")

                finding = Finding(
                    category="Renamed Executable",
                    description=f"Potentially renamed malware: .{second_to_last} file disguised as .{last_ext}",
                    score=renamed_score,
                    severity="high",
                    mitre_techniques=["T1036.008"],  # Masquerading: Masquerade File Type
                    source="file",
                    evidence={"filename": fname_orig, "path": path_orig, "sha256": sha256,
                              "original_ext": second_to_last, "renamed_to": last_ext}
                )
                self._add_finding(finding)

        # Check temp locations
        temp_rule = rules.get('temp_locations', {})
        for pattern in temp_rule.get('patterns', []):
            if pattern in path:
                score += temp_rule.get('score', 25)
                reasons.append("Located in Temp Folder")
                break

        return score, reasons

    def assess_dns(self, name: str) -> str:
        """
        Assess risk for a DNS record.

        Args:
            name: DNS record name

        Returns:
            Risk status string
        """
        name_lower = name.lower()
        rules = self.rules.get('dns_rules', {})

        # Check crypto mining pools first (high priority)
        mining_rule = rules.get('crypto_mining_pools', {})
        for pattern in mining_rule.get('patterns', []):
            if pattern in name_lower:
                finding = Finding(
                    category="Crypto Mining",
                    description=f"Connection to cryptocurrency mining pool: {name}",
                    score=mining_rule.get('score', 45),
                    severity=mining_rule.get('severity', 'high'),
                    mitre_techniques=mining_rule.get('mitre_techniques', []),
                    source="dns",
                    evidence={"domain": name}
                )
                self._add_finding(finding)
                return "Crypto Mining Pool"

        # Check known malware domains
        malware_rule = rules.get('known_malware_domains', {})
        for pattern in malware_rule.get('patterns', []):
            if pattern in name_lower:
                finding = Finding(
                    category="Suspicious Domain",
                    description=f"Domain contains malware-related keyword: {name}",
                    score=malware_rule.get('score', 50),
                    severity=malware_rule.get('severity', 'critical'),
                    mitre_techniques=malware_rule.get('mitre_techniques', []),
                    source="dns",
                    evidence={"domain": name}
                )
                self._add_finding(finding)
                return "Malware Domain"

        # Check tunneling keywords
        tunnel_rule = rules.get('tunneling_keywords', {})
        for keyword in tunnel_rule.get('patterns', []):
            if keyword in name_lower:
                finding = Finding(
                    category="Tunneling Indicator",
                    description=f"Possible tunneling/proxy/dynamic DNS: {name}",
                    score=tunnel_rule.get('score', 40),
                    severity=tunnel_rule.get('severity', 'high'),
                    mitre_techniques=tunnel_rule.get('mitre_techniques', []),
                    source="dns",
                    evidence={"domain": name}
                )
                self._add_finding(finding)
                return "Tunneling/DDNS"

        # Check file sharing services
        fileshare_rule = rules.get('file_sharing_services', {})
        for pattern in fileshare_rule.get('patterns', []):
            if pattern in name_lower:
                finding = Finding(
                    category="File Sharing",
                    description=f"Connection to file sharing service: {name}",
                    score=fileshare_rule.get('score', 30),
                    severity=fileshare_rule.get('severity', 'medium'),
                    mitre_techniques=fileshare_rule.get('mitre_techniques', []),
                    source="dns",
                    evidence={"domain": name}
                )
                self._add_finding(finding)
                return "File Sharing Service"

        # Check C2 infrastructure (cloud services)
        c2_rule = rules.get('c2_infrastructure', {})
        for pattern in c2_rule.get('patterns', []):
            if pattern in name_lower:
                # Don't flag as finding, just return status (too many false positives)
                return "Cloud Service"

        # Check suspicious TLDs
        tld_rule = rules.get('suspicious_tlds', {})
        for tld in tld_rule.get('patterns', []):
            if name_lower.endswith(tld):
                finding = Finding(
                    category="Suspicious TLD",
                    description=f"DNS query to suspicious TLD: {name}",
                    score=tld_rule.get('score', 30),
                    severity=tld_rule.get('severity', 'medium'),
                    mitre_techniques=tld_rule.get('mitre_techniques', []),
                    source="dns",
                    evidence={"domain": name}
                )
                self._add_finding(finding)
                return "Suspicious TLD"

        # Check for DGA-like domains (high entropy, long random strings)
        dga_rule = rules.get('dga_indicators', {})
        domain_parts = name_lower.split('.')
        if len(domain_parts) >= 2:
            main_domain = domain_parts[-2]  # e.g., "example" from "sub.example.com"
            min_length = dga_rule.get('min_length', 25)
            entropy_threshold = dga_rule.get('entropy_threshold', 3.5)

            if len(main_domain) >= min_length:
                # Calculate entropy
                entropy = self._calculate_entropy(main_domain)
                if entropy >= entropy_threshold:
                    finding = Finding(
                        category="DGA Domain",
                        description=f"Possible DGA domain (high entropy): {name}",
                        score=dga_rule.get('score', 35),
                        severity=dga_rule.get('severity', 'high'),
                        mitre_techniques=dga_rule.get('mitre_techniques', []),
                        source="dns",
                        evidence={"domain": name, "entropy": round(entropy, 2), "length": len(main_domain)}
                    )
                    self._add_finding(finding)
                    return "Possible DGA"

        return "Normal"

    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string."""
        import math
        if not string:
            return 0.0
        prob = [float(string.count(c)) / len(string) for c in set(string)]
        return -sum(p * math.log2(p) for p in prob if p > 0)

    def assess_registry(self, row: pd.Series) -> str:
        """
        Assess risk for a registry autorun entry.

        Args:
            row: DataFrame row containing registry data

        Returns:
            Risk status string
        """
        val = str(row.get('Value', '')).lower()
        key = str(row.get('Key', '') or row.get('Path', '')).lower()
        name = str(row.get('Name', '')).lower()
        rules = self.rules.get('registry_rules', {})

        # Check for accessibility feature hijacking (sticky keys backdoor)
        access_rule = rules.get('accessibility_features', {})
        for pattern in access_rule.get('patterns', []):
            if pattern in val or pattern in key:
                finding = Finding(
                    category="Accessibility Backdoor",
                    description=f"Accessibility feature hijacking detected: {pattern}",
                    score=access_rule.get('score', 55),
                    severity=access_rule.get('severity', 'critical'),
                    mitre_techniques=access_rule.get('mitre_techniques', []),
                    source="registry",
                    evidence={"key": key[:200], "value": val[:200]}
                )
                self._add_finding(finding)
                return "Critical: Accessibility Backdoor"

        # Check for Image File Execution Options (debugger persistence)
        ifeo_rule = rules.get('image_file_execution_options', {})
        for pattern in ifeo_rule.get('key_patterns', []):
            if pattern in key and 'debugger' in name:
                finding = Finding(
                    category="IFEO Persistence",
                    description=f"Image File Execution Options debugger persistence",
                    score=ifeo_rule.get('score', 50),
                    severity=ifeo_rule.get('severity', 'critical'),
                    mitre_techniques=ifeo_rule.get('mitre_techniques', []),
                    source="registry",
                    evidence={"key": key[:200], "value": val[:200]}
                )
                self._add_finding(finding)
                return "Critical: IFEO Persistence"

        # Check for AppInit_DLLs
        appinit_rule = rules.get('appinit_dlls', {})
        for pattern in appinit_rule.get('key_patterns', []):
            if pattern in key or pattern in name:
                if val and val not in ['', '(empty)', 'none']:
                    finding = Finding(
                        category="AppInit DLL",
                        description=f"AppInit_DLLs injection detected",
                        score=appinit_rule.get('score', 50),
                        severity=appinit_rule.get('severity', 'critical'),
                        mitre_techniques=appinit_rule.get('mitre_techniques', []),
                        source="registry",
                        evidence={"key": key[:200], "value": val[:200]}
                    )
                    self._add_finding(finding)
                    return "Critical: AppInit DLL"

        # Check for Winlogon persistence
        winlogon_rule = rules.get('winlogon_persistence', {})
        for pattern in winlogon_rule.get('key_patterns', []):
            if pattern in key:
                # Check if value is modified from default
                if val and 'userinit.exe' not in val and 'explorer.exe' not in val:
                    finding = Finding(
                        category="Winlogon Persistence",
                        description=f"Modified Winlogon entry detected",
                        score=winlogon_rule.get('score', 50),
                        severity=winlogon_rule.get('severity', 'critical'),
                        mitre_techniques=winlogon_rule.get('mitre_techniques', []),
                        source="registry",
                        evidence={"key": key[:200], "value": val[:200]}
                    )
                    self._add_finding(finding)
                    return "Critical: Winlogon Persistence"

        # Check script commands
        script_rule = rules.get('script_commands', {})
        for pattern in script_rule.get('patterns', []):
            if pattern in val:
                finding = Finding(
                    category="Suspicious Registry",
                    description=f"Registry persistence with script/URL: {val[:100]}",
                    score=script_rule.get('score', 45),
                    severity=script_rule.get('severity', 'high'),
                    mitre_techniques=script_rule.get('mitre_techniques', []),
                    source="registry",
                    evidence={"key": key[:200], "value": val[:200]}
                )
                self._add_finding(finding)
                return "High Risk (Script/URL)"

        # Check suspicious paths
        path_rule = rules.get('suspicious_paths', {})
        for pattern in path_rule.get('patterns', []):
            if pattern in val:
                return "Suspicious Path"

        return "Normal"

    def assess_service(self, row: pd.Series) -> str:
        """
        Assess risk for a Windows service.

        Args:
            row: DataFrame row containing service data

        Returns:
            Risk status string
        """
        path = str(row.get('BinPath', '')).lower()
        status = str(row.get('Status', '')).lower()
        rules = self.rules.get('service_rules', {})

        # Check user-space paths
        path_rule = rules.get('user_space_path', {})
        for pattern in path_rule.get('patterns', []):
            if pattern in path:
                if 'temp' in path and status == 'running':
                    finding = Finding(
                        category="Malicious Service",
                        description=f"Service running from temp folder",
                        score=60,
                        severity="critical",
                        mitre_techniques=path_rule.get('mitre_techniques', []),
                        source="service",
                        evidence={"path": path}
                    )
                    self._add_finding(finding)
                    return "Critical: Running from Temp"
                return "High Risk: User-Space Path"

        # Check missing binary
        if not path or path == 'none':
            return "Suspicious: Missing Path"

        return "Normal"

    def assess_wmi_persistence(self, entry: dict) -> Optional[Finding]:
        """
        Assess WMI event subscription for malicious indicators.

        Args:
            entry: Dictionary containing WMI subscription data

        Returns:
            Finding if suspicious, None otherwise
        """
        # Use actual collector field names: Type, Name, Command, Query
        entry_type = str(entry.get('Type', '')).lower()
        name = str(entry.get('Name', ''))
        command = str(entry.get('Command', '') or entry.get('Query', '')).lower()

        # EventConsumer entries are most suspicious
        if entry_type == 'eventconsumer':
            # Check for encoded/obfuscated commands
            if any(p in command for p in ['-enc', '-encodedcommand', 'frombase64', 'hidden', '-w hidden', '-nop', 'powershell', 'cmd.exe']):
                finding = Finding(
                    category="WMI Persistence",
                    description=f"WMI EventConsumer with suspicious command: {name}",
                    score=55,
                    severity="critical",
                    mitre_techniques=["T1546.003"],
                    source="wmi",
                    evidence=entry
                )
                self._add_finding(finding)
                return finding

            # EventConsumer with any command is suspicious
            if command:
                finding = Finding(
                    category="WMI Persistence",
                    description=f"WMI EventConsumer detected: {name}",
                    score=40,
                    severity="high",
                    mitre_techniques=["T1546.003"],
                    source="wmi",
                    evidence=entry
                )
                self._add_finding(finding)
                return finding

        # EventFilter entries - check for suspicious queries
        if entry_type == 'eventfilter':
            if any(p in command for p in ['win32_process', 'win32_logon', '__instancecreation', '__instancemodification']):
                finding = Finding(
                    category="WMI Persistence",
                    description=f"WMI EventFilter monitoring system events: {name}",
                    score=30,
                    severity="medium",
                    mitre_techniques=["T1546.003"],
                    source="wmi",
                    evidence=entry
                )
                self._add_finding(finding)
                return finding

        return None

    def assess_shimcache(self, entry: dict) -> Optional[Finding]:
        """
        Assess shimcache entry for suspicious execution.

        Args:
            entry: Dictionary containing shimcache data

        Returns:
            Finding if suspicious, None otherwise
        """
        path = str(entry.get('path', '')).lower()
        filename = path.split('\\')[-1] if '\\' in path else path

        # Check suspicious paths
        suspicious_paths = [
            'temp', 'appdata\\local\\temp', '\\recycle', 'programdata',
            'downloads', 'public', '\\users\\public'
        ]

        # Known malware tool names
        malware_names = [
            'mimikatz', 'psexec', 'procdump', 'lazagne', 'ncat', 'nc.exe',
            'powercat', 'rubeus', 'sharphound', 'bloodhound', 'covenant'
        ]

        # Check for known malware names
        for malware in malware_names:
            if malware in filename:
                finding = Finding(
                    category="Known Malware Tool",
                    description=f"Known attack tool in shimcache: {filename}",
                    score=60,
                    severity="critical",
                    mitre_techniques=["T1059", "T1003"],
                    source="shimcache",
                    evidence=entry
                )
                self._add_finding(finding)
                return finding

        # Check for execution from suspicious paths
        for susp_path in suspicious_paths:
            if susp_path in path:
                finding = Finding(
                    category="Suspicious Execution",
                    description=f"Program executed from suspicious location: {path[:100]}",
                    score=35,
                    severity="high",
                    mitre_techniques=["T1059"],
                    source="shimcache",
                    evidence=entry
                )
                self._add_finding(finding)
                return finding

        return None

    def assess_startup_file(self, entry: dict) -> Optional[Finding]:
        """
        Assess startup folder file for persistence.

        Args:
            entry: Dictionary containing startup file data

        Returns:
            Finding if suspicious, None otherwise
        """
        # Use actual collector field names (capitalized): Filename, Path
        filename = str(entry.get('Filename', entry.get('filename', ''))).lower()
        path = str(entry.get('Path', entry.get('path', ''))).lower()

        # Script extensions are high risk in startup
        script_extensions = ['.vbs', '.bat', '.ps1', '.js', '.hta', '.cmd', '.wsf']
        if any(filename.endswith(ext) for ext in script_extensions):
            finding = Finding(
                category="Startup Persistence",
                description=f"Script file in startup folder: {filename}",
                score=50,
                severity="critical",
                mitre_techniques=["T1547.001"],
                source="startup",
                evidence=entry
            )
            self._add_finding(finding)
            return finding

        # Executable in startup is medium risk
        exe_extensions = ['.exe', '.dll', '.scr', '.pif']
        if any(filename.endswith(ext) for ext in exe_extensions):
            finding = Finding(
                category="Startup Persistence",
                description=f"Executable in startup folder: {filename}",
                score=30,
                severity="medium",
                mitre_techniques=["T1547.001"],
                source="startup",
                evidence=entry
            )
            self._add_finding(finding)
            return finding

        # LNK files pointing to scripts
        if filename.endswith('.lnk'):
            target = str(entry.get('target', '')).lower()
            if any(ext in target for ext in script_extensions + exe_extensions):
                finding = Finding(
                    category="Startup Persistence",
                    description=f"Shortcut in startup folder: {filename}",
                    score=25,
                    severity="medium",
                    mitre_techniques=["T1547.001"],
                    source="startup",
                    evidence=entry
                )
                self._add_finding(finding)
                return finding

        return None

    def assess_bits_job(self, entry: dict) -> Optional[Finding]:
        """
        Assess BITS job for malicious transfers.

        Args:
            entry: Dictionary containing BITS job data

        Returns:
            Finding if suspicious, None otherwise
        """
        # Use actual collector field names: DisplayName, JobState, TransferType, Files
        files = str(entry.get('Files', '')).lower()
        job_name = str(entry.get('DisplayName', 'Unknown'))
        job_state = str(entry.get('JobState', '')).lower()
        transfer_type = str(entry.get('TransferType', '')).lower()

        # Executable in BITS transfer is highly suspicious
        exe_extensions = ['.exe', '.dll', '.ps1', '.bat', '.vbs', '.msi', '.scr', '.hta', '.cmd']
        if any(ext in files for ext in exe_extensions):
            finding = Finding(
                category="BITS Download",
                description=f"Executable in BITS transfer: {job_name}",
                score=45,
                severity="high",
                mitre_techniques=["T1197", "T1105"],
                source="bits",
                evidence=entry
            )
            self._add_finding(finding)
            return finding

        # Suspicious URL patterns
        suspicious_patterns = ['pastebin', 'githubusercontent', 'discord', 'telegram', 'ngrok', 'duckdns']
        if any(p in files for p in suspicious_patterns):
            finding = Finding(
                category="BITS Transfer",
                description=f"BITS job with suspicious URL: {job_name}",
                score=35,
                severity="medium",
                mitre_techniques=["T1197"],
                source="bits",
                evidence=entry
            )
            self._add_finding(finding)
            return finding

        # Downloads to temp/suspicious locations
        suspicious_paths = ['temp', 'appdata', 'programdata', 'public']
        if any(p in files for p in suspicious_paths):
            finding = Finding(
                category="BITS Transfer",
                description=f"BITS job to suspicious location: {job_name}",
                score=30,
                severity="medium",
                mitre_techniques=["T1197"],
                source="bits",
                evidence=entry
            )
            self._add_finding(finding)
            return finding

        # Download type jobs are notable
        if 'download' in transfer_type and files:
            state = job_state
            if state in ['queued', 'connecting', 'transferring', 'suspended']:
                finding = Finding(
                    category="BITS Job",
                    description=f"Active BITS job from user account: {job_name}",
                    score=20,
                    severity="low",
                    mitre_techniques=["T1197"],
                    source="bits",
                    evidence=entry
                )
                self._add_finding(finding)
                return finding

        return None

    def assess_browser_download(self, entry: dict) -> Optional[Finding]:
        """
        Assess browser download for suspicious indicators.

        Args:
            entry: Dictionary containing download data

        Returns:
            Finding if suspicious, None otherwise
        """
        url = str(entry.get('url', '') or entry.get('URL', '')).lower()
        filename = str(entry.get('filename', '') or entry.get('Filename', '')).lower()
        target_path = str(entry.get('target_path', '') or entry.get('TargetPath', '')).lower()

        rules = self.rules.get('browser_rules', {})

        # Check for executable downloads
        ext_rule = rules.get('suspicious_downloads', {})
        for ext in ext_rule.get('extensions', []):
            if filename.endswith(ext) or target_path.endswith(ext):
                finding = Finding(
                    category="Suspicious Download",
                    description=f"Executable downloaded via browser: {filename}",
                    score=ext_rule.get('score', 35),
                    severity=ext_rule.get('severity', 'high'),
                    mitre_techniques=ext_rule.get('mitre_techniques', []),
                    source="browser",
                    evidence=entry
                )
                self._add_finding(finding)
                return finding

        # Check for suspicious download sources
        source_rule = rules.get('suspicious_download_sources', {})
        for pattern in source_rule.get('patterns', []):
            if pattern in url:
                finding = Finding(
                    category="Suspicious Download Source",
                    description=f"Download from suspicious source: {pattern}",
                    score=source_rule.get('score', 40),
                    severity=source_rule.get('severity', 'high'),
                    mitre_techniques=source_rule.get('mitre_techniques', []),
                    source="browser",
                    evidence=entry
                )
                self._add_finding(finding)
                return finding

        return None

    def assess_anti_forensics(self, entry: dict, source_type: str = "process") -> Optional[Finding]:
        """
        Assess evidence of anti-forensics activity.

        Detects:
        - Log clearing / event log manipulation
        - Shadow copy deletion (vssadmin, wmic shadowcopy)
        - Timestomping indicators
        - Defender/AV tampering
        - Evidence destruction

        Args:
            entry: Dictionary or Series containing data to assess
            source_type: Type of source (process, event, file)

        Returns:
            Finding if anti-forensics detected, None otherwise
        """
        # Convert pandas Series to dict if needed
        if hasattr(entry, 'to_dict'):
            entry = entry.to_dict()

        cmd = str(entry.get('cmdline', '') or entry.get('Command', '')).lower()
        name = str(entry.get('name', '') or entry.get('Name', '')).lower()
        path = str(entry.get('exe', '') or entry.get('Path', '')).lower()

        # Shadow copy deletion - T1490 Inhibit System Recovery
        shadow_patterns = [
            'vssadmin delete shadows',
            'vssadmin.exe delete shadows',
            'wmic shadowcopy delete',
            'wmic.exe shadowcopy delete',
            'bcdedit /set {default} bootstatuspolicy ignoreallfailures',
            'bcdedit /set {default} recoveryenabled no',
            'wbadmin delete catalog',
            'wbadmin delete systemstatebackup',
        ]
        for pattern in shadow_patterns:
            if pattern in cmd:
                finding = Finding(
                    category="Anti-Forensics",
                    description=f"Shadow copy/backup deletion detected: {pattern}",
                    score=60,
                    severity="critical",
                    mitre_techniques=["T1490", "T1070"],
                    source=source_type,
                    evidence=entry
                )
                self._add_finding(finding)
                return finding

        # Event log clearing - T1070.001 Clear Windows Event Logs
        log_clear_patterns = [
            'wevtutil cl',
            'wevtutil.exe cl',
            'clear-eventlog',
            'remove-eventlog',
            'del /f /q %windir%\\system32\\winevt',
            'del /f /q c:\\windows\\system32\\winevt',
        ]
        for pattern in log_clear_patterns:
            if pattern in cmd:
                finding = Finding(
                    category="Anti-Forensics",
                    description=f"Event log clearing detected: {pattern}",
                    score=55,
                    severity="critical",
                    mitre_techniques=["T1070.001"],
                    source=source_type,
                    evidence=entry
                )
                self._add_finding(finding)
                return finding

        # Timestomping indicators - T1070.006 Timestomp
        timestomp_patterns = [
            'timestomp',
            'touch -t',
            'setmace',
            'nircmd.exe setfiletime',
            'powershell.exe.*creationtime',
            'powershell.exe.*lastwritetime',
            'powershell.exe.*lastaccesstime',
            '(get-item).creationtime',
            '(get-item).lastwritetime',
        ]
        for pattern in timestomp_patterns:
            if pattern in cmd:
                finding = Finding(
                    category="Anti-Forensics",
                    description=f"Timestomping activity detected",
                    score=50,
                    severity="critical",
                    mitre_techniques=["T1070.006"],
                    source=source_type,
                    evidence=entry
                )
                self._add_finding(finding)
                return finding

        # Defender/AV tampering - T1562.001 Disable or Modify Tools
        av_tamper_patterns = [
            'set-mppreference -disablerealtimemonitoring',
            'set-mppreference -disablebehaviormonitoring',
            'set-mppreference -disableioavprotection',
            'set-mppreference -disablescriptscanning',
            'set-mppreference -disableintrusionpreventionsystem',
            'add-mppreference -exclusionpath',
            'add-mppreference -exclusionprocess',
            'add-mppreference -exclusionextension',
            'sc stop windefend',
            'sc config windefend start= disabled',
            'net stop windefend',
            'taskkill /f /im msmpeng.exe',
            'reg add.*windows defender.*disableantispyware',
        ]
        for pattern in av_tamper_patterns:
            if pattern in cmd:
                finding = Finding(
                    category="Anti-Forensics",
                    description=f"Security tool tampering detected",
                    score=55,
                    severity="critical",
                    mitre_techniques=["T1562.001"],
                    source=source_type,
                    evidence=entry
                )
                self._add_finding(finding)
                return finding

        # Firewall tampering - T1562.004 Disable or Modify System Firewall
        firewall_patterns = [
            'netsh advfirewall set allprofiles state off',
            'netsh firewall set opmode disable',
            'set-netfirewallprofile -enabled false',
            'netsh advfirewall firewall add rule',
        ]
        for pattern in firewall_patterns:
            if pattern in cmd:
                finding = Finding(
                    category="Anti-Forensics",
                    description=f"Firewall tampering detected",
                    score=45,
                    severity="high",
                    mitre_techniques=["T1562.004"],
                    source=source_type,
                    evidence=entry
                )
                self._add_finding(finding)
                return finding

        # Evidence destruction - secure delete tools
        destruction_patterns = [
            'sdelete', 'eraser.exe', 'cipher /w:', 'srm ',
            'bleachbit', 'ccleaner', 'wipe.exe', 'shred ',
        ]
        for pattern in destruction_patterns:
            if pattern in cmd or pattern in name:
                finding = Finding(
                    category="Anti-Forensics",
                    description=f"Evidence destruction tool detected: {pattern}",
                    score=45,
                    severity="high",
                    mitre_techniques=["T1070.004"],
                    source=source_type,
                    evidence=entry
                )
                self._add_finding(finding)
                return finding

        return None

    def assess_kerberos_attack(self, entry: dict, source_type: str = "event") -> Optional[Finding]:
        """
        Assess evidence of Kerberos attacks.

        Detects:
        - Kerberoasting (T1558.003)
        - AS-REP Roasting (T1558.004)
        - Golden/Silver Ticket (T1558.001)
        - Pass-the-Ticket (T1550.003)

        Args:
            entry: Dictionary containing event or process data
            source_type: Type of source

        Returns:
            Finding if Kerberos attack detected, None otherwise
        """
        # Convert pandas Series to dict if needed
        if hasattr(entry, 'to_dict'):
            entry = entry.to_dict()

        event_id = entry.get('EventID') or entry.get('event_id') or entry.get('Id')
        cmd = str(entry.get('cmdline', '') or entry.get('Command', '')).lower()
        message = str(entry.get('Message', '') or entry.get('message', '')).lower()

        # Kerberoasting tool patterns in command line
        kerberoast_patterns = [
            'invoke-kerberoast', 'get-spnusers', 'rubeus kerberoast',
            'rubeus.exe kerberoast', 'gettgt', 'getuserspns',
            'impacket', 'kerberoast.py', '-spn',
        ]
        for pattern in kerberoast_patterns:
            if pattern in cmd:
                finding = Finding(
                    category="Kerberos Attack",
                    description=f"Kerberoasting activity detected: {pattern}",
                    score=60,
                    severity="critical",
                    mitre_techniques=["T1558.003"],
                    source=source_type,
                    evidence=entry
                )
                self._add_finding(finding)
                return finding

        # AS-REP Roasting patterns
        asrep_patterns = [
            'invoke-asreproast', 'rubeus asreproast', 'getnpusers',
            'asrep', 'rubeus.exe asreproast',
        ]
        for pattern in asrep_patterns:
            if pattern in cmd:
                finding = Finding(
                    category="Kerberos Attack",
                    description=f"AS-REP Roasting activity detected: {pattern}",
                    score=60,
                    severity="critical",
                    mitre_techniques=["T1558.004"],
                    source=source_type,
                    evidence=entry
                )
                self._add_finding(finding)
                return finding

        # Golden/Silver ticket patterns
        ticket_patterns = [
            'mimikatz.*kerberos::golden', 'mimikatz.*kerberos::silver',
            'rubeus ptt', 'rubeus.exe ptt', 'invoke-mimikatz.*ticket',
            'ticketer.py', 'golden_ticket', 'silver_ticket',
        ]
        for pattern in ticket_patterns:
            if pattern in cmd:
                finding = Finding(
                    category="Kerberos Attack",
                    description=f"Kerberos ticket forgery detected",
                    score=65,
                    severity="critical",
                    mitre_techniques=["T1558.001", "T1550.003"],
                    source=source_type,
                    evidence=entry
                )
                self._add_finding(finding)
                return finding

        # Event ID based detection
        if event_id:
            try:
                eid = int(event_id)
                # 4769 - Kerberos Service Ticket Request (watch for RC4 encryption)
                if eid == 4769 and ('0x17' in message or 'rc4' in message):
                    finding = Finding(
                        category="Kerberos Attack",
                        description="Kerberos ticket requested with weak encryption (RC4)",
                        score=40,
                        severity="high",
                        mitre_techniques=["T1558.003"],
                        source=source_type,
                        evidence=entry
                    )
                    self._add_finding(finding)
                    return finding

                # 4768 - TGT Request with unusual encryption
                if eid == 4768 and ('0x17' in message or 'rc4' in message):
                    finding = Finding(
                        category="Kerberos Attack",
                        description="TGT requested with weak encryption (potential AS-REP roast)",
                        score=35,
                        severity="high",
                        mitre_techniques=["T1558.004"],
                        source=source_type,
                        evidence=entry
                    )
                    self._add_finding(finding)
                    return finding
            except (ValueError, TypeError):
                pass

        return None

    def assess_brute_force(self, events: list) -> List[Finding]:
        """
        Assess evidence of brute force attacks from event logs.

        Detects:
        - Multiple failed logons (T1110.001)
        - Password spraying (T1110.003)
        - Credential stuffing (T1110.004)

        Args:
            events: List of event dictionaries

        Returns:
            List of findings if brute force detected
        """
        findings = []
        failed_logons = {}  # Track by user and source IP
        failed_by_ip = {}   # Track by source IP only (for password spraying)

        for event in events:
            if hasattr(event, 'to_dict'):
                event = event.to_dict()

            event_id = event.get('EventID') or event.get('event_id') or event.get('Id')
            try:
                eid = int(event_id) if event_id else 0
            except (ValueError, TypeError):
                continue

            # 4625 - Failed logon
            if eid == 4625:
                message = str(event.get('Message', '') or event.get('message', ''))
                user = str(event.get('TargetUserName', '') or event.get('user', '') or 'unknown').lower()
                source_ip = str(event.get('IpAddress', '') or event.get('source_ip', '') or 'unknown')

                # Track by user
                key = f"{user}:{source_ip}"
                failed_logons[key] = failed_logons.get(key, 0) + 1

                # Track by IP only
                failed_by_ip[source_ip] = failed_by_ip.get(source_ip, set())
                failed_by_ip[source_ip].add(user)

        # Check for brute force against single user (5+ failures)
        for key, count in failed_logons.items():
            if count >= 5:
                user, source_ip = key.split(':', 1)
                finding = Finding(
                    category="Brute Force Attack",
                    description=f"Multiple failed logons for user {user} from {source_ip} ({count} attempts)",
                    score=45,
                    severity="high",
                    mitre_techniques=["T1110.001"],
                    source="event_log",
                    evidence={"user": user, "source_ip": source_ip, "failed_attempts": count}
                )
                self._add_finding(finding)
                findings.append(finding)

        # Check for password spraying (same IP, multiple users)
        for source_ip, users in failed_by_ip.items():
            if len(users) >= 5 and source_ip not in ['unknown', '', '-']:
                finding = Finding(
                    category="Password Spraying",
                    description=f"Failed logons to {len(users)} different accounts from {source_ip}",
                    score=55,
                    severity="critical",
                    mitre_techniques=["T1110.003"],
                    source="event_log",
                    evidence={"source_ip": source_ip, "targeted_users": len(users), "users": list(users)[:10]}
                )
                self._add_finding(finding)
                findings.append(finding)

        return findings

    def assess_scheduled_task(self, entry: dict) -> Optional[Finding]:
        """
        Assess scheduled task for suspicious indicators.

        Args:
            entry: Dictionary containing scheduled task data

        Returns:
            Finding if suspicious, None otherwise
        """
        task_name = str(entry.get('TaskName', '') or entry.get('name', '')).lower()
        action = str(entry.get('Action', '') or entry.get('action', '')).lower()
        run_as = str(entry.get('RunAs', '') or entry.get('UserId', '')).lower()
        path = str(entry.get('TaskPath', '') or entry.get('path', '')).lower()

        rules = self.rules.get('scheduled_task_rules', {})

        # Check for hidden tasks
        hidden_rule = rules.get('hidden_task', {})
        for pattern in hidden_rule.get('patterns', []):
            if pattern in str(entry).lower():
                finding = Finding(
                    category="Hidden Scheduled Task",
                    description=f"Hidden scheduled task detected: {task_name}",
                    score=hidden_rule.get('score', 40),
                    severity=hidden_rule.get('severity', 'high'),
                    mitre_techniques=hidden_rule.get('mitre_techniques', []),
                    source="scheduled_task",
                    evidence=entry
                )
                self._add_finding(finding)
                return finding

        # Check for SYSTEM tasks running from user locations
        system_rule = rules.get('system_impersonation', {})
        if any(p in run_as for p in system_rule.get('user_patterns', ['system', 'nt authority'])):
            for loc in system_rule.get('location_patterns', []):
                if loc in action:
                    finding = Finding(
                        category="Suspicious Scheduled Task",
                        description=f"SYSTEM task running from user location: {task_name}",
                        score=system_rule.get('score', 50),
                        severity=system_rule.get('severity', 'critical'),
                        mitre_techniques=system_rule.get('mitre_techniques', []),
                        source="scheduled_task",
                        evidence=entry
                    )
                    self._add_finding(finding)
                    return finding

        # Check for script-based tasks
        script_patterns = ['powershell', 'cmd.exe', 'wscript', 'cscript', 'mshta', '-enc', '-encodedcommand']
        for pattern in script_patterns:
            if pattern in action:
                finding = Finding(
                    category="Script Scheduled Task",
                    description=f"Scheduled task runs script interpreter: {task_name}",
                    score=35,
                    severity="high",
                    mitre_techniques=["T1053.005"],
                    source="scheduled_task",
                    evidence=entry
                )
                self._add_finding(finding)
                return finding

        return None

    def assess_file_for_ransomware(self, filename: str, path: str) -> Optional[Finding]:
        """
        Check if file indicates ransomware activity.

        Args:
            filename: Name of the file
            path: Full path to the file

        Returns:
            Finding if ransomware indicator found, None otherwise
        """
        fname_lower = filename.lower()
        path_lower = path.lower()
        rules = self.rules.get('file_rules', {})

        # Check for ransomware file extensions
        ransom_ext_rule = rules.get('ransomware_extensions', {})
        for ext in ransom_ext_rule.get('patterns', []):
            if fname_lower.endswith(ext):
                finding = Finding(
                    category="Ransomware Indicator",
                    description=f"File with ransomware extension detected: {filename}",
                    score=ransom_ext_rule.get('score', 70),
                    severity=ransom_ext_rule.get('severity', 'critical'),
                    mitre_techniques=ransom_ext_rule.get('mitre_techniques', []),
                    source="file",
                    evidence={"filename": filename, "path": path}
                )
                self._add_finding(finding)
                return finding

        # Check for ransom notes
        ransom_note_rule = rules.get('ransom_notes', {})
        for pattern in ransom_note_rule.get('patterns', []):
            if pattern in fname_lower:
                finding = Finding(
                    category="Ransom Note",
                    description=f"Possible ransom note detected: {filename}",
                    score=ransom_note_rule.get('score', 65),
                    severity=ransom_note_rule.get('severity', 'critical'),
                    mitre_techniques=ransom_note_rule.get('mitre_techniques', []),
                    source="file",
                    evidence={"filename": filename, "path": path}
                )
                self._add_finding(finding)
                return finding

        return None

    def get_global_score(self) -> int:
        """
        Calculate the global risk score from all findings.

        The score is bounded by category caps and global max to ensure
        reliable, interpretable results (0-100 scale).

        Returns:
            Aggregated risk score (0-100)
        """
        # Sum all category scores (already capped per category)
        total = sum(self._category_scores.values())

        # Apply global max cap
        max_global = self.scoring_config.get('max_global_score', 100)
        normalized = min(total, max_global)

        logger.debug("Global score: %d (raw: %d, categories: %s)",
                    normalized, total, dict(self._category_scores))
        return normalized

    def get_severity(self) -> str:
        """
        Get the overall severity level based on configurable thresholds.

        Returns:
            Severity string: 'critical', 'high', 'medium', 'low', 'info'
        """
        score = self.get_global_score()
        thresholds = self.scoring_config.get('severity_thresholds', {
            'critical': 70, 'high': 50, 'medium': 25, 'low': 10
        })

        if score >= thresholds.get('critical', 70):
            return "critical"
        elif score >= thresholds.get('high', 50):
            return "high"
        elif score >= thresholds.get('medium', 25):
            return "medium"
        elif score >= thresholds.get('low', 10):
            return "low"
        return "info"

    def get_top_findings(self, n: int = 5) -> List[Finding]:
        """
        Get the top N findings by score.

        Args:
            n: Number of findings to return

        Returns:
            List of top findings sorted by score (highest first)
        """
        # Filter out zero-score findings (capped duplicates)
        scored_findings = [f for f in self.all_findings if f.score > 0]
        return sorted(scored_findings, key=lambda f: f.score, reverse=True)[:n]

    def get_findings_by_mitre(self) -> Dict[str, List[Finding]]:
        """
        Group findings by MITRE technique.

        Returns:
            Dictionary mapping technique IDs to findings
        """
        result = {}
        for finding in self.all_findings:
            for technique in finding.mitre_techniques:
                if technique not in result:
                    result[technique] = []
                result[technique].append(finding)
        return result

    def get_category_breakdown(self) -> Dict[str, Dict]:
        """
        Get score breakdown by category with max limits.

        Returns:
            Dictionary with category scores and their limits
        """
        category_max = self.scoring_config.get('category_max_scores', {})
        breakdown = {}
        for category, score in self._category_scores.items():
            max_score = category_max.get(category, category_max.get('default', 15))
            breakdown[category] = {
                'score': score,
                'max': max_score,
                'percentage': round((score / max_score) * 100, 1) if max_score > 0 else 0
            }
        return breakdown

    def get_scoring_summary(self) -> Dict:
        """
        Get a complete scoring summary for reporting.

        Returns:
            Dictionary with scoring details
        """
        return {
            'global_score': self.get_global_score(),
            'severity': self.get_severity(),
            'total_findings': len(self.all_findings),
            'unique_findings': len([f for f in self.all_findings if f.score > 0]),
            'mitre_techniques': len(self.mitre_techniques),
            'category_breakdown': self.get_category_breakdown(),
            'top_findings': [
                {'category': f.category, 'score': f.score, 'severity': f.severity}
                for f in self.get_top_findings(5)
            ]
        }

    def reset(self):
        """Reset all findings for a new analysis session."""
        self.all_findings = []
        self.mitre_techniques = set()
        self._finding_keys = set()
        self._category_scores = {}
        logger.info("RiskEngine reset")
