"""
Threat Intelligence Integration Module.

Checks IPs, domains, and hashes against threat intelligence sources.
Supports caching to avoid repeated lookups.
"""
import os
import json
import time
import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from pathlib import Path
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


@dataclass
class ThreatIndicator:
    """Represents a threat intelligence match."""
    indicator_type: str  # ip, domain, hash
    value: str
    source: str
    threat_type: str
    confidence: str  # high, medium, low
    description: str
    tags: List[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    reference_url: str = ""


class ThreatIntelCache:
    """Simple file-based cache for threat intel lookups."""

    def __init__(self, cache_dir: str, ttl_hours: int = 24):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = timedelta(hours=ttl_hours)
        self.cache_file = self.cache_dir / "threat_intel_cache.json"
        self._cache = self._load_cache()

    def _load_cache(self) -> Dict:
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save_cache(self):
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self._cache, f)
        except Exception as e:
            logger.warning("Failed to save cache: %s", str(e))

    def get(self, key: str) -> Optional[Dict]:
        """Get cached result if not expired."""
        if key in self._cache:
            entry = self._cache[key]
            cached_time = datetime.fromisoformat(entry.get('timestamp', '2000-01-01'))
            if datetime.now() - cached_time < self.ttl:
                return entry.get('data')
        return None

    def set(self, key: str, data: Any):
        """Cache a result."""
        self._cache[key] = {
            'timestamp': datetime.now().isoformat(),
            'data': data
        }
        self._save_cache()


class ThreatIntelEngine:
    """
    Threat Intelligence lookup engine.

    Uses local threat lists and optional API integrations.
    """

    # Known malicious/suspicious indicators (built-in)
    KNOWN_MALICIOUS_IPS = {
        # Tor exit nodes (sample)
        '185.220.100.', '185.220.101.', '185.220.102.',
        '45.33.32.156',  # scanme.nmap.org - scanning
        # Known C2 ranges (sample)
        '23.227.38.',  # Cobalt Strike default
    }

    KNOWN_MALICIOUS_DOMAINS = {
        # Malware/phishing keywords
        'malware', 'phishing', 'exploit', 'payload', 'dropper',
        'c2server', 'command-control', 'botnet',
        # Suspicious TLDs
        '.tk', '.ml', '.ga', '.cf', '.gq',
        # Dynamic DNS (often abused)
        'duckdns.org', 'no-ip.', 'dynu.', 'hopto.org',
        'ddns.net', 'serveo.net', 'ngrok.io',
        # File sharing (used for malware hosting)
        'anonfiles.com', 'transfer.sh',
    }

    KNOWN_SUSPICIOUS_PORTS = {
        4444: 'Metasploit default',
        5555: 'Android ADB/RAT',
        6666: 'IRC bot',
        6667: 'IRC C2',
        1337: 'Leet/backdoor',
        31337: 'Back Orifice',
        9001: 'Tor',
        9050: 'Tor SOCKS',
        3333: 'Crypto mining',
        14444: 'Crypto mining',
    }

    CRYPTO_MINING_POOLS = [
        'pool.minergate.com', 'xmr.pool.', 'monero.', 'xmrpool.',
        'nanopool.org', 'dwarfpool.', 'supportxmr.', '2miners.',
        'hashvault.pro', 'minexmr.', 'f2pool.', 'antpool.',
    ]

    def __init__(self, config_dir: str = None):
        """
        Initialize the threat intel engine.

        Args:
            config_dir: Directory for cache and custom threat lists
        """
        self.matches: List[ThreatIndicator] = []
        self._checked_indicators: Set[str] = set()

        # Initialize cache
        cache_dir = config_dir or os.path.join(os.path.dirname(__file__), '..', 'config', 'cache')
        self.cache = ThreatIntelCache(cache_dir)

        # Load custom threat lists if available
        self.custom_ips: Set[str] = set()
        self.custom_domains: Set[str] = set()
        self._load_custom_lists(config_dir)

    def _load_custom_lists(self, config_dir: str = None):
        """Load custom threat lists from config directory."""
        if not config_dir:
            config_dir = os.path.join(os.path.dirname(__file__), '..', 'config')

        # Load custom IP list
        ip_file = os.path.join(config_dir, 'threat_ips.txt')
        if os.path.exists(ip_file):
            try:
                with open(ip_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            self.custom_ips.add(line)
                logger.info("Loaded %d custom threat IPs", len(self.custom_ips))
            except Exception as e:
                logger.warning("Failed to load custom IPs: %s", str(e))

        # Load custom domain list
        domain_file = os.path.join(config_dir, 'threat_domains.txt')
        if os.path.exists(domain_file):
            try:
                with open(domain_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            self.custom_domains.add(line.lower())
                logger.info("Loaded %d custom threat domains", len(self.custom_domains))
            except Exception as e:
                logger.warning("Failed to load custom domains: %s", str(e))

    def check_ip(self, ip: str) -> Optional[ThreatIndicator]:
        """
        Check an IP address against threat intelligence.

        Args:
            ip: IP address to check

        Returns:
            ThreatIndicator if malicious, None otherwise
        """
        if not ip or ip in self._checked_indicators:
            return None

        self._checked_indicators.add(ip)

        # Skip private/local IPs
        if self._is_private_ip(ip):
            return None

        # Check cache first
        cached = self.cache.get(f"ip:{ip}")
        if cached is not None:
            if cached:
                indicator = ThreatIndicator(**cached)
                self.matches.append(indicator)
                return indicator
            return None

        # Check against known malicious IPs
        for mal_ip in self.KNOWN_MALICIOUS_IPS:
            if ip.startswith(mal_ip):
                indicator = ThreatIndicator(
                    indicator_type='ip',
                    value=ip,
                    source='built-in',
                    threat_type='malicious_ip',
                    confidence='medium',
                    description=f'IP matches known malicious range: {mal_ip}*',
                    tags=['malicious', 'c2']
                )
                self.matches.append(indicator)
                self.cache.set(f"ip:{ip}", indicator.__dict__)
                return indicator

        # Check custom list
        if ip in self.custom_ips:
            indicator = ThreatIndicator(
                indicator_type='ip',
                value=ip,
                source='custom_list',
                threat_type='threat_list',
                confidence='high',
                description='IP found in custom threat list',
                tags=['custom', 'threat']
            )
            self.matches.append(indicator)
            self.cache.set(f"ip:{ip}", indicator.__dict__)
            return indicator

        # No match - cache negative result
        self.cache.set(f"ip:{ip}", None)
        return None

    def check_domain(self, domain: str) -> Optional[ThreatIndicator]:
        """
        Check a domain against threat intelligence.

        Args:
            domain: Domain name to check

        Returns:
            ThreatIndicator if malicious, None otherwise
        """
        if not domain or domain in self._checked_indicators:
            return None

        domain = domain.lower().strip()
        self._checked_indicators.add(domain)

        # Check cache first
        cached = self.cache.get(f"domain:{domain}")
        if cached is not None:
            if cached:
                indicator = ThreatIndicator(**cached)
                self.matches.append(indicator)
                return indicator
            return None

        # Check for crypto mining pools
        for pool in self.CRYPTO_MINING_POOLS:
            if pool in domain:
                indicator = ThreatIndicator(
                    indicator_type='domain',
                    value=domain,
                    source='built-in',
                    threat_type='crypto_mining',
                    confidence='high',
                    description=f'Cryptocurrency mining pool detected',
                    tags=['mining', 'cryptominer']
                )
                self.matches.append(indicator)
                self.cache.set(f"domain:{domain}", indicator.__dict__)
                return indicator

        # Check against known malicious patterns
        for pattern in self.KNOWN_MALICIOUS_DOMAINS:
            if pattern in domain:
                indicator = ThreatIndicator(
                    indicator_type='domain',
                    value=domain,
                    source='built-in',
                    threat_type='suspicious_domain',
                    confidence='medium',
                    description=f'Domain matches suspicious pattern: {pattern}',
                    tags=['suspicious', pattern.replace('.', '')]
                )
                self.matches.append(indicator)
                self.cache.set(f"domain:{domain}", indicator.__dict__)
                return indicator

        # Check custom list
        if domain in self.custom_domains:
            indicator = ThreatIndicator(
                indicator_type='domain',
                value=domain,
                source='custom_list',
                threat_type='threat_list',
                confidence='high',
                description='Domain found in custom threat list',
                tags=['custom', 'threat']
            )
            self.matches.append(indicator)
            self.cache.set(f"domain:{domain}", indicator.__dict__)
            return indicator

        # Check for DGA-like domains
        if self._looks_like_dga(domain):
            indicator = ThreatIndicator(
                indicator_type='domain',
                value=domain,
                source='heuristic',
                threat_type='dga_domain',
                confidence='medium',
                description='Domain appears to be algorithmically generated (DGA)',
                tags=['dga', 'suspicious']
            )
            self.matches.append(indicator)
            self.cache.set(f"domain:{domain}", indicator.__dict__)
            return indicator

        # No match
        self.cache.set(f"domain:{domain}", None)
        return None

    def check_port(self, port: int) -> Optional[ThreatIndicator]:
        """Check if a port is associated with known threats."""
        if port in self.KNOWN_SUSPICIOUS_PORTS:
            description = self.KNOWN_SUSPICIOUS_PORTS[port]
            indicator = ThreatIndicator(
                indicator_type='port',
                value=str(port),
                source='built-in',
                threat_type='suspicious_port',
                confidence='medium',
                description=f'Connection to suspicious port: {description}',
                tags=['suspicious_port', description.replace(' ', '_').lower()]
            )
            self.matches.append(indicator)
            return indicator
        return None

    def check_hash(self, file_hash: str, hash_type: str = 'sha256') -> Optional[ThreatIndicator]:
        """
        Check a file hash against threat intelligence.

        Note: This requires API integration for real lookups.
        Currently just checks against local lists.
        """
        if not file_hash or file_hash in self._checked_indicators:
            return None

        file_hash = file_hash.lower().strip()
        self._checked_indicators.add(file_hash)

        # Check cache
        cached = self.cache.get(f"hash:{file_hash}")
        if cached is not None:
            if cached:
                indicator = ThreatIndicator(**cached)
                self.matches.append(indicator)
                return indicator
            return None

        # Load custom hash list if available
        hash_file = os.path.join(os.path.dirname(__file__), '..', 'config', 'threat_hashes.txt')
        if os.path.exists(hash_file):
            try:
                with open(hash_file, 'r') as f:
                    if file_hash in f.read().lower():
                        indicator = ThreatIndicator(
                            indicator_type='hash',
                            value=file_hash,
                            source='custom_list',
                            threat_type='malicious_file',
                            confidence='high',
                            description='File hash found in threat list',
                            tags=['malware', 'custom']
                        )
                        self.matches.append(indicator)
                        self.cache.set(f"hash:{file_hash}", indicator.__dict__)
                        return indicator
            except Exception:
                pass

        self.cache.set(f"hash:{file_hash}", None)
        return None

    def analyze_network_connections(self, connections: List[Dict]) -> List[ThreatIndicator]:
        """Analyze a list of network connections for threats."""
        results = []

        for conn in connections:
            # Extract remote address
            raddr = conn.get('raddr', '')
            if ':' in str(raddr):
                parts = str(raddr).split(':')
                ip = parts[0]
                try:
                    port = int(parts[-1])
                except ValueError:
                    port = 0

                # Check IP
                ip_result = self.check_ip(ip)
                if ip_result:
                    results.append(ip_result)

                # Check port
                port_result = self.check_port(port)
                if port_result:
                    results.append(port_result)

        return results

    def analyze_dns_cache(self, dns_records: List[Dict]) -> List[ThreatIndicator]:
        """Analyze DNS cache entries for threats."""
        results = []

        for record in dns_records:
            domain = record.get('Entry') or record.get('Record Name', '')
            if domain:
                result = self.check_domain(domain)
                if result:
                    results.append(result)

        return results

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local."""
        private_patterns = [
            r'^10\.', r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
            r'^192\.168\.', r'^127\.', r'^0\.0\.0\.0',
            r'^169\.254\.', r'^::1$', r'^fc00:', r'^fe80:'
        ]
        return any(re.match(p, ip) for p in private_patterns)

    def _looks_like_dga(self, domain: str) -> bool:
        """Heuristic check for DGA domains."""
        # Get the main domain part
        parts = domain.split('.')
        if len(parts) < 2:
            return False

        main_part = parts[-2]

        # DGA indicators:
        # - Long random-looking strings
        # - High consonant ratio
        # - Few vowels

        if len(main_part) < 12:
            return False

        vowels = set('aeiou')
        consonants = set('bcdfghjklmnpqrstvwxyz')

        vowel_count = sum(1 for c in main_part.lower() if c in vowels)
        consonant_count = sum(1 for c in main_part.lower() if c in consonants)

        if consonant_count == 0:
            return False

        vowel_ratio = vowel_count / len(main_part)

        # DGA domains typically have low vowel ratio and high entropy
        if vowel_ratio < 0.2 and len(main_part) > 15:
            return True

        # Check for repeating patterns (not DGA-like)
        if len(set(main_part)) < len(main_part) / 3:
            return False

        return False

    def get_all_matches(self) -> List[ThreatIndicator]:
        """Get all threat matches."""
        return self.matches

    def get_stats(self) -> Dict[str, int]:
        """Get statistics about threat matches."""
        return {
            'total_matches': len(self.matches),
            'ip_matches': len([m for m in self.matches if m.indicator_type == 'ip']),
            'domain_matches': len([m for m in self.matches if m.indicator_type == 'domain']),
            'hash_matches': len([m for m in self.matches if m.indicator_type == 'hash']),
            'port_matches': len([m for m in self.matches if m.indicator_type == 'port']),
            'high_confidence': len([m for m in self.matches if m.confidence == 'high']),
        }

    def reset(self):
        """Clear all matches."""
        self.matches = []
        self._checked_indicators = set()
