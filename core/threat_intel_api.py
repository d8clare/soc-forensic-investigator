"""
Threat Intelligence API Integration.

Provides enrichment from external sources:
- VirusTotal: File hash and URL scanning
- AbuseIPDB: IP reputation checking
"""
import os
import json
import time
import hashlib
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
from pathlib import Path
from datetime import datetime, timedelta

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class VirusTotalResult:
    """Result from VirusTotal lookup."""
    sha256: str
    detected: bool
    detection_ratio: str
    detections: int
    total_engines: int
    scan_date: str
    permalink: str
    malware_names: List[str]
    raw_response: Dict


@dataclass
class AbuseIPDBResult:
    """Result from AbuseIPDB lookup."""
    ip: str
    is_public: bool
    abuse_confidence_score: int
    country_code: str
    isp: str
    domain: str
    total_reports: int
    last_reported: str
    is_tor: bool
    is_whitelisted: bool
    raw_response: Dict


class ThreatIntelAPICache:
    """File-based cache for API results."""

    def __init__(self, cache_dir: str, ttl_hours: int = 24):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = timedelta(hours=ttl_hours)
        self.cache_file = self.cache_dir / "api_cache.json"
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
            logger.warning("Failed to save API cache: %s", str(e))

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


class VirusTotalAPI:
    """VirusTotal API v3 integration."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str = None, cache_dir: str = None):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "")
        self.cache = ThreatIntelAPICache(
            cache_dir or os.path.join(os.path.dirname(__file__), '..', 'config', 'cache')
        )
        self._rate_limit_remaining = 4  # Default for free tier
        self._rate_limit_reset = 0

    def is_configured(self) -> bool:
        """Check if API key is configured."""
        return bool(self.api_key)

    def _make_request(self, endpoint: str) -> Optional[Dict]:
        """Make API request with rate limiting."""
        if not REQUESTS_AVAILABLE:
            logger.warning("requests library not available")
            return None

        if not self.api_key:
            return None

        # Check rate limit
        if self._rate_limit_remaining <= 0:
            wait_time = self._rate_limit_reset - time.time()
            if wait_time > 0:
                logger.info("Rate limited, waiting %d seconds", wait_time)
                return None

        try:
            headers = {"x-apikey": self.api_key}
            response = requests.get(f"{self.BASE_URL}/{endpoint}", headers=headers, timeout=10)

            # Update rate limit info
            self._rate_limit_remaining = int(response.headers.get('x-api-quota-remaining', 4))

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"error": "not_found"}
            elif response.status_code == 429:
                self._rate_limit_remaining = 0
                self._rate_limit_reset = time.time() + 60
                return {"error": "rate_limited"}
            else:
                return {"error": f"status_{response.status_code}"}

        except Exception as e:
            logger.error("VirusTotal API error: %s", str(e))
            return {"error": str(e)}

    def lookup_hash(self, file_hash: str) -> Optional[VirusTotalResult]:
        """Look up a file hash on VirusTotal."""
        file_hash = file_hash.lower().strip()

        # Check cache
        cache_key = f"vt:hash:{file_hash}"
        cached = self.cache.get(cache_key)
        if cached:
            if cached.get("error"):
                return None
            return VirusTotalResult(**cached)

        # Make API request
        data = self._make_request(f"files/{file_hash}")
        if not data or data.get("error"):
            self.cache.set(cache_key, {"error": data.get("error", "unknown")})
            return None

        # Parse response
        try:
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())

            # Extract malware names
            malware_names = []
            for engine, result in results.items():
                if result.get("category") in ("malicious", "suspicious"):
                    name = result.get("result")
                    if name and name not in malware_names:
                        malware_names.append(name)

            result = VirusTotalResult(
                sha256=file_hash,
                detected=(malicious + suspicious) > 0,
                detection_ratio=f"{malicious + suspicious}/{total}",
                detections=malicious + suspicious,
                total_engines=total,
                scan_date=attrs.get("last_analysis_date", ""),
                permalink=f"https://www.virustotal.com/gui/file/{file_hash}",
                malware_names=malware_names[:5],
                raw_response=data
            )

            # Cache result
            self.cache.set(cache_key, result.__dict__)
            return result

        except Exception as e:
            logger.error("Error parsing VT response: %s", str(e))
            return None

    def lookup_url(self, url: str) -> Optional[Dict]:
        """Look up a URL on VirusTotal."""
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        cache_key = f"vt:url:{hashlib.md5(url.encode()).hexdigest()}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached if not cached.get("error") else None

        data = self._make_request(f"urls/{url_id}")
        if data and not data.get("error"):
            self.cache.set(cache_key, data)
        return data


class AbuseIPDBAPI:
    """AbuseIPDB API integration."""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str = None, cache_dir: str = None):
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY", "")
        self.cache = ThreatIntelAPICache(
            cache_dir or os.path.join(os.path.dirname(__file__), '..', 'config', 'cache'),
            ttl_hours=12  # IP reputation can change faster
        )

    def is_configured(self) -> bool:
        """Check if API key is configured."""
        return bool(self.api_key)

    def check_ip(self, ip: str) -> Optional[AbuseIPDBResult]:
        """Check an IP address against AbuseIPDB."""
        if not REQUESTS_AVAILABLE:
            return None

        if not self.api_key:
            return None

        # Skip private IPs
        if self._is_private_ip(ip):
            return None

        # Check cache
        cache_key = f"abuseipdb:{ip}"
        cached = self.cache.get(cache_key)
        if cached:
            if cached.get("error"):
                return None
            return AbuseIPDBResult(**cached)

        try:
            headers = {
                "Key": self.api_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90
            }
            response = requests.get(
                f"{self.BASE_URL}/check",
                headers=headers,
                params=params,
                timeout=10
            )

            if response.status_code == 200:
                data = response.json().get("data", {})

                result = AbuseIPDBResult(
                    ip=ip,
                    is_public=data.get("isPublic", True),
                    abuse_confidence_score=data.get("abuseConfidenceScore", 0),
                    country_code=data.get("countryCode", ""),
                    isp=data.get("isp", ""),
                    domain=data.get("domain", ""),
                    total_reports=data.get("totalReports", 0),
                    last_reported=data.get("lastReportedAt", ""),
                    is_tor=data.get("isTor", False),
                    is_whitelisted=data.get("isWhitelisted", False),
                    raw_response=data
                )

                self.cache.set(cache_key, result.__dict__)
                return result
            else:
                self.cache.set(cache_key, {"error": f"status_{response.status_code}"})
                return None

        except Exception as e:
            logger.error("AbuseIPDB API error: %s", str(e))
            return None

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local."""
        import re
        private_patterns = [
            r'^10\.', r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
            r'^192\.168\.', r'^127\.', r'^0\.0\.0\.0',
            r'^169\.254\.', r'^::1$', r'^fc00:', r'^fe80:'
        ]
        return any(re.match(p, ip) for p in private_patterns)


class ThreatIntelEnricher:
    """
    Unified threat intelligence enrichment.

    Combines multiple API sources for comprehensive enrichment.
    """

    def __init__(self, vt_api_key: str = None, abuseipdb_api_key: str = None):
        cache_dir = os.path.join(os.path.dirname(__file__), '..', 'config', 'cache')
        self.vt = VirusTotalAPI(vt_api_key, cache_dir)
        self.abuseipdb = AbuseIPDBAPI(abuseipdb_api_key, cache_dir)

    def get_status(self) -> Dict[str, bool]:
        """Get configuration status of all APIs."""
        return {
            "virustotal": self.vt.is_configured(),
            "abuseipdb": self.abuseipdb.is_configured()
        }

    def enrich_hash(self, file_hash: str) -> Optional[VirusTotalResult]:
        """Enrich a file hash with VirusTotal data."""
        return self.vt.lookup_hash(file_hash)

    def enrich_ip(self, ip: str) -> Optional[AbuseIPDBResult]:
        """Enrich an IP with AbuseIPDB data."""
        return self.abuseipdb.check_ip(ip)

    def enrich_process(self, process: Dict) -> Dict:
        """Enrich process data with threat intel."""
        enriched = {"virustotal": None, "abuseipdb": None}

        # Check hash
        sha256 = process.get("sha256")
        if sha256 and self.vt.is_configured():
            enriched["virustotal"] = self.enrich_hash(sha256)

        return enriched

    def enrich_network_connection(self, connection: Dict) -> Dict:
        """Enrich network connection with threat intel."""
        enriched = {"abuseipdb": None}

        # Extract remote IP
        raddr = connection.get("raddr", "")
        if ":" in str(raddr):
            ip = str(raddr).split(":")[0]
            if ip and self.abuseipdb.is_configured():
                enriched["abuseipdb"] = self.enrich_ip(ip)

        return enriched
