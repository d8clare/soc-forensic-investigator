"""
Pivot Engine - Cross-artifact correlation for SOC investigations.
Enables analysts to click on any IOC (IP, hash, process, domain) and see ALL related artifacts.
"""
import re
import json
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

from core.data_loader import load_json


class PivotType(Enum):
    """Types of pivotable indicators."""
    IP = "ip"
    HASH = "hash"
    PROCESS = "process"
    DOMAIN = "domain"
    FILE = "file"
    USER = "user"
    REGISTRY = "registry"
    COMMAND = "command"


@dataclass
class PivotResult:
    """Result from a pivot search."""
    source: str  # e.g., "Processes", "Network", "DNS"
    artifact_type: str
    matched_field: str
    matched_value: str
    data: Dict[str, Any]
    relevance: str = "direct"  # direct, indirect


@dataclass
class PivotContext:
    """Complete context from a pivot operation."""
    indicator: str
    indicator_type: PivotType
    results: List[PivotResult] = field(default_factory=list)
    total_matches: int = 0
    sources_searched: int = 0
    related_indicators: Set[str] = field(default_factory=set)


class PivotEngine:
    """
    Engine for pivoting across all forensic artifacts.
    Finds relationships between IPs, hashes, processes, and other indicators.
    """

    # Regex patterns for indicator detection
    IP_PATTERN = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    MD5_PATTERN = re.compile(r'^[a-fA-F0-9]{32}$')
    SHA1_PATTERN = re.compile(r'^[a-fA-F0-9]{40}$')
    SHA256_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')
    DOMAIN_PATTERN = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

    # Data sources configuration
    DATA_SOURCES = [
        ("processes.json", "Processes", ["name", "exe", "cmdline", "sha256", "username", "pid"]),
        ("network_connections.json", "Network", ["laddr", "raddr", "pid", "status"]),
        ("dns_cache.json", "DNS", ["Entry", "Record Name", "Data"]),
        ("recent_files.json", "Files", ["filename", "path", "sha256", "md5"]),
        ("browser_history.json", "Browser", ["url", "title"]),
        ("browser_cookies.json", "Cookies", ["host", "name", "value"]),
        ("firefox_history.json", "Firefox", ["url", "title"]),
        ("registry_autoruns.json", "Registry", ["Key", "Value", "Name", "Data"]),
        ("scheduled_tasks.json", "Tasks", ["TaskName", "Action", "Author"]),
        ("services.json", "Services", ["Name", "BinPath", "StartName"]),
        ("all_events.json", "Events", ["Message", "ProviderName", "UserId"]),
        ("shimcache.json", "Shimcache", ["path"]),
        ("startup_files.json", "Startup", ["Filename", "Path", "Hash"]),
        ("wmi_persistence.json", "WMI", ["Name", "Command", "Query"]),
        ("bits_jobs.json", "BITS", ["DisplayName", "Files", "RemoteUrl"]),
        ("jump_lists.json", "Jump Lists", ["target_path", "app_id"]),
        ("shellbags.json", "Shellbags", ["path"]),
        ("arp_cache.json", "ARP", ["IPAddress", "MACAddress"]),
        ("hosts_file.json", "Hosts", ["IP", "Hostname"]),
        ("usb_history.json", "USB", ["DeviceName", "SerialNumber"]),
        ("installed_software.json", "Software", ["Name", "Publisher", "InstallLocation"]),
        ("user_assist.json", "UserAssist", ["Name", "Path"]),
        ("prefetch_list.json", "Prefetch", ["FileName", "Hash", "FullPath"]),
        ("lnk_files.json", "LNK", ["TargetPath", "Arguments"]),
        ("powershell_history.json", "PowerShell", ["Line", "CommandLine"]),
    ]

    def __init__(self, evidence_folder: str):
        """Initialize pivot engine with evidence folder path."""
        self.evidence_folder = evidence_folder
        self._cache: Dict[str, List[Dict]] = {}

    def detect_indicator_type(self, indicator: str) -> PivotType:
        """Detect the type of indicator based on its format."""
        indicator = indicator.strip()

        # Check for IP
        if self.IP_PATTERN.match(indicator):
            return PivotType.IP

        # Check for hashes
        if self.SHA256_PATTERN.match(indicator):
            return PivotType.HASH
        if self.SHA1_PATTERN.match(indicator):
            return PivotType.HASH
        if self.MD5_PATTERN.match(indicator):
            return PivotType.HASH

        # Check for domain
        if self.DOMAIN_PATTERN.match(indicator) and '.' in indicator:
            return PivotType.DOMAIN

        # Check for file path
        if '\\' in indicator or indicator.endswith('.exe') or indicator.endswith('.dll'):
            return PivotType.FILE

        # Check for username format
        if '\\' in indicator and not indicator.endswith('.exe'):
            parts = indicator.split('\\')
            if len(parts) == 2 and len(parts[0]) < 20 and len(parts[1]) < 50:
                return PivotType.USER

        # Check for registry key
        if indicator.upper().startswith(('HKEY_', 'HKLM\\', 'HKCU\\', 'HKU\\')):
            return PivotType.REGISTRY

        # Default to process/command
        return PivotType.PROCESS

    def _load_data(self, filename: str) -> List[Dict]:
        """Load and cache data from a JSON file."""
        if filename not in self._cache:
            data = load_json(self.evidence_folder, filename)
            self._cache[filename] = data if data else []
        return self._cache[filename]

    def _search_in_dict(self, item: Dict, search_term: str, fields: List[str]) -> Optional[str]:
        """Search for term in dictionary fields. Returns matched field name or None."""
        search_lower = search_term.lower()

        for field in fields:
            value = item.get(field)
            if value:
                value_str = str(value).lower()
                if search_lower in value_str:
                    return field

        # Also search in the entire item as JSON
        item_str = json.dumps(item, default=str).lower()
        if search_lower in item_str:
            return "_json"

        return None

    def pivot(self, indicator: str, max_results: int = 200) -> PivotContext:
        """
        Pivot on an indicator and find all related artifacts.

        Args:
            indicator: The IOC to pivot on (IP, hash, process name, etc.)
            max_results: Maximum results to return per source

        Returns:
            PivotContext with all related artifacts
        """
        indicator = indicator.strip()
        indicator_type = self.detect_indicator_type(indicator)

        context = PivotContext(
            indicator=indicator,
            indicator_type=indicator_type,
            results=[],
            related_indicators=set()
        )

        for filename, source_name, fields in self.DATA_SOURCES:
            data = self._load_data(filename)
            if not data:
                continue

            context.sources_searched += 1
            source_results = []

            for item in data:
                matched_field = self._search_in_dict(item, indicator, fields)
                if matched_field:
                    result = PivotResult(
                        source=source_name,
                        artifact_type=filename.replace('.json', ''),
                        matched_field=matched_field,
                        matched_value=str(item.get(matched_field, indicator))[:200],
                        data=item
                    )
                    source_results.append(result)

                    # Extract related indicators for deeper pivoting
                    self._extract_related_indicators(item, context.related_indicators, indicator)

                    if len(source_results) >= max_results:
                        break

            context.results.extend(source_results)
            context.total_matches += len(source_results)

        # Remove the original indicator from related
        context.related_indicators.discard(indicator)
        context.related_indicators.discard(indicator.lower())

        return context

    def _extract_related_indicators(self, item: Dict, related: Set[str], exclude: str):
        """Extract related indicators from an artifact for deeper pivoting."""
        exclude_lower = exclude.lower()

        # Extract IPs
        for field in ['laddr', 'raddr', 'IPAddress', 'remote_ip', 'ip']:
            value = item.get(field)
            if value:
                # Handle format like "192.168.1.1:443"
                ip = str(value).split(':')[0]
                if self.IP_PATTERN.match(ip) and ip.lower() != exclude_lower:
                    if ip not in ['0.0.0.0', '127.0.0.1', '::']:
                        related.add(ip)

        # Extract hashes
        for field in ['sha256', 'sha1', 'md5', 'Hash']:
            value = item.get(field)
            if value and str(value).lower() != exclude_lower:
                if len(str(value)) in [32, 40, 64] and str(value).replace('-', '').isalnum():
                    related.add(str(value))

        # Extract domains from URLs
        for field in ['url', 'host', 'domain', 'Entry', 'Data']:
            value = item.get(field)
            if value:
                # Extract domain from URL
                match = re.search(r'(?:https?://)?([a-zA-Z0-9.-]+)', str(value))
                if match:
                    domain = match.group(1)
                    if self.DOMAIN_PATTERN.match(domain) and domain.lower() != exclude_lower:
                        related.add(domain)

        # Extract process PIDs
        pid = item.get('pid')
        if pid and str(pid) != exclude:
            related.add(str(pid))

    def get_related_processes(self, indicator: str) -> List[Dict]:
        """Find processes related to an indicator."""
        results = []
        processes = self._load_data("processes.json")
        network = self._load_data("network_connections.json")

        # If it's an IP, find processes with connections to that IP
        if self.IP_PATTERN.match(indicator):
            connected_pids = set()
            for conn in network:
                raddr = str(conn.get('raddr', ''))
                if indicator in raddr:
                    pid = conn.get('pid')
                    if pid:
                        connected_pids.add(pid)

            for proc in processes:
                if proc.get('pid') in connected_pids:
                    results.append(proc)

        # Otherwise, search in process fields
        else:
            indicator_lower = indicator.lower()
            for proc in processes:
                if (indicator_lower in str(proc.get('name', '')).lower() or
                    indicator_lower in str(proc.get('cmdline', '')).lower() or
                    indicator_lower in str(proc.get('exe', '')).lower() or
                    indicator_lower in str(proc.get('sha256', '')).lower()):
                    results.append(proc)

        return results

    def get_network_connections(self, indicator: str) -> List[Dict]:
        """Find network connections related to an indicator."""
        results = []
        network = self._load_data("network_connections.json")
        processes = self._load_data("processes.json")

        # Build PID -> process name map
        pid_map = {p.get('pid'): p.get('name', 'Unknown') for p in processes}

        indicator_lower = indicator.lower()

        for conn in network:
            matched = False
            if (indicator_lower in str(conn.get('laddr', '')).lower() or
                indicator_lower in str(conn.get('raddr', '')).lower()):
                matched = True

            # Also match by process name
            pid = conn.get('pid')
            if pid and pid in pid_map:
                if indicator_lower in pid_map[pid].lower():
                    matched = True

            if matched:
                # Enrich with process name
                conn_copy = conn.copy()
                if pid and pid in pid_map:
                    conn_copy['process_name'] = pid_map[pid]
                results.append(conn_copy)

        return results

    def get_dns_entries(self, indicator: str) -> List[Dict]:
        """Find DNS entries related to an indicator."""
        results = []
        dns = self._load_data("dns_cache.json")
        indicator_lower = indicator.lower()

        for entry in dns:
            if (indicator_lower in str(entry.get('Entry', '')).lower() or
                indicator_lower in str(entry.get('Record Name', '')).lower() or
                indicator_lower in str(entry.get('Data', '')).lower()):
                results.append(entry)

        return results

    def get_file_references(self, indicator: str) -> List[Dict]:
        """Find file references related to an indicator (files, LNK, prefetch, etc.)."""
        results = []
        indicator_lower = indicator.lower()

        for filename in ['recent_files.json', 'lnk_files.json', 'prefetch_list.json',
                         'jump_lists.json', 'shellbags.json', 'shimcache.json']:
            data = self._load_data(filename)
            source = filename.replace('.json', '').replace('_', ' ').title()

            for item in data:
                item_str = json.dumps(item, default=str).lower()
                if indicator_lower in item_str:
                    item_copy = item.copy()
                    item_copy['_source'] = source
                    results.append(item_copy)

        return results

    def get_registry_entries(self, indicator: str) -> List[Dict]:
        """Find registry entries related to an indicator."""
        results = []
        indicator_lower = indicator.lower()

        for filename in ['registry_autoruns.json', 'services.json']:
            data = self._load_data(filename)
            source = filename.replace('.json', '').replace('_', ' ').title()

            for item in data:
                item_str = json.dumps(item, default=str).lower()
                if indicator_lower in item_str:
                    item_copy = item.copy()
                    item_copy['_source'] = source
                    results.append(item_copy)

        return results

    def get_timeline_events(self, indicator: str) -> List[Dict]:
        """Find timeline events related to an indicator."""
        results = []
        events = self._load_data("all_events.json")
        indicator_lower = indicator.lower()

        for event in events:
            message = str(event.get('Message', '')).lower()
            if indicator_lower in message:
                results.append(event)

        return results[:100]  # Limit events

    def build_relationship_graph(self, indicator: str) -> Dict:
        """
        Build a relationship graph showing connections between artifacts.
        Returns a structure suitable for visualization.
        """
        context = self.pivot(indicator, max_results=50)

        nodes = [{"id": indicator, "type": context.indicator_type.value, "primary": True}]
        edges = []

        # Add related indicators as nodes
        for related in list(context.related_indicators)[:20]:
            rel_type = self.detect_indicator_type(related)
            nodes.append({"id": related, "type": rel_type.value, "primary": False})
            edges.append({"from": indicator, "to": related, "type": "related"})

        # Add source counts
        source_counts = {}
        for result in context.results:
            source = result.source
            source_counts[source] = source_counts.get(source, 0) + 1

        return {
            "nodes": nodes,
            "edges": edges,
            "source_counts": source_counts,
            "total_matches": context.total_matches
        }

    def clear_cache(self):
        """Clear the data cache."""
        self._cache = {}
