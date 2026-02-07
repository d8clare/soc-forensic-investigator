"""
YARA Rule Detection Engine.

Scans files for malware signatures and suspicious patterns.
Supports scanning of collected evidence files.
"""
import os
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from pathlib import Path

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class YaraMatch:
    """Represents a YARA rule match."""
    rule_name: str
    rule_namespace: str
    description: str
    severity: str
    mitre_techniques: List[str]
    file_path: str
    file_name: str
    matched_strings: List[str]
    tags: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)


class YaraEngine:
    """
    Engine for loading and matching YARA rules against files.

    Supports:
    - Scanning files from evidence folders
    - Multiple rule files/directories
    - Metadata extraction for severity and MITRE mapping
    """

    # File extensions to scan
    SCANNABLE_EXTENSIONS = {
        # Executables
        '.exe', '.dll', '.sys', '.scr', '.com', '.pif',
        # Scripts
        '.ps1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh',
        '.hta', '.py', '.pyw', '.rb', '.pl', '.sh',
        # Documents (can contain macros)
        '.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm', '.ppt', '.pptx', '.pptm',
        '.pdf', '.rtf',
        # Archives
        '.zip', '.rar', '.7z', '.cab',
        # Web
        '.html', '.htm', '.php', '.asp', '.aspx', '.jsp',
        # Other
        '.lnk', '.url', '.iso', '.img',
    }

    # Maximum file size to scan (10 MB)
    MAX_FILE_SIZE = 10 * 1024 * 1024

    def __init__(self, rules_dir: str = None):
        """
        Initialize the YARA engine.

        Args:
            rules_dir: Directory containing YARA rule files
        """
        self.rules = None
        self.matches: List[YaraMatch] = []
        self.rules_count = 0
        self._loaded_files: Set[str] = set()

        if not YARA_AVAILABLE:
            logger.warning("yara-python not installed. YARA scanning disabled.")
            return

        if rules_dir and os.path.exists(rules_dir):
            self.load_rules_from_directory(rules_dir)

    def load_rules_from_directory(self, directory: str) -> int:
        """
        Load and compile all YARA rules from a directory.

        Args:
            directory: Path to directory containing .yar/.yara files

        Returns:
            Number of rule files loaded
        """
        if not YARA_AVAILABLE:
            return 0

        path = Path(directory)
        rule_files = {}
        count = 0

        # Collect all rule files
        for pattern in ['*.yar', '*.yara', '*.rules']:
            for rule_file in path.glob(f"**/{pattern}"):
                namespace = rule_file.stem
                # Ensure unique namespace
                if namespace in rule_files:
                    namespace = f"{namespace}_{count}"
                rule_files[namespace] = str(rule_file)
                count += 1

        if not rule_files:
            logger.info("No YARA rules found in %s", directory)
            return 0

        try:
            self.rules = yara.compile(filepaths=rule_files)
            self.rules_count = count
            logger.info("Compiled %d YARA rule files from %s", count, directory)
            return count
        except yara.Error as e:
            logger.error("Failed to compile YARA rules: %s", str(e))
            # Try loading rules one by one to identify problematic files
            self._load_rules_individually(rule_files)
            return self.rules_count

    def _load_rules_individually(self, rule_files: Dict[str, str]):
        """Load rules one by one, skipping problematic files."""
        valid_rules = {}
        for namespace, filepath in rule_files.items():
            try:
                # Test compile individual file
                yara.compile(filepath=filepath)
                valid_rules[namespace] = filepath
            except yara.Error as e:
                logger.warning("Skipping invalid YARA rule %s: %s", filepath, str(e))

        if valid_rules:
            try:
                self.rules = yara.compile(filepaths=valid_rules)
                self.rules_count = len(valid_rules)
            except yara.Error:
                self.rules = None
                self.rules_count = 0

    def scan_file(self, file_path: str) -> List[YaraMatch]:
        """
        Scan a single file with YARA rules.

        Args:
            file_path: Path to file to scan

        Returns:
            List of matches
        """
        if not YARA_AVAILABLE or not self.rules:
            return []

        if not os.path.exists(file_path):
            return []

        # Check file size
        try:
            file_size = os.path.getsize(file_path)
            if file_size > self.MAX_FILE_SIZE:
                logger.debug("Skipping large file: %s (%d bytes)", file_path, file_size)
                return []
            if file_size == 0:
                return []
        except OSError:
            return []

        matches = []
        try:
            yara_matches = self.rules.match(file_path, timeout=5)

            for match in yara_matches:
                # Extract metadata
                meta = {str(k): str(v) for k, v in match.meta.items()} if match.meta else {}

                # Determine severity from metadata
                severity = self._get_severity(meta, match.tags)

                # Extract MITRE techniques from metadata or tags
                mitre_techniques = self._extract_mitre(meta, match.tags)

                # Get matched strings (limit to first 10)
                matched_strings = []
                if match.strings:
                    for string_match in match.strings[:10]:
                        try:
                            # yara-python 4.x format
                            if hasattr(string_match, 'instances'):
                                for instance in string_match.instances[:3]:
                                    matched_strings.append(f"{string_match.identifier}: {instance.matched_data[:50]}")
                            else:
                                # Older format
                                matched_strings.append(str(string_match)[:100])
                        except Exception:
                            matched_strings.append(str(string_match.identifier))

                yara_match = YaraMatch(
                    rule_name=match.rule,
                    rule_namespace=match.namespace,
                    description=meta.get('description', meta.get('desc', '')),
                    severity=severity,
                    mitre_techniques=mitre_techniques,
                    file_path=file_path,
                    file_name=os.path.basename(file_path),
                    matched_strings=matched_strings,
                    tags=list(match.tags) if match.tags else [],
                    meta=meta
                )

                matches.append(yara_match)
                self.matches.append(yara_match)

        except yara.Error as e:
            logger.debug("YARA scan error for %s: %s", file_path, str(e))
        except Exception as e:
            logger.debug("Error scanning %s: %s", file_path, str(e))

        return matches

    def scan_directory(self, directory: str, recursive: bool = True, max_files: int = 500) -> List[YaraMatch]:
        """
        Scan all scannable files in a directory.

        Args:
            directory: Directory to scan
            recursive: Whether to scan subdirectories
            max_files: Maximum number of files to scan

        Returns:
            List of all matches
        """
        if not YARA_AVAILABLE or not self.rules:
            return []

        all_matches = []
        path = Path(directory)
        files_scanned = 0

        pattern = "**/*" if recursive else "*"
        for file_path in path.glob(pattern):
            if files_scanned >= max_files:
                break

            if not file_path.is_file():
                continue

            # Check extension
            if file_path.suffix.lower() not in self.SCANNABLE_EXTENSIONS:
                continue

            matches = self.scan_file(str(file_path))
            all_matches.extend(matches)
            files_scanned += 1

        return all_matches

    def scan_evidence_files(self, evidence_folder: str, files_data: List[Dict]) -> List[YaraMatch]:
        """
        Scan files referenced in evidence data.

        Args:
            evidence_folder: Base evidence folder
            files_data: List of file dictionaries from recent_files.json

        Returns:
            List of matches
        """
        if not YARA_AVAILABLE or not self.rules:
            return []

        all_matches = []
        scanned = set()

        for file_info in files_data:
            file_path = file_info.get('path', '')
            if not file_path or file_path in scanned:
                continue

            scanned.add(file_path)

            # Check extension
            ext = Path(file_path).suffix.lower()
            if ext not in self.SCANNABLE_EXTENSIONS:
                continue

            matches = self.scan_file(file_path)
            all_matches.extend(matches)

        return all_matches

    def _get_severity(self, meta: Dict[str, str], tags: List[str]) -> str:
        """Determine severity from rule metadata and tags."""
        # Check metadata fields
        for field in ['severity', 'threat_level', 'level']:
            if field in meta:
                level = meta[field].lower()
                if level in ('critical', 'high', 'medium', 'low'):
                    return level

        # Check tags
        tags_lower = [t.lower() for t in tags]
        if 'critical' in tags_lower or 'apt' in tags_lower:
            return 'critical'
        if 'high' in tags_lower or 'malware' in tags_lower or 'ransomware' in tags_lower:
            return 'high'
        if 'medium' in tags_lower or 'suspicious' in tags_lower:
            return 'medium'
        if 'low' in tags_lower or 'pup' in tags_lower:
            return 'low'

        # Default based on certain keywords in rule name
        return 'high'  # Default to high for YARA matches

    def _extract_mitre(self, meta: Dict[str, str], tags: List[str]) -> List[str]:
        """Extract MITRE ATT&CK techniques from metadata and tags."""
        techniques = []

        # Check metadata
        for field in ['mitre', 'mitre_attack', 'attack', 'technique']:
            if field in meta:
                value = meta[field]
                # Parse technique IDs (T1xxx format)
                import re
                found = re.findall(r'T\d{4}(?:\.\d{3})?', value.upper())
                techniques.extend(found)

        # Check tags
        for tag in tags:
            tag_upper = tag.upper()
            if tag_upper.startswith('T1'):
                techniques.append(tag_upper)
            elif tag_upper.startswith('ATTACK.T'):
                techniques.append(tag_upper.replace('ATTACK.', ''))

        return list(set(techniques))

    def get_all_matches(self) -> List[YaraMatch]:
        """Get all matches from this session."""
        return self.matches

    def get_matches_by_severity(self, severity: str) -> List[YaraMatch]:
        """Get matches filtered by severity."""
        return [m for m in self.matches if m.severity == severity]

    def reset(self):
        """Clear all matches (but keep rules loaded)."""
        self.matches = []

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about loaded rules and matches."""
        files_matched = len(set(m.file_path for m in self.matches))
        return {
            'rules_loaded': self.rules_count,
            'total_matches': len(self.matches),
            'files_matched': files_matched,
            'critical_matches': len(self.get_matches_by_severity('critical')),
            'high_matches': len(self.get_matches_by_severity('high')),
            'medium_matches': len(self.get_matches_by_severity('medium')),
            'low_matches': len(self.get_matches_by_severity('low')),
        }

    def is_available(self) -> bool:
        """Check if YARA scanning is available."""
        return YARA_AVAILABLE and self.rules is not None
