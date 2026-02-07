"""
Sigma Rule Detection Engine.

Parses and matches Sigma rules against collected evidence.
Supports process, network, and event log detection.

Sigma rule format: https://github.com/SigmaHQ/sigma
"""
import os
import re
import fnmatch
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from pathlib import Path

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class SigmaMatch:
    """Represents a Sigma rule match."""
    rule_name: str
    rule_id: str
    description: str
    severity: str
    mitre_techniques: List[str]
    matched_field: str
    matched_value: str
    evidence: Dict[str, Any]
    tags: List[str] = field(default_factory=list)


@dataclass
class SigmaRule:
    """Parsed Sigma rule."""
    id: str
    name: str
    description: str
    status: str
    level: str  # critical, high, medium, low, informational
    logsource: Dict[str, str]
    detection: Dict[str, Any]
    mitre_techniques: List[str]
    tags: List[str]
    author: str
    file_path: str

    @property
    def severity(self) -> str:
        """Map Sigma level to our severity."""
        level_map = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'informational': 'info'
        }
        return level_map.get(self.level.lower(), 'medium')


class SigmaEngine:
    """
    Engine for loading and matching Sigma rules.

    Supports:
    - Process creation rules (logsource.category: process_creation)
    - Network connection rules (logsource.category: network_connection)
    - Windows event log rules (logsource.product: windows)
    """

    # Field mappings from Sigma to our evidence fields
    PROCESS_FIELD_MAP = {
        'Image': 'exe',
        'OriginalFileName': 'name',
        'CommandLine': 'cmdline',
        'ParentImage': 'parent_exe',
        'ParentCommandLine': 'parent_cmdline',
        'User': 'username',
        'ProcessId': 'pid',
        'ParentProcessId': 'parent_pid',
        'Company': 'Publisher',
        'Product': 'Product',
        'Description': 'Description',
    }

    NETWORK_FIELD_MAP = {
        'DestinationIp': 'remote_ip',
        'DestinationPort': 'remote_port',
        'DestinationHostname': 'remote_host',
        'SourceIp': 'local_ip',
        'SourcePort': 'local_port',
        'Protocol': 'protocol',
    }

    EVENT_FIELD_MAP = {
        'EventID': 'Id',
        'Provider_Name': 'ProviderName',
        'Channel': 'LogName',
    }

    def __init__(self, rules_dir: str = None):
        """
        Initialize the Sigma engine.

        Args:
            rules_dir: Directory containing Sigma YAML rules
        """
        self.rules: List[SigmaRule] = []
        self.matches: List[SigmaMatch] = []
        self._loaded_files: Set[str] = set()

        if not YAML_AVAILABLE:
            logger.warning("PyYAML not installed. Sigma rules disabled.")
            return

        if rules_dir and os.path.exists(rules_dir):
            self.load_rules_from_directory(rules_dir)

    def load_rules_from_directory(self, directory: str) -> int:
        """
        Load all Sigma rules from a directory.

        Args:
            directory: Path to directory containing .yml/.yaml files

        Returns:
            Number of rules loaded
        """
        if not YAML_AVAILABLE:
            return 0

        count = 0
        path = Path(directory)

        for yaml_file in path.glob("**/*.yml"):
            if self._load_rule_file(str(yaml_file)):
                count += 1

        for yaml_file in path.glob("**/*.yaml"):
            if self._load_rule_file(str(yaml_file)):
                count += 1

        logger.info("Loaded %d Sigma rules from %s", count, directory)
        return count

    def _load_rule_file(self, file_path: str) -> bool:
        """Load a single Sigma rule file (supports multi-document YAML)."""
        if file_path in self._loaded_files:
            return False

        loaded_any = False
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Use safe_load_all to support multiple YAML documents in one file
                documents = list(yaml.safe_load_all(f))

            for data in documents:
                if not data or not isinstance(data, dict):
                    continue

                # Skip if no detection section
                if 'detection' not in data:
                    continue

                # Extract MITRE techniques from tags
                tags = data.get('tags', []) or []
                mitre_techniques = []
                for tag in tags:
                    if isinstance(tag, str) and tag.startswith('attack.t'):
                        tech_id = tag.replace('attack.', '').upper()
                        mitre_techniques.append(tech_id)

                rule = SigmaRule(
                    id=data.get('id', os.path.basename(file_path)),
                    name=data.get('title', 'Unknown Rule'),
                    description=data.get('description', ''),
                    status=data.get('status', 'experimental'),
                    level=data.get('level', 'medium'),
                    logsource=data.get('logsource', {}),
                    detection=data.get('detection', {}),
                    mitre_techniques=mitre_techniques,
                    tags=tags,
                    author=data.get('author', 'Unknown'),
                    file_path=file_path
                )

                self.rules.append(rule)
                loaded_any = True

            if loaded_any:
                self._loaded_files.add(file_path)
            return loaded_any

        except Exception as e:
            logger.debug("Failed to load Sigma rule %s: %s", file_path, str(e))
            return False

    def match_process(self, process: Dict[str, Any]) -> List[SigmaMatch]:
        """
        Match a process against all applicable Sigma rules.

        Args:
            process: Process data dictionary

        Returns:
            List of matches
        """
        matches = []

        for rule in self.rules:
            logsource = rule.logsource
            category = logsource.get('category', '').lower()
            product = logsource.get('product', '').lower()

            # Only match process creation rules
            if category not in ('process_creation', 'process_access', ''):
                continue
            if product and product not in ('windows', ''):
                continue

            match = self._match_detection(rule, process, self.PROCESS_FIELD_MAP)
            if match:
                matches.append(match)
                self.matches.append(match)

        return matches

    def match_network(self, connection: Dict[str, Any]) -> List[SigmaMatch]:
        """
        Match a network connection against Sigma rules.

        Args:
            connection: Network connection data

        Returns:
            List of matches
        """
        matches = []

        for rule in self.rules:
            logsource = rule.logsource
            category = logsource.get('category', '').lower()

            if category not in ('network_connection', 'firewall', ''):
                continue

            match = self._match_detection(rule, connection, self.NETWORK_FIELD_MAP)
            if match:
                matches.append(match)
                self.matches.append(match)

        return matches

    def match_event(self, event: Dict[str, Any]) -> List[SigmaMatch]:
        """
        Match an event log entry against Sigma rules.

        Args:
            event: Event log data

        Returns:
            List of matches
        """
        matches = []

        for rule in self.rules:
            logsource = rule.logsource
            product = logsource.get('product', '').lower()

            if product and product != 'windows':
                continue

            match = self._match_detection(rule, event, self.EVENT_FIELD_MAP)
            if match:
                matches.append(match)
                self.matches.append(match)

        return matches

    def _match_detection(self, rule: SigmaRule, data: Dict[str, Any],
                         field_map: Dict[str, str]) -> Optional[SigmaMatch]:
        """
        Check if data matches a rule's detection logic.

        Args:
            rule: Sigma rule to match
            data: Evidence data
            field_map: Mapping from Sigma fields to evidence fields

        Returns:
            SigmaMatch if matched, None otherwise
        """
        detection = rule.detection
        condition = detection.get('condition', '')

        # Get all selection blocks
        selections = {}
        for key, value in detection.items():
            if key != 'condition' and isinstance(value, (dict, list)):
                selections[key] = value

        if not selections:
            return None

        # Evaluate each selection
        selection_results = {}
        matched_info = {'field': '', 'value': ''}

        for sel_name, sel_criteria in selections.items():
            result, match_info = self._evaluate_selection(sel_criteria, data, field_map)
            selection_results[sel_name] = result
            if result and match_info:
                matched_info = match_info

        # Evaluate condition
        if self._evaluate_condition(condition, selection_results):
            return SigmaMatch(
                rule_name=rule.name,
                rule_id=rule.id,
                description=rule.description,
                severity=rule.severity,
                mitre_techniques=rule.mitre_techniques,
                matched_field=matched_info.get('field', ''),
                matched_value=matched_info.get('value', ''),
                evidence=data,
                tags=rule.tags
            )

        return None

    def _evaluate_selection(self, criteria: Any, data: Dict[str, Any],
                           field_map: Dict[str, str]) -> tuple:
        """
        Evaluate a selection block against data.

        Returns:
            Tuple of (matched: bool, match_info: dict)
        """
        match_info = {}

        if isinstance(criteria, dict):
            # All conditions must match (AND)
            for sigma_field, expected in criteria.items():
                # Handle field modifiers (e.g., CommandLine|contains)
                field_parts = sigma_field.split('|')
                base_field = field_parts[0]
                modifiers = field_parts[1:] if len(field_parts) > 1 else []

                # Map to our field name
                our_field = field_map.get(base_field, base_field.lower())
                actual_value = data.get(our_field, '')

                if actual_value is None:
                    actual_value = ''
                actual_value = str(actual_value).lower()

                if not self._match_value(actual_value, expected, modifiers):
                    return False, {}

                match_info = {'field': our_field, 'value': str(data.get(our_field, ''))[:100]}

            return True, match_info

        elif isinstance(criteria, list):
            # Any condition can match (OR)
            for item in criteria:
                result, info = self._evaluate_selection(item, data, field_map)
                if result:
                    return True, info
            return False, {}

        return False, {}

    def _match_value(self, actual: str, expected: Any, modifiers: List[str]) -> bool:
        """
        Check if actual value matches expected with modifiers.

        Modifiers:
        - contains: substring match
        - startswith: prefix match
        - endswith: suffix match
        - re: regex match
        - all: all values must match (for lists)
        """
        if expected is None:
            return actual == ''

        # Handle list of expected values (OR)
        if isinstance(expected, list):
            if 'all' in modifiers:
                return all(self._match_single(actual, str(e).lower(), modifiers) for e in expected)
            return any(self._match_single(actual, str(e).lower(), modifiers) for e in expected)

        return self._match_single(actual, str(expected).lower(), modifiers)

    def _match_single(self, actual: str, expected: str, modifiers: List[str]) -> bool:
        """Match a single value with modifiers."""
        # Handle wildcards in expected value
        if '*' in expected or '?' in expected:
            # Convert to regex
            pattern = expected.replace('*', '.*').replace('?', '.')
            try:
                return bool(re.search(pattern, actual, re.IGNORECASE))
            except re.error:
                return False

        if 'contains' in modifiers:
            return expected in actual
        elif 'startswith' in modifiers:
            return actual.startswith(expected)
        elif 'endswith' in modifiers:
            return actual.endswith(expected)
        elif 're' in modifiers:
            try:
                return bool(re.search(expected, actual, re.IGNORECASE))
            except re.error:
                return False
        else:
            # Exact match (case-insensitive)
            return actual == expected

    def _evaluate_condition(self, condition: str, results: Dict[str, bool]) -> bool:
        """
        Evaluate the condition expression.

        Supports: and, or, not, 1 of, all of
        """
        if not condition:
            # Default: any selection matches
            return any(results.values())

        condition = condition.lower().strip()

        # Handle "1 of selection*" or "all of selection*"
        if condition.startswith('1 of ') or condition.startswith('any of '):
            pattern = condition.split(' of ')[-1].replace('*', '')
            matching = [r for name, r in results.items() if name.startswith(pattern)]
            return any(matching)

        if condition.startswith('all of '):
            pattern = condition.split(' of ')[-1].replace('*', '')
            matching = [r for name, r in results.items() if name.startswith(pattern)]
            return all(matching) if matching else False

        # Simple conditions
        if ' and ' in condition:
            parts = condition.split(' and ')
            return all(self._eval_single_condition(p.strip(), results) for p in parts)

        if ' or ' in condition:
            parts = condition.split(' or ')
            return any(self._eval_single_condition(p.strip(), results) for p in parts)

        return self._eval_single_condition(condition, results)

    def _eval_single_condition(self, cond: str, results: Dict[str, bool]) -> bool:
        """Evaluate a single condition term."""
        cond = cond.strip()

        if cond.startswith('not '):
            inner = cond[4:].strip()
            return not results.get(inner, False)

        return results.get(cond, False)

    def get_all_matches(self) -> List[SigmaMatch]:
        """Get all matches from this session."""
        return self.matches

    def get_matches_by_severity(self, severity: str) -> List[SigmaMatch]:
        """Get matches filtered by severity."""
        return [m for m in self.matches if m.severity == severity]

    def reset(self):
        """Clear all matches (but keep rules loaded)."""
        self.matches = []

    def get_stats(self) -> Dict[str, int]:
        """Get statistics about loaded rules and matches."""
        return {
            'rules_loaded': len(self.rules),
            'total_matches': len(self.matches),
            'critical_matches': len(self.get_matches_by_severity('critical')),
            'high_matches': len(self.get_matches_by_severity('high')),
            'medium_matches': len(self.get_matches_by_severity('medium')),
            'low_matches': len(self.get_matches_by_severity('low')),
        }
