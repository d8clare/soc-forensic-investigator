"""
Forensic Audit Trail Module.
Provides persistent, tamper-evident logging of all forensic actions.
"""
import os
import json
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    """Single audit log entry."""
    sequence: int
    timestamp: str
    action: str
    category: str  # 'auth', 'evidence', 'finding', 'export', 'config'
    analyst_id: str
    hostname: str
    session_id: str
    details: Dict
    previous_hash: str  # Hash of previous entry for chain integrity


class AuditTrail:
    """
    Persistent, tamper-evident audit trail for forensic investigations.

    Features:
    - Persistent storage (survives session restarts)
    - Hash chain for tamper detection
    - Structured logging with categories
    - Export capability for legal proceedings
    """

    AUDIT_DIR = ".forensic_audit"
    AUDIT_FILE = "audit_trail.jsonl"  # JSON Lines format for append-only

    def __init__(self, base_dir: str = None, analyst_id: str = "unknown", session_id: str = None):
        """
        Initialize audit trail.

        Args:
            base_dir: Base directory for audit files (default: user's home)
            analyst_id: Identifier for current analyst
            session_id: Unique session identifier
        """
        if base_dir is None:
            base_dir = str(Path.home())

        self.audit_dir = os.path.join(base_dir, self.AUDIT_DIR)
        self.audit_file = os.path.join(self.audit_dir, self.AUDIT_FILE)
        self.analyst_id = analyst_id
        self.hostname = os.environ.get('COMPUTERNAME', os.environ.get('HOSTNAME', 'unknown'))
        self.session_id = session_id or self._generate_session_id()

        # Ensure audit directory exists
        os.makedirs(self.audit_dir, exist_ok=True)

        # Get current sequence number and last hash
        self.sequence, self.last_hash = self._get_chain_state()

    def _generate_session_id(self) -> str:
        """Generate unique session ID."""
        import uuid
        return str(uuid.uuid4())[:8]

    def _get_chain_state(self) -> tuple:
        """Get current sequence number and last hash from existing log."""
        if not os.path.exists(self.audit_file):
            return 0, "GENESIS"

        sequence = 0
        last_hash = "GENESIS"

        try:
            with open(self.audit_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        entry = json.loads(line)
                        sequence = entry.get("sequence", 0)
                        # Calculate hash of this entry for chain
                        last_hash = self._hash_entry(entry)
        except (IOError, json.JSONDecodeError) as e:
            logger.warning("Error reading audit trail: %s", e)

        return sequence, last_hash

    def _hash_entry(self, entry: Dict) -> str:
        """Calculate hash of an entry (excluding previous_hash to avoid recursion)."""
        # Create deterministic string representation
        hash_data = json.dumps({
            k: v for k, v in sorted(entry.items())
            if k != "previous_hash"
        }, sort_keys=True)
        return hashlib.sha256(hash_data.encode()).hexdigest()[:16]

    def log(self, action: str, category: str, details: Dict = None) -> AuditEntry:
        """
        Log an audit event.

        Args:
            action: Description of the action
            category: Category ('auth', 'evidence', 'finding', 'export', 'config')
            details: Additional details dictionary

        Returns:
            The created AuditEntry
        """
        self.sequence += 1

        entry = AuditEntry(
            sequence=self.sequence,
            timestamp=datetime.utcnow().isoformat() + "Z",
            action=action,
            category=category,
            analyst_id=self.analyst_id,
            hostname=self.hostname,
            session_id=self.session_id,
            details=details or {},
            previous_hash=self.last_hash
        )

        entry_dict = asdict(entry)

        # Write to file (append)
        try:
            with open(self.audit_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry_dict) + "\n")
            self.last_hash = self._hash_entry(entry_dict)
        except IOError as e:
            logger.error("Failed to write audit entry: %s", e)

        return entry

    # Convenience methods for common actions
    def log_auth(self, action: str, success: bool, details: Dict = None):
        """Log authentication event."""
        self.log(action, "auth", {
            "success": success,
            **(details or {})
        })

    def log_evidence_access(self, evidence_folder: str, files_accessed: List[str] = None):
        """Log evidence access."""
        self.log("evidence_loaded", "evidence", {
            "folder": os.path.basename(evidence_folder),
            "files": files_accessed or [],
            "file_count": len(files_accessed) if files_accessed else 0
        })

    def log_finding_generated(self, finding_count: int, critical_count: int, evidence_folder: str):
        """Log findings generation."""
        self.log("findings_generated", "finding", {
            "total": finding_count,
            "critical": critical_count,
            "evidence_folder": os.path.basename(evidence_folder)
        })

    def log_export(self, export_type: str, filename: str, record_count: int):
        """Log data export."""
        self.log("data_exported", "export", {
            "type": export_type,
            "filename": filename,
            "records": record_count
        })

    def log_tab_access(self, tab_name: str, evidence_folder: str):
        """Log tab/page access."""
        self.log("tab_viewed", "evidence", {
            "tab": tab_name,
            "evidence_folder": os.path.basename(evidence_folder)
        })

    def log_search(self, query: str, results_count: int):
        """Log search action."""
        self.log("search_performed", "evidence", {
            "query": query[:100],  # Truncate for privacy
            "results": results_count
        })

    def log_config_change(self, setting: str, old_value: str, new_value: str):
        """Log configuration change."""
        self.log("config_changed", "config", {
            "setting": setting,
            "old": old_value,
            "new": new_value
        })

    def verify_chain(self) -> tuple:
        """
        Verify the integrity of the audit chain.

        Returns:
            Tuple of (is_valid, list of violations)
        """
        if not os.path.exists(self.audit_file):
            return True, []

        violations = []
        expected_hash = "GENESIS"
        expected_sequence = 0

        try:
            with open(self.audit_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if not line.strip():
                        continue

                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        violations.append(f"Line {line_num}: Invalid JSON")
                        continue

                    # Check sequence
                    expected_sequence += 1
                    if entry.get("sequence") != expected_sequence:
                        violations.append(
                            f"Line {line_num}: Sequence mismatch (expected {expected_sequence}, got {entry.get('sequence')})"
                        )

                    # Check hash chain
                    if entry.get("previous_hash") != expected_hash:
                        violations.append(
                            f"Line {line_num}: Hash chain broken (expected {expected_hash}, got {entry.get('previous_hash')})"
                        )

                    expected_hash = self._hash_entry(entry)

        except IOError as e:
            violations.append(f"Error reading audit file: {e}")

        return len(violations) == 0, violations

    def get_entries(self, category: str = None, limit: int = 100) -> List[Dict]:
        """
        Get audit entries.

        Args:
            category: Filter by category (optional)
            limit: Maximum entries to return

        Returns:
            List of entry dictionaries
        """
        entries = []

        if not os.path.exists(self.audit_file):
            return entries

        try:
            with open(self.audit_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        entry = json.loads(line)
                        if category is None or entry.get("category") == category:
                            entries.append(entry)
        except (IOError, json.JSONDecodeError) as e:
            logger.error("Error reading audit entries: %s", e)

        # Return most recent entries
        return entries[-limit:]

    def get_session_entries(self) -> List[Dict]:
        """Get entries for current session only."""
        entries = []

        if not os.path.exists(self.audit_file):
            return entries

        try:
            with open(self.audit_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        entry = json.loads(line)
                        if entry.get("session_id") == self.session_id:
                            entries.append(entry)
        except (IOError, json.JSONDecodeError):
            pass

        return entries

    def export_audit_report(self, start_date: str = None, end_date: str = None) -> str:
        """
        Export audit trail as JSON report.

        Args:
            start_date: Filter start (ISO format)
            end_date: Filter end (ISO format)

        Returns:
            JSON string
        """
        entries = self.get_entries(limit=10000)

        # Filter by date if specified
        if start_date or end_date:
            filtered = []
            for e in entries:
                ts = e.get("timestamp", "")
                if start_date and ts < start_date:
                    continue
                if end_date and ts > end_date:
                    continue
                filtered.append(e)
            entries = filtered

        is_valid, violations = self.verify_chain()

        report = {
            "report_generated": datetime.utcnow().isoformat() + "Z",
            "chain_integrity": {
                "valid": is_valid,
                "violations": violations
            },
            "entry_count": len(entries),
            "date_range": {
                "start": entries[0]["timestamp"] if entries else None,
                "end": entries[-1]["timestamp"] if entries else None
            },
            "entries": entries
        }

        return json.dumps(report, indent=2)

    def get_summary(self) -> Dict:
        """Get summary statistics of audit trail."""
        entries = self.get_entries(limit=10000)

        categories = {}
        analysts = set()
        sessions = set()

        for e in entries:
            cat = e.get("category", "unknown")
            categories[cat] = categories.get(cat, 0) + 1
            analysts.add(e.get("analyst_id", "unknown"))
            sessions.add(e.get("session_id", "unknown"))

        is_valid, violations = self.verify_chain()

        return {
            "total_entries": len(entries),
            "categories": categories,
            "unique_analysts": len(analysts),
            "unique_sessions": len(sessions),
            "chain_valid": is_valid,
            "violations": len(violations),
            "first_entry": entries[0]["timestamp"] if entries else None,
            "last_entry": entries[-1]["timestamp"] if entries else None
        }


# Global audit trail instance
_audit_trail: Optional[AuditTrail] = None


def get_audit_trail(analyst_id: str = "unknown") -> AuditTrail:
    """Get or create global audit trail instance."""
    global _audit_trail
    if _audit_trail is None:
        _audit_trail = AuditTrail(analyst_id=analyst_id)
    return _audit_trail


def init_audit_trail(base_dir: str = None, analyst_id: str = "unknown", session_id: str = None) -> AuditTrail:
    """Initialize audit trail with specific settings."""
    global _audit_trail
    _audit_trail = AuditTrail(base_dir, analyst_id, session_id)
    _audit_trail.log("session_started", "auth", {"analyst_id": analyst_id})
    return _audit_trail
