"""
Evidence Integrity Module - Chain of Custody and Hash Verification.
Ensures forensic admissibility by tracking evidence integrity.
"""
import os
import json
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class IntegrityRecord:
    """Record of a single file's integrity."""
    filename: str
    sha256: str
    size_bytes: int
    first_seen: str  # ISO timestamp
    last_verified: str  # ISO timestamp
    verification_count: int


@dataclass
class ChainOfCustodyEntry:
    """Entry in the chain of custody log."""
    timestamp: str
    action: str  # 'collected', 'loaded', 'exported', 'verified'
    analyst_id: str
    hostname: str
    details: str


class EvidenceIntegrity:
    """
    Manages evidence integrity verification and chain of custody.

    Creates an integrity manifest (evidence_integrity.json) that tracks:
    - SHA-256 hashes of all evidence files
    - First seen timestamps
    - Verification history
    - Chain of custody entries
    """

    MANIFEST_FILE = "evidence_integrity.json"

    def __init__(self, evidence_folder: str, analyst_id: str = "unknown"):
        """
        Initialize integrity manager.

        Args:
            evidence_folder: Path to evidence folder
            analyst_id: Identifier for the current analyst
        """
        self.evidence_folder = evidence_folder
        self.analyst_id = analyst_id
        self.hostname = os.environ.get('COMPUTERNAME', os.environ.get('HOSTNAME', 'unknown'))
        self.manifest_path = os.path.join(evidence_folder, self.MANIFEST_FILE)
        self.manifest = self._load_manifest()

    def _load_manifest(self) -> Dict:
        """Load existing manifest or create new one."""
        if os.path.exists(self.manifest_path):
            try:
                with open(self.manifest_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning("Could not load integrity manifest: %s", e)

        # Create new manifest
        return {
            "version": "1.0",
            "created": datetime.utcnow().isoformat() + "Z",
            "evidence_folder": os.path.basename(self.evidence_folder),
            "files": {},
            "chain_of_custody": []
        }

    def _save_manifest(self):
        """Save manifest to disk."""
        try:
            self.manifest["last_updated"] = datetime.utcnow().isoformat() + "Z"
            with open(self.manifest_path, 'w', encoding='utf-8') as f:
                json.dump(self.manifest, f, indent=2)
        except IOError as e:
            logger.error("Could not save integrity manifest: %s", e)

    @staticmethod
    def calculate_hash(filepath: str) -> Tuple[str, int]:
        """
        Calculate SHA-256 hash of a file.

        Returns:
            Tuple of (hash_hex, file_size)
        """
        sha256 = hashlib.sha256()
        size = 0

        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                sha256.update(chunk)
                size += len(chunk)

        return sha256.hexdigest(), size

    def hash_all_evidence(self, extensions: List[str] = None) -> Dict[str, IntegrityRecord]:
        """
        Calculate hashes for all evidence files.

        Args:
            extensions: File extensions to hash (default: .json)

        Returns:
            Dictionary of filename -> IntegrityRecord
        """
        if extensions is None:
            extensions = ['.json', '.txt', '.log', '.csv']

        now = datetime.utcnow().isoformat() + "Z"
        results = {}

        for filename in os.listdir(self.evidence_folder):
            filepath = os.path.join(self.evidence_folder, filename)

            # Skip directories and manifest
            if os.path.isdir(filepath):
                continue
            if filename == self.MANIFEST_FILE:
                continue

            # Check extension
            ext = os.path.splitext(filename)[1].lower()
            if ext not in extensions:
                continue

            try:
                file_hash, file_size = self.calculate_hash(filepath)

                # Check if we already have this file
                existing = self.manifest["files"].get(filename)

                if existing:
                    # Verify hash matches
                    if existing["sha256"] != file_hash:
                        logger.warning("INTEGRITY VIOLATION: %s hash changed!", filename)
                        self._add_custody_entry(
                            "integrity_violation",
                            f"Hash mismatch for {filename}: expected {existing['sha256'][:16]}..., got {file_hash[:16]}..."
                        )

                    # Update verification
                    existing["last_verified"] = now
                    existing["verification_count"] = existing.get("verification_count", 0) + 1
                    results[filename] = IntegrityRecord(**existing)
                else:
                    # New file
                    record = IntegrityRecord(
                        filename=filename,
                        sha256=file_hash,
                        size_bytes=file_size,
                        first_seen=now,
                        last_verified=now,
                        verification_count=1
                    )
                    self.manifest["files"][filename] = asdict(record)
                    results[filename] = record

            except IOError as e:
                logger.error("Could not hash %s: %s", filename, e)

        self._save_manifest()
        return results

    def verify_file(self, filename: str) -> Tuple[bool, str]:
        """
        Verify a single file's integrity.

        Returns:
            Tuple of (is_valid, message)
        """
        filepath = os.path.join(self.evidence_folder, filename)

        if not os.path.exists(filepath):
            return False, f"File not found: {filename}"

        existing = self.manifest["files"].get(filename)
        if not existing:
            return False, f"No integrity record for: {filename}"

        try:
            current_hash, _ = self.calculate_hash(filepath)

            if current_hash == existing["sha256"]:
                # Update verification timestamp
                now = datetime.utcnow().isoformat() + "Z"
                existing["last_verified"] = now
                existing["verification_count"] = existing.get("verification_count", 0) + 1
                self._save_manifest()
                return True, f"Integrity verified: {filename}"
            else:
                self._add_custody_entry(
                    "integrity_violation",
                    f"Hash mismatch for {filename}"
                )
                return False, f"INTEGRITY VIOLATION: {filename} has been modified!"

        except IOError as e:
            return False, f"Error verifying {filename}: {e}"

    def verify_all(self) -> Dict[str, Tuple[bool, str]]:
        """
        Verify all files in the manifest.

        Returns:
            Dictionary of filename -> (is_valid, message)
        """
        results = {}

        for filename in self.manifest["files"]:
            results[filename] = self.verify_file(filename)

        # Check for missing files
        for filename in self.manifest["files"]:
            filepath = os.path.join(self.evidence_folder, filename)
            if not os.path.exists(filepath):
                results[filename] = (False, f"File missing: {filename}")

        return results

    def _add_custody_entry(self, action: str, details: str):
        """Add an entry to the chain of custody."""
        entry = ChainOfCustodyEntry(
            timestamp=datetime.utcnow().isoformat() + "Z",
            action=action,
            analyst_id=self.analyst_id,
            hostname=self.hostname,
            details=details
        )
        self.manifest["chain_of_custody"].append(asdict(entry))
        self._save_manifest()

    def log_access(self, action: str, details: str = ""):
        """
        Log an access event in the chain of custody.

        Args:
            action: Type of action (loaded, exported, analyzed, etc.)
            details: Additional details
        """
        self._add_custody_entry(action, details)

    def get_custody_chain(self) -> List[Dict]:
        """Get the full chain of custody."""
        return self.manifest.get("chain_of_custody", [])

    def get_integrity_summary(self) -> Dict:
        """
        Get a summary of evidence integrity status.

        Returns:
            Dictionary with counts and status
        """
        files = self.manifest.get("files", {})
        verification_results = self.verify_all()

        valid_count = sum(1 for v, _ in verification_results.values() if v)
        invalid_count = sum(1 for v, _ in verification_results.values() if not v)

        return {
            "total_files": len(files),
            "verified_valid": valid_count,
            "integrity_violations": invalid_count,
            "last_verification": self.manifest.get("last_updated"),
            "custody_entries": len(self.manifest.get("chain_of_custody", [])),
            "status": "VALID" if invalid_count == 0 else "COMPROMISED"
        }

    def export_integrity_report(self) -> str:
        """
        Export integrity report as JSON string.

        Returns:
            JSON string with full integrity data
        """
        report = {
            "report_generated": datetime.utcnow().isoformat() + "Z",
            "evidence_folder": self.evidence_folder,
            "integrity_summary": self.get_integrity_summary(),
            "file_hashes": self.manifest.get("files", {}),
            "chain_of_custody": self.manifest.get("chain_of_custody", [])
        }
        return json.dumps(report, indent=2)


def initialize_integrity(evidence_folder: str, analyst_id: str = "system") -> EvidenceIntegrity:
    """
    Initialize evidence integrity for a folder.
    Hashes all files and creates manifest if needed.

    Args:
        evidence_folder: Path to evidence folder
        analyst_id: Identifier for the analyst

    Returns:
        EvidenceIntegrity instance
    """
    integrity = EvidenceIntegrity(evidence_folder, analyst_id)
    integrity.hash_all_evidence()
    integrity.log_access("initialized", f"Evidence integrity initialized by {analyst_id}")
    return integrity


def verify_integrity(evidence_folder: str) -> Tuple[bool, Dict]:
    """
    Quick verification of evidence integrity.

    Returns:
        Tuple of (all_valid, summary_dict)
    """
    integrity = EvidenceIntegrity(evidence_folder)
    summary = integrity.get_integrity_summary()
    return summary["status"] == "VALID", summary
