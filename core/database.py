"""
SQLite Database Module for Evidence Caching.

Provides fast querying and pagination for large evidence datasets.
Caches JSON evidence into SQLite for better dashboard performance.
"""
import json
import logging
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Database schema version - increment to force rebuild
DB_SCHEMA_VERSION = 1

# Whitelist of allowed table names (prevents SQL injection)
ALLOWED_TABLES = frozenset([
    "processes", "network", "events", "files", "registry",
    "services", "scheduled_tasks", "browser_history", "browser_cookies",
    "dns_cache", "findings", "metadata"
])

# Whitelist of allowed column names per table
ALLOWED_COLUMNS = {
    "processes": frozenset(["id", "pid", "name", "exe", "cmdline", "parent_pid", "parent_name",
                            "username", "status", "create_time", "signature_status", "cpu_percent",
                            "memory_mb", "connections", "raw_json"]),
    "network": frozenset(["id", "pid", "name", "family", "type", "laddr", "raddr", "status",
                          "local_ip", "local_port", "remote_ip", "remote_port", "raw_json"]),
    "events": frozenset(["id", "event_id", "time", "time_unix", "log_name", "provider", "level",
                         "level_value", "message", "user_id", "computer", "raw_json"]),
    "files": frozenset(["id", "filename", "path", "extension", "size_bytes", "size_mb",
                        "created", "modified", "accessed", "sha256", "raw_json"]),
    "registry": frozenset(["id", "key_path", "name", "value", "value_type", "category", "raw_json"]),
    "services": frozenset(["id", "name", "display_name", "status", "start_type", "bin_path",
                           "description", "raw_json"]),
    "scheduled_tasks": frozenset(["id", "task_name", "task_path", "status", "next_run", "last_run",
                                  "action", "author", "run_as", "raw_json"]),
    "browser_history": frozenset(["id", "browser", "user", "url", "title", "visit_time",
                                  "visit_count", "raw_json"]),
    "browser_cookies": frozenset(["id", "browser", "user", "host", "cookie_name", "value",
                                  "created", "expires", "raw_json"]),
    "dns_cache": frozenset(["id", "name", "type", "ttl", "data", "raw_json"]),
    "findings": frozenset(["id", "category", "description", "score", "original_score", "severity",
                           "confidence", "whitelisted", "whitelist_reason", "source",
                           "mitre_techniques", "evidence", "created_at"]),
    "metadata": frozenset(["key", "value"])
}


def _validate_table_name(table_name: str) -> str:
    """Validate table name against whitelist to prevent SQL injection."""
    if table_name not in ALLOWED_TABLES:
        raise ValueError(f"Invalid table name: {table_name}")
    return table_name


def _validate_column_name(table_name: str, column_name: str) -> str:
    """Validate column name against whitelist to prevent SQL injection."""
    if table_name not in ALLOWED_COLUMNS:
        raise ValueError(f"Invalid table name: {table_name}")
    if column_name not in ALLOWED_COLUMNS[table_name]:
        raise ValueError(f"Invalid column name '{column_name}' for table '{table_name}'")
    return column_name


def _validate_columns(table_name: str, columns: List[str]) -> List[str]:
    """Validate multiple column names."""
    return [_validate_column_name(table_name, col) for col in columns]

# Table definitions
TABLES = {
    "processes": """
        CREATE TABLE IF NOT EXISTS processes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pid INTEGER,
            name TEXT,
            exe TEXT,
            cmdline TEXT,
            parent_pid INTEGER,
            parent_name TEXT,
            username TEXT,
            status TEXT,
            create_time TEXT,
            signature_status TEXT,
            cpu_percent REAL,
            memory_mb REAL,
            connections INTEGER,
            raw_json TEXT
        )
    """,
    "network": """
        CREATE TABLE IF NOT EXISTS network (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pid INTEGER,
            name TEXT,
            family TEXT,
            type TEXT,
            laddr TEXT,
            raddr TEXT,
            status TEXT,
            local_ip TEXT,
            local_port INTEGER,
            remote_ip TEXT,
            remote_port INTEGER,
            raw_json TEXT
        )
    """,
    "events": """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER,
            time TEXT,
            time_unix REAL,
            log_name TEXT,
            provider TEXT,
            level TEXT,
            level_value INTEGER,
            message TEXT,
            user_id TEXT,
            computer TEXT,
            raw_json TEXT
        )
    """,
    "files": """
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            path TEXT,
            extension TEXT,
            size_bytes INTEGER,
            size_mb REAL,
            created TEXT,
            modified TEXT,
            accessed TEXT,
            sha256 TEXT,
            raw_json TEXT
        )
    """,
    "registry": """
        CREATE TABLE IF NOT EXISTS registry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_path TEXT,
            name TEXT,
            value TEXT,
            value_type TEXT,
            category TEXT,
            raw_json TEXT
        )
    """,
    "services": """
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            display_name TEXT,
            status TEXT,
            start_type TEXT,
            bin_path TEXT,
            description TEXT,
            raw_json TEXT
        )
    """,
    "scheduled_tasks": """
        CREATE TABLE IF NOT EXISTS scheduled_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_name TEXT,
            task_path TEXT,
            status TEXT,
            next_run TEXT,
            last_run TEXT,
            action TEXT,
            author TEXT,
            run_as TEXT,
            raw_json TEXT
        )
    """,
    "browser_history": """
        CREATE TABLE IF NOT EXISTS browser_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            browser TEXT,
            user TEXT,
            url TEXT,
            title TEXT,
            visit_time TEXT,
            visit_count INTEGER,
            raw_json TEXT
        )
    """,
    "browser_cookies": """
        CREATE TABLE IF NOT EXISTS browser_cookies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            browser TEXT,
            user TEXT,
            host TEXT,
            cookie_name TEXT,
            value TEXT,
            created TEXT,
            expires TEXT,
            raw_json TEXT
        )
    """,
    "dns_cache": """
        CREATE TABLE IF NOT EXISTS dns_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            type TEXT,
            ttl INTEGER,
            data TEXT,
            raw_json TEXT
        )
    """,
    "findings": """
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT,
            description TEXT,
            score INTEGER,
            original_score INTEGER,
            severity TEXT,
            confidence TEXT,
            whitelisted INTEGER,
            whitelist_reason TEXT,
            source TEXT,
            mitre_techniques TEXT,
            evidence TEXT,
            created_at TEXT
        )
    """,
    "metadata": """
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """
}

# Indexes for fast queries
INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_processes_name ON processes(name)",
    "CREATE INDEX IF NOT EXISTS idx_processes_pid ON processes(pid)",
    "CREATE INDEX IF NOT EXISTS idx_network_raddr ON network(remote_ip)",
    "CREATE INDEX IF NOT EXISTS idx_network_port ON network(remote_port)",
    "CREATE INDEX IF NOT EXISTS idx_events_id ON events(event_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_time ON events(time_unix)",
    "CREATE INDEX IF NOT EXISTS idx_events_level ON events(level_value)",
    "CREATE INDEX IF NOT EXISTS idx_files_ext ON files(extension)",
    "CREATE INDEX IF NOT EXISTS idx_files_path ON files(path)",
    "CREATE INDEX IF NOT EXISTS idx_dns_name ON dns_cache(name)",
    "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)",
    "CREATE INDEX IF NOT EXISTS idx_findings_score ON findings(score)",
    "CREATE INDEX IF NOT EXISTS idx_browser_url ON browser_history(url)",
]


class EvidenceDatabase:
    """SQLite database for caching and querying evidence data."""

    def __init__(self, evidence_folder: str):
        """
        Initialize database for an evidence folder.

        Args:
            evidence_folder: Path to evidence folder
        """
        self.evidence_folder = evidence_folder
        self.db_path = os.path.join(evidence_folder, "evidence_cache.db")
        self.conn: Optional[sqlite3.Connection] = None
        self._initialized = False

    def connect(self) -> sqlite3.Connection:
        """Get or create database connection."""
        if self.conn is None:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            # Enable WAL mode for better concurrent access
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")
            self.conn.execute("PRAGMA cache_size=10000")
        return self.conn

    def initialize(self, force_rebuild: bool = False) -> bool:
        """
        Initialize database schema.

        Args:
            force_rebuild: If True, drop and recreate all tables

        Returns:
            True if database was created/rebuilt, False if already valid
        """
        conn = self.connect()
        cursor = conn.cursor()

        # Check schema version
        try:
            cursor.execute("SELECT value FROM metadata WHERE key='schema_version'")
            row = cursor.fetchone()
            current_version = int(row['value']) if row else 0
        except sqlite3.OperationalError:
            current_version = 0

        if current_version == DB_SCHEMA_VERSION and not force_rebuild:
            self._initialized = True
            return False

        # Create/recreate tables
        if force_rebuild or current_version != DB_SCHEMA_VERSION:
            logger.info("Initializing evidence database (version %d)", DB_SCHEMA_VERSION)

            # Drop existing tables if rebuilding
            if force_rebuild:
                for table_name in TABLES.keys():
                    cursor.execute(f"DROP TABLE IF EXISTS {table_name}")

            # Create tables
            for table_name, create_sql in TABLES.items():
                cursor.execute(create_sql)

            # Create indexes
            for index_sql in INDEXES:
                cursor.execute(index_sql)

            # Set schema version
            cursor.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                ('schema_version', str(DB_SCHEMA_VERSION))
            )

            conn.commit()
            self._initialized = True
            return True

        self._initialized = True
        return False

    def is_cached(self, artifact_type: str) -> bool:
        """Check if artifact type is already cached."""
        if not self._initialized:
            self.initialize()

        # Validate table name to prevent SQL injection
        try:
            table = _validate_table_name(artifact_type)
        except ValueError:
            return False

        conn = self.connect()
        cursor = conn.cursor()

        try:
            cursor.execute(f"SELECT COUNT(*) as cnt FROM {table}")
            row = cursor.fetchone()
            return row['cnt'] > 0 if row else False
        except sqlite3.OperationalError:
            return False

    def cache_json_file(self, json_filename: str, table_name: str,
                        field_mapping: Dict[str, str]) -> int:
        """
        Load JSON file and cache into SQLite table.

        Args:
            json_filename: Name of JSON file in evidence folder
            table_name: Target SQLite table
            field_mapping: Dict mapping JSON keys to table columns

        Returns:
            Number of records cached
        """
        json_path = os.path.join(self.evidence_folder, json_filename)
        if not os.path.exists(json_path):
            return 0

        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            logger.warning("Failed to load %s: %s", json_filename, e)
            return 0

        if not data:
            return 0

        if not isinstance(data, list):
            data = [data]

        return self._insert_records(table_name, data, field_mapping)

    def _insert_records(self, table_name: str, records: List[Dict],
                        field_mapping: Dict[str, str]) -> int:
        """Insert records into table with field mapping."""
        if not records:
            return 0

        # Validate table and column names to prevent SQL injection
        try:
            table = _validate_table_name(table_name)
            columns = _validate_columns(table, list(field_mapping.values())) + ['raw_json']
        except ValueError as e:
            logger.warning("Validation failed: %s", e)
            return 0

        conn = self.connect()
        cursor = conn.cursor()

        # Build insert statement with validated names
        placeholders = ', '.join(['?' for _ in columns])
        insert_sql = f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})"

        count = 0
        for record in records:
            try:
                values = []
                for json_key, col_name in field_mapping.items():
                    val = record.get(json_key)
                    # Handle nested keys like "parent.name"
                    if '.' in json_key:
                        parts = json_key.split('.')
                        val = record
                        for part in parts:
                            val = val.get(part, {}) if isinstance(val, dict) else None
                    values.append(val)

                # Add raw JSON
                values.append(json.dumps(record, default=str))

                cursor.execute(insert_sql, values)
                count += 1
            except Exception as e:
                logger.debug("Failed to insert record: %s", e)
                continue

        conn.commit()
        return count

    def query(self, table_name: str, where: str = None, params: tuple = None,
              order_by: str = None, limit: int = None, offset: int = 0) -> List[Dict]:
        """
        Query table with optional filters and pagination.

        Args:
            table_name: Table to query (validated against whitelist)
            where: WHERE clause (without WHERE keyword) - use parameterized queries
            params: Parameters for WHERE clause
            order_by: ORDER BY clause (column name validated against whitelist)
            limit: Maximum records to return
            offset: Number of records to skip

        Returns:
            List of record dictionaries
        """
        # Validate table name to prevent SQL injection
        try:
            table = _validate_table_name(table_name)
        except ValueError as e:
            logger.warning("Invalid table name: %s", e)
            return []

        conn = self.connect()
        cursor = conn.cursor()

        sql = f"SELECT * FROM {table}"
        if where:
            sql += f" WHERE {where}"
        if order_by:
            # Validate order_by column if it looks like a simple column name
            order_col = order_by.split()[0] if order_by else None
            if order_col and order_col in ALLOWED_COLUMNS.get(table, set()):
                sql += f" ORDER BY {order_by}"
        if limit:
            # Use parameterized limit/offset to prevent injection
            sql += f" LIMIT ? OFFSET ?"
            params = (params or ()) + (limit, offset)

        try:
            if params:
                cursor.execute(sql, params)
            else:
                cursor.execute(sql)

            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        except sqlite3.OperationalError as e:
            logger.warning("Query failed: %s", e)
            return []

    def count(self, table_name: str, where: str = None, params: tuple = None) -> int:
        """Count records in table."""
        # Validate table name to prevent SQL injection
        try:
            table = _validate_table_name(table_name)
        except ValueError:
            return 0

        conn = self.connect()
        cursor = conn.cursor()

        sql = f"SELECT COUNT(*) as cnt FROM {table}"
        if where:
            sql += f" WHERE {where}"

        try:
            if params:
                cursor.execute(sql, params)
            else:
                cursor.execute(sql)
            row = cursor.fetchone()
            return row['cnt'] if row else 0
        except sqlite3.OperationalError:
            return 0

    def search(self, table_name: str, search_term: str, columns: List[str],
               limit: int = 100) -> List[Dict]:
        """
        Full-text search across specified columns.

        Args:
            table_name: Table to search (validated against whitelist)
            search_term: Search term
            columns: Columns to search (validated against whitelist)
            limit: Maximum results

        Returns:
            Matching records
        """
        if not search_term or not columns:
            return []

        # Validate table and column names to prevent SQL injection
        try:
            table = _validate_table_name(table_name)
            validated_cols = _validate_columns(table, columns)
        except ValueError as e:
            logger.warning("Search validation failed: %s", e)
            return []

        where_parts = [f"{col} LIKE ?" for col in validated_cols]
        where = " OR ".join(where_parts)
        params = tuple(f"%{search_term}%" for _ in validated_cols)

        return self.query(table_name, where=where, params=params, limit=limit)

    def get_distinct_values(self, table_name: str, column: str) -> List[str]:
        """Get distinct values from a column."""
        # Validate table and column names to prevent SQL injection
        try:
            table = _validate_table_name(table_name)
            col = _validate_column_name(table, column)
        except ValueError as e:
            logger.warning("Validation failed: %s", e)
            return []

        conn = self.connect()
        cursor = conn.cursor()

        try:
            cursor.execute(f"SELECT DISTINCT {col} FROM {table} WHERE {col} IS NOT NULL")
            return [row[0] for row in cursor.fetchall()]
        except sqlite3.OperationalError:
            return []

    def cache_findings(self, findings: List) -> int:
        """
        Cache analysis findings to database.

        Args:
            findings: List of Finding objects

        Returns:
            Number of findings cached
        """
        conn = self.connect()
        cursor = conn.cursor()

        # Clear existing findings
        cursor.execute("DELETE FROM findings")

        count = 0
        for f in findings:
            try:
                cursor.execute("""
                    INSERT INTO findings
                    (category, description, score, original_score, severity, confidence,
                     whitelisted, whitelist_reason, source, mitre_techniques, evidence, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    f.category,
                    f.description,
                    f.score,
                    getattr(f, 'original_score', f.score),
                    f.severity,
                    getattr(f, 'confidence', 'medium'),
                    1 if getattr(f, 'whitelisted', False) else 0,
                    getattr(f, 'whitelist_reason', ''),
                    f.source,
                    json.dumps(f.mitre_techniques),
                    json.dumps(f.evidence, default=str),
                    datetime.now().isoformat()
                ))
                count += 1
            except Exception as e:
                logger.debug("Failed to cache finding: %s", e)

        conn.commit()
        return count

    def get_stats(self) -> Dict[str, int]:
        """Get record counts for all tables."""
        stats = {}
        for table_name in TABLES.keys():
            if table_name != 'metadata':
                stats[table_name] = self.count(table_name)
        return stats

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None


# Field mappings for common JSON files
FIELD_MAPPINGS = {
    "processes.json": {
        "table": "processes",
        "mapping": {
            "pid": "pid",
            "name": "name",
            "exe": "exe",
            "cmdline": "cmdline",
            "parent_pid": "parent_pid",
            "parent_name": "parent_name",
            "username": "username",
            "status": "status",
            "create_time": "create_time",
            "SignatureStatus": "signature_status",
            "cpu_percent": "cpu_percent",
            "memory_mb": "memory_mb",
            "connections": "connections"
        }
    },
    "network_connections.json": {
        "table": "network",
        "mapping": {
            "pid": "pid",
            "name": "name",
            "family": "family",
            "type": "type",
            "laddr": "laddr",
            "raddr": "raddr",
            "status": "status"
        }
    },
    "events.json": {
        "table": "events",
        "mapping": {
            "EventId": "event_id",
            "Time": "time",
            "LogName": "log_name",
            "ProviderName": "provider",
            "LevelDisplayName": "level",
            "Level": "level_value",
            "Message": "message",
            "UserId": "user_id",
            "MachineName": "computer"
        }
    },
    "recent_files.json": {
        "table": "files",
        "mapping": {
            "filename": "filename",
            "path": "path",
            "extension": "extension",
            "size_bytes": "size_bytes",
            "size_mb": "size_mb",
            "created": "created",
            "modified": "modified",
            "accessed": "accessed",
            "sha256": "sha256"
        }
    },
    "dns_cache.json": {
        "table": "dns_cache",
        "mapping": {
            "Name": "name",
            "Type": "type",
            "TTL": "ttl",
            "Data": "data"
        }
    },
    "browser_history.json": {
        "table": "browser_history",
        "mapping": {
            "Browser": "browser",
            "User": "user",
            "URL": "url",
            "Title": "title",
            "Time": "visit_time",
            "VisitCount": "visit_count"
        }
    },
    "browser_cookies.json": {
        "table": "browser_cookies",
        "mapping": {
            "Browser": "browser",
            "User": "user",
            "Host": "host",
            "CookieName": "cookie_name",
            "Value": "value",
            "Created": "created",
            "Expires": "expires"
        }
    },
    "services.json": {
        "table": "services",
        "mapping": {
            "Name": "name",
            "DisplayName": "display_name",
            "Status": "status",
            "StartType": "start_type",
            "BinPath": "bin_path",
            "Description": "description"
        }
    },
    "scheduled_tasks.json": {
        "table": "scheduled_tasks",
        "mapping": {
            "TaskName": "task_name",
            "TaskPath": "task_path",
            "State": "status",
            "NextRunTime": "next_run",
            "LastRunTime": "last_run",
            "Action": "action",
            "Author": "author",
            "UserId": "run_as"
        }
    },
    "registry_autoruns.json": {
        "table": "registry",
        "mapping": {
            "Path": "key_path",
            "Name": "name",
            "Value": "value",
            "Type": "value_type",
            "Category": "category"
        }
    }
}


def cache_all_evidence(evidence_folder: str, force: bool = False) -> Dict[str, int]:
    """
    Cache all JSON evidence files into SQLite database.

    Args:
        evidence_folder: Path to evidence folder
        force: Force rebuild even if cache exists

    Returns:
        Dict with counts per artifact type
    """
    db = EvidenceDatabase(evidence_folder)
    db.initialize(force_rebuild=force)

    results = {}
    for json_file, config in FIELD_MAPPINGS.items():
        table = config['table']

        # Skip if already cached (unless forcing)
        if not force and db.is_cached(table):
            results[table] = db.count(table)
            continue

        count = db.cache_json_file(json_file, table, config['mapping'])
        results[table] = count
        if count > 0:
            logger.info("Cached %d records from %s", count, json_file)

    db.close()
    return results


def get_evidence_db(evidence_folder: str) -> EvidenceDatabase:
    """Get database instance for evidence folder."""
    db = EvidenceDatabase(evidence_folder)
    db.initialize()
    return db
