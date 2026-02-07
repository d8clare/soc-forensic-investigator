"""
Centralized evidence data cache for fast dashboard performance.
Loads all evidence files once and stores in session state.
Optionally uses SQLite for large datasets with pagination support.
"""
import os
import logging
import streamlit as st
from typing import Dict, Any, Optional, List

from core.data_loader import load_json, load_text_file

# Try to import database module
try:
    from core.database import cache_all_evidence, get_evidence_db, EvidenceDatabase
    SQLITE_AVAILABLE = True
except ImportError:
    SQLITE_AVAILABLE = False

logger = logging.getLogger(__name__)


# List of all evidence files to preload
EVIDENCE_FILES = [
    # Core artifacts
    ("processes", "processes.json"),
    ("network", "network_connections.json"),
    ("events", "all_events.json"),
    ("recent_files", "recent_files.json"),
    ("dns", "dns_cache.json"),
    ("arp", "arp_table.json"),

    # Persistence
    ("registry", "registry_autoruns.json"),
    ("tasks", "scheduled_tasks.json"),
    ("services", "services_list.json"),
    ("wmi", "wmi_persistence.json"),
    ("startup", "startup_files.json"),

    # Execution
    ("userassist", "user_assist.json"),
    ("prefetch", "prefetch_list.json"),
    ("lnk_files", "lnk_files.json"),
    ("powershell", "powershell_history.json"),
    ("shimcache", "shimcache.json"),

    # Browser
    ("browser_history", "browser_history.json"),
    ("browser_cookies", "browser_cookies.json"),
    ("firefox_history", "firefox_history.json"),
    ("firefox_cookies", "firefox_cookies.json"),
    ("browser_downloads", "browser_downloads.json"),

    # Files
    ("jump_lists", "jump_lists.json"),
    ("shellbags", "shellbags.json"),

    # Network
    ("bits_jobs", "bits_jobs.json"),

    # USB
    ("usb_devices", "usb_events.json"),
    ("usb_history", "usb_history_reg.json"),

    # Software
    ("installed_software", "installed_software.json"),

    # Hashes
    ("file_hashes", "file_hashes.json"),

    # Audit
    ("audit_log", "audit_log.json"),
]

TEXT_FILES = [
    ("hosts_file", "hosts_file_backup"),
]


def get_cache_key(folder: str) -> str:
    """Generate a unique cache key for the evidence folder."""
    return f"evidence_cache_{os.path.basename(folder)}"


def is_cache_valid(folder: str) -> bool:
    """Check if the cache is valid for the given folder."""
    cache_key = get_cache_key(folder)
    if cache_key not in st.session_state:
        return False
    cached = st.session_state[cache_key]
    return cached.get("folder") == folder and cached.get("loaded", False)


def load_all_evidence(folder: str, force_reload: bool = False, use_sqlite: bool = True) -> Dict[str, Any]:
    """
    Load all evidence files into session state cache.
    Optionally caches to SQLite for better performance with large datasets.

    Args:
        folder: Path to the evidence folder
        force_reload: Force reload even if cached
        use_sqlite: Use SQLite caching (recommended for large datasets)

    Returns:
        Dictionary with all loaded evidence data
    """
    cache_key = get_cache_key(folder)

    # Return cached data if valid
    if not force_reload and is_cache_valid(folder):
        return st.session_state[cache_key]["data"]

    # Try to cache to SQLite for better performance
    if use_sqlite and SQLITE_AVAILABLE:
        try:
            sqlite_stats = cache_all_evidence(folder, force=force_reload)
            st.session_state['sqlite_cache_stats'] = sqlite_stats
            st.session_state['sqlite_enabled'] = True
            logger.info("SQLite cache: %s", sqlite_stats)
        except Exception as e:
            logger.warning("SQLite caching failed: %s", e)
            st.session_state['sqlite_enabled'] = False

    # Load all evidence files (still needed for full data access)
    data = {}
    loaded_count = 0
    failed_count = 0
    failed_files = []

    for key, filename in EVIDENCE_FILES:
        result = load_json(folder, filename)
        data[key] = result
        if result is not None:
            loaded_count += 1
        else:
            # Only count as failed if file exists but couldn't be loaded
            import os
            if os.path.exists(os.path.join(folder, filename)):
                failed_count += 1
                failed_files.append(filename)

    for key, filename in TEXT_FILES:
        result = load_text_file(folder, filename)
        data[key] = result
        if result is not None:
            loaded_count += 1

    # Store loading stats
    st.session_state['evidence_load_stats'] = {
        'loaded': loaded_count,
        'failed': failed_count,
        'failed_files': failed_files
    }

    # Check for registry hives directory
    hives_dir = os.path.join(folder, "registry_hives")
    registry_hives = []
    if os.path.exists(hives_dir):
        try:
            for f in os.listdir(hives_dir):
                fpath = os.path.join(hives_dir, f)
                if os.path.isfile(fpath):
                    registry_hives.append({
                        'name': f,
                        'path': fpath,
                        'size': os.path.getsize(fpath)
                    })
        except Exception:
            pass
    data["registry_hives"] = registry_hives
    data["registry_hives_dir"] = hives_dir

    # Store in session state
    st.session_state[cache_key] = {
        "folder": folder,
        "loaded": True,
        "data": data,
        "sqlite_enabled": st.session_state.get('sqlite_enabled', False)
    }

    return data


def query_evidence(folder: str, table: str, where: str = None, params: tuple = None,
                   order_by: str = None, limit: int = 100, offset: int = 0) -> List[Dict]:
    """
    Query evidence from SQLite cache with pagination.

    Args:
        folder: Evidence folder path
        table: Table name (processes, network, events, etc.)
        where: WHERE clause
        params: Query parameters
        order_by: ORDER BY clause
        limit: Max records
        offset: Skip records

    Returns:
        List of records
    """
    if not SQLITE_AVAILABLE:
        return []

    try:
        db = get_evidence_db(folder)
        results = db.query(table, where=where, params=params,
                          order_by=order_by, limit=limit, offset=offset)
        db.close()
        return results
    except Exception as e:
        logger.warning("Query failed: %s", e)
        return []


def count_evidence(folder: str, table: str, where: str = None, params: tuple = None) -> int:
    """
    Count records in SQLite cache.

    Args:
        folder: Evidence folder path
        table: Table name
        where: WHERE clause
        params: Query parameters

    Returns:
        Record count
    """
    if not SQLITE_AVAILABLE:
        return 0

    try:
        db = get_evidence_db(folder)
        count = db.count(table, where=where, params=params)
        db.close()
        return count
    except Exception as e:
        logger.warning("Count failed: %s", e)
        return 0


def search_evidence(folder: str, table: str, search_term: str,
                    columns: List[str], limit: int = 100) -> List[Dict]:
    """
    Search evidence in SQLite cache.

    Args:
        folder: Evidence folder path
        table: Table name
        search_term: Search string
        columns: Columns to search
        limit: Max results

    Returns:
        Matching records
    """
    if not SQLITE_AVAILABLE:
        return []

    try:
        db = get_evidence_db(folder)
        results = db.search(table, search_term, columns, limit=limit)
        db.close()
        return results
    except Exception as e:
        logger.warning("Search failed: %s", e)
        return []


def get_sqlite_stats(folder: str) -> Dict[str, int]:
    """Get SQLite cache statistics."""
    if not SQLITE_AVAILABLE:
        return {}

    try:
        db = get_evidence_db(folder)
        stats = db.get_stats()
        db.close()
        return stats
    except Exception:
        return {}


def get_evidence(folder: str, key: str) -> Optional[Any]:
    """
    Get a specific evidence type from the cache.

    Args:
        folder: Path to the evidence folder
        key: Evidence key (e.g., 'processes', 'network')

    Returns:
        Evidence data or None
    """
    cache_key = get_cache_key(folder)

    if cache_key not in st.session_state:
        load_all_evidence(folder)

    cached = st.session_state.get(cache_key, {})
    data = cached.get("data", {})
    return data.get(key)


def clear_cache(folder: str = None):
    """Clear the evidence cache."""
    if folder:
        cache_key = get_cache_key(folder)
        if cache_key in st.session_state:
            del st.session_state[cache_key]
    else:
        # Clear all evidence caches
        keys_to_delete = [k for k in st.session_state.keys() if k.startswith("evidence_cache_")]
        for key in keys_to_delete:
            del st.session_state[key]
