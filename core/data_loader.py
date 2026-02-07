"""
Cached data loading with validation for SOC Dashboard.
Uses session state for fast in-memory caching.

Includes:
- JSON loading with error handling
- DataFrame sanitization
- Input validation
- Credential masking
"""
import json
import os
import re
from datetime import datetime
from typing import Any, Optional, List, Dict

import streamlit as st
import pandas as pd

from core.security import (
    logger, escape_html, mask_credentials, safe_str,
    validate_path, validate_json_structure, SafeContext
)


def parse_dotnet_date(date_str) -> str:
    """
    Parse .NET JSON serialized DateTime format: /Date(1234567890123)/
    Returns a human-readable datetime string.
    """
    if not date_str or pd.isna(date_str):
        return ""
    date_str = str(date_str)
    # Check for /Date(timestamp)/ format (with optional timezone offset)
    if '/Date(' in date_str:
        try:
            match = re.search(r'/Date\((-?\d+)', date_str)
            if match:
                timestamp_ms = int(match.group(1))
                # .NET DateTime.MinValue is -62135596800000 (year 0001)
                # This represents "no date" / unset value
                if timestamp_ms <= -62135596800000:
                    return ""
                # Handle negative timestamps (before 1970) - not supported on Windows
                if timestamp_ms < 0:
                    return ""
                dt = datetime.fromtimestamp(timestamp_ms / 1000)
                return dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            pass
    return date_str


def convert_dotnet_dates(df: pd.DataFrame, columns: List[str]) -> pd.DataFrame:
    """
    Convert .NET date columns in a DataFrame to readable format.
    """
    for col in columns:
        if col in df.columns:
            df[col] = df[col].apply(parse_dotnet_date)
    return df


def _get_session_cache_key(folder: str, filename: str) -> str:
    """Generate a unique session cache key."""
    folder_name = os.path.basename(folder)
    return f"_data_{folder_name}_{filename}"


def load_json(folder: str, filename: str) -> Optional[List[Dict[str, Any]]]:
    """
    Load a JSON file from the evidence folder with session state caching.
    Uses session state for instant access on reruns.

    Args:
        folder: Path to the evidence folder
        filename: Name of the JSON file

    Returns:
        Parsed JSON data or None if not found/error
    """
    # Validate inputs
    if not folder or not filename:
        logger.warning("load_json called with empty folder or filename")
        return None

    # Security: validate path components
    if not validate_path(folder) or not validate_path(filename):
        logger.error("Invalid path detected: folder=%s, filename=%s", folder, filename)
        return None

    # Check session state first (fastest)
    cache_key = _get_session_cache_key(folder, filename)
    if cache_key in st.session_state:
        return st.session_state[cache_key]

    # Load from file with error handling
    path = os.path.join(folder, filename)

    try:
        if not os.path.exists(path):
            logger.debug("File not found: %s", path)
            st.session_state[cache_key] = None
            return None

        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Validate JSON structure
        if data is not None and not isinstance(data, (list, dict)):
            logger.warning("Unexpected JSON type in %s: %s", filename, type(data).__name__)

        # Cache in session state for future reruns
        st.session_state[cache_key] = data
        logger.debug("Loaded %s successfully (%d items)",
                    filename, len(data) if isinstance(data, list) else 1)
        return data

    except json.JSONDecodeError as e:
        logger.error("JSON decode error in %s: %s", filename, str(e))
        st.session_state[cache_key] = None
        return None

    except PermissionError:
        logger.error("Permission denied reading %s", path)
        st.session_state[cache_key] = None
        return None

    except Exception as e:
        logger.error("Error loading %s: %s", filename, str(e))
        st.session_state[cache_key] = None
        return None


def load_text_file(folder: str, filename: str) -> Optional[str]:
    """
    Load a text file from the evidence folder with session state caching.

    Args:
        folder: Path to the evidence folder
        filename: Name of the text file

    Returns:
        File contents as string or None if not found/error
    """
    # Check session state first
    cache_key = _get_session_cache_key(folder, filename)
    if cache_key in st.session_state:
        return st.session_state[cache_key]

    try:
        path = os.path.join(folder, filename)
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                st.session_state[cache_key] = content
                return content
        st.session_state[cache_key] = None
        return None
    except Exception:
        st.session_state[cache_key] = None
        return None


def clear_data_cache(folder: str = None):
    """Clear cached data from session state."""
    if folder:
        folder_name = os.path.basename(folder)
        prefix = f"_data_{folder_name}_"
        keys_to_delete = [k for k in st.session_state.keys() if k.startswith(prefix)]
    else:
        keys_to_delete = [k for k in st.session_state.keys() if k.startswith("_data_")]

    for key in keys_to_delete:
        del st.session_state[key]


def sanitize_dataframe(df: pd.DataFrame, mask_sensitive: bool = True) -> pd.DataFrame:
    """
    Sanitize a DataFrame for safe display.

    Includes:
    - Converting complex objects to strings
    - Masking sensitive credentials
    - Handling None/NaN values
    - HTML escaping for string columns

    Args:
        df: Input DataFrame
        mask_sensitive: Whether to mask credentials (default True)

    Returns:
        Sanitized DataFrame safe for display
    """
    if df is None or df.empty:
        return df if df is not None else pd.DataFrame()

    try:
        df = df.copy()

        for col in df.columns:
            try:
                # Check if column contains complex objects (dict or list)
                if df[col].apply(lambda x: isinstance(x, (dict, list))).any():
                    df[col] = df[col].apply(lambda x: safe_str(x) if x is not None else "")

                # Ensure object columns are strings with no NaN
                if df[col].dtype == 'object':
                    df[col] = df[col].fillna("").astype(str)

                    # Mask sensitive credentials in string columns
                    if mask_sensitive:
                        # Only mask columns likely to contain sensitive data
                        sensitive_col_names = ['cmdline', 'command', 'value', 'data',
                                              'message', 'content', 'url', 'path']
                        if any(s in col.lower() for s in sensitive_col_names):
                            df[col] = df[col].apply(mask_credentials)

            except Exception as e:
                logger.warning("Error sanitizing column %s: %s", col, str(e))
                continue

        return df

    except Exception as e:
        logger.error("Error sanitizing DataFrame: %s", str(e))
        return df if df is not None else pd.DataFrame()


def load_json_with_validation(folder: str, filename: str, required_fields: List[str] = None) -> Optional[List[Dict[str, Any]]]:
    """
    Load JSON with optional field validation.

    Args:
        folder: Path to the evidence folder
        filename: Name of the JSON file
        required_fields: List of field names that must be present in each record

    Returns:
        Validated JSON data or None
    """
    data = load_json(folder, filename)

    if data is None:
        return None

    if not isinstance(data, list):
        data = [data]

    if required_fields and data:
        # Check first record for required fields
        first_record = data[0]
        missing = [f for f in required_fields if f not in first_record]
        if missing:
            st.warning(f"{filename}: Missing expected fields: {', '.join(missing)}")

    return data


def create_dataframe_safe(data: Optional[List[Dict]], default_columns: List[str] = None) -> pd.DataFrame:
    """
    Create a DataFrame from data with safe handling.

    Args:
        data: List of dictionaries or None
        default_columns: Columns to use if data is empty

    Returns:
        DataFrame (may be empty with default columns)
    """
    if not data:
        if default_columns:
            return pd.DataFrame(columns=default_columns)
        return pd.DataFrame()

    return sanitize_dataframe(pd.DataFrame(data))


def get_file_list(folder: str, extension: str = ".json") -> List[str]:
    """
    Get list of files with a specific extension in a folder.

    Args:
        folder: Path to search
        extension: File extension to filter by

    Returns:
        List of matching filenames
    """
    try:
        if os.path.exists(folder):
            return [f for f in os.listdir(folder) if f.endswith(extension)]
        return []
    except Exception:
        return []


def folder_exists(base_folder: str, subfolder: str) -> bool:
    """
    Check if a subfolder exists within the evidence folder.

    Args:
        base_folder: Base evidence folder path
        subfolder: Name of subfolder to check

    Returns:
        True if subfolder exists
    """
    return os.path.exists(os.path.join(base_folder, subfolder))
