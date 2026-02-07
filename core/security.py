"""
Security utilities for the SOC Dashboard.

Provides:
- HTML sanitization to prevent XSS attacks
- Credential masking for sensitive data display
- Input validation helpers
- Centralized logging configuration
- Secure API key storage with encryption
"""
import base64
import html
import json
import logging
import os
import re
import secrets
from typing import Any, Dict, List, Optional, Union

# Try to import Windows DPAPI for secure storage
try:
    import win32crypt
    DPAPI_AVAILABLE = True
except ImportError:
    DPAPI_AVAILABLE = False

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

def setup_logging(name: str = "soc_dashboard", level: int = logging.INFO) -> logging.Logger:
    """
    Set up a logger with consistent formatting.

    Args:
        name: Logger name
        level: Logging level (default INFO)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    logger.setLevel(level)
    return logger


# Create default logger
logger = setup_logging()


# ============================================================================
# HTML SANITIZATION (XSS Prevention)
# ============================================================================

def escape_html(text: Any) -> str:
    """
    Escape HTML special characters to prevent XSS attacks.

    Args:
        text: Input text (any type, will be converted to string)

    Returns:
        HTML-escaped string safe for rendering
    """
    if text is None:
        return ""

    # Convert to string if not already
    text_str = str(text)

    # Use Python's built-in HTML escaping
    return html.escape(text_str, quote=True)


def sanitize_for_html(data: Union[str, Dict, List, Any]) -> Union[str, Dict, List, Any]:
    """
    Recursively sanitize data for safe HTML rendering.

    Args:
        data: Input data (string, dict, list, or other)

    Returns:
        Sanitized data structure
    """
    if isinstance(data, str):
        return escape_html(data)
    elif isinstance(data, dict):
        return {k: sanitize_for_html(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_for_html(item) for item in data]
    elif data is None:
        return ""
    else:
        return escape_html(str(data))


def safe_html_value(value: Any, max_length: int = 500, default: str = "") -> str:
    """
    Get a safe HTML value with length limiting.

    Args:
        value: Input value
        max_length: Maximum length before truncation
        default: Default value if input is empty/None

    Returns:
        Escaped and truncated string
    """
    if value is None or value == "":
        return default

    text = escape_html(str(value))

    if len(text) > max_length:
        return text[:max_length] + "..."

    return text


# ============================================================================
# CREDENTIAL MASKING
# ============================================================================

# Patterns that indicate sensitive data
SENSITIVE_PATTERNS = [
    # API keys and tokens
    (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', r'\1=***MASKED***'),
    (r'(?i)(token|bearer|auth)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,})["\']?', r'\1=***MASKED***'),
    (r'(?i)(secret|private[_-]?key)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{10,})["\']?', r'\1=***MASKED***'),

    # Passwords
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{4,})["\']?', r'\1=***MASKED***'),

    # Connection strings
    (r'(?i)(connectionstring|connstr)\s*[=:]\s*["\']?(.+?)["\']?\s*(?:;|$)', r'\1=***MASKED***'),

    # AWS keys
    (r'AKIA[0-9A-Z]{16}', '***AWS_KEY_MASKED***'),
    (r'(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', r'\1=***MASKED***'),

    # Azure keys
    (r'(?i)(azure[_-]?key|storage[_-]?key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40,})["\']?', r'\1=***MASKED***'),

    # Private keys
    (r'-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----.*?-----END \1?PRIVATE KEY-----', '***PRIVATE_KEY_MASKED***'),

    # Credit card numbers (basic pattern)
    (r'\b(?:\d{4}[- ]?){3}\d{4}\b', '***CARD_MASKED***'),

    # SSN pattern
    (r'\b\d{3}[- ]?\d{2}[- ]?\d{4}\b', '***SSN_MASKED***'),
]


def mask_credentials(text: Any) -> str:
    """
    Mask sensitive information in text.

    Args:
        text: Input text that may contain credentials

    Returns:
        Text with sensitive information masked
    """
    if text is None:
        return ""

    result = str(text)

    for pattern, replacement in SENSITIVE_PATTERNS:
        try:
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE | re.DOTALL)
        except re.error:
            continue

    return result


def safe_display_value(value: Any, mask_sensitive: bool = True, escape: bool = True) -> str:
    """
    Prepare a value for safe display (masked and escaped).

    Args:
        value: Input value
        mask_sensitive: Whether to mask credentials
        escape: Whether to HTML-escape

    Returns:
        Safe display string
    """
    if value is None:
        return ""

    result = str(value)

    if mask_sensitive:
        result = mask_credentials(result)

    if escape:
        result = escape_html(result)

    return result


# ============================================================================
# DATA VALIDATION
# ============================================================================

def validate_path(path: str) -> bool:
    """
    Validate that a path is safe (no path traversal).

    Args:
        path: File path to validate

    Returns:
        True if path is safe
    """
    if not path:
        return False

    # Check for path traversal attempts
    if '..' in path:
        logger.warning("Path traversal attempt detected: %s", path)
        return False

    # Normalize and check
    try:
        normalized = os.path.normpath(path)

        # On Windows, allow standard paths like C:\folder
        # Only reject if there are multiple drive letters (e.g., C:\folder\D:\other)
        if os.name == 'nt':
            # Count colons - Windows paths should have at most one (in drive letter)
            colon_count = normalized.count(':')
            if colon_count > 1:
                logger.warning("Multiple drive letters detected: %s", path)
                return False

        return True
    except Exception:
        return False


def validate_json_structure(data: Any, expected_type: type = list) -> bool:
    """
    Validate JSON data structure.

    Args:
        data: Parsed JSON data
        expected_type: Expected top-level type

    Returns:
        True if valid
    """
    if data is None:
        return False

    if not isinstance(data, expected_type):
        logger.warning("Invalid JSON structure: expected %s, got %s",
                      expected_type.__name__, type(data).__name__)
        return False

    return True


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename for safe use.

    Args:
        filename: Input filename

    Returns:
        Sanitized filename
    """
    if not filename:
        return ""

    # Remove path components
    filename = os.path.basename(filename)

    # Remove dangerous characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)

    # Limit length
    max_length = 255
    if len(filename) > max_length:
        name, ext = os.path.splitext(filename)
        filename = name[:max_length - len(ext)] + ext

    return filename


def validate_record(record: Dict, required_fields: List[str]) -> tuple:
    """
    Validate a record has required fields.

    Args:
        record: Dictionary to validate
        required_fields: List of required field names

    Returns:
        Tuple of (is_valid, missing_fields)
    """
    if not isinstance(record, dict):
        return False, required_fields

    missing = [f for f in required_fields if f not in record]
    return len(missing) == 0, missing


def safe_int(value: Any, default: int = 0) -> int:
    """
    Safely convert value to integer.

    Args:
        value: Input value
        default: Default if conversion fails

    Returns:
        Integer value
    """
    try:
        if value is None:
            return default
        return int(value)
    except (ValueError, TypeError):
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    """
    Safely convert value to float.

    Args:
        value: Input value
        default: Default if conversion fails

    Returns:
        Float value
    """
    try:
        if value is None:
            return default
        return float(value)
    except (ValueError, TypeError):
        return default


def safe_str(value: Any, default: str = "", max_length: int = 0) -> str:
    """
    Safely convert value to string with optional length limit.

    Args:
        value: Input value
        default: Default if conversion fails
        max_length: Maximum length (0 = unlimited)

    Returns:
        String value
    """
    try:
        if value is None:
            return default
        result = str(value)
        if max_length > 0 and len(result) > max_length:
            return result[:max_length]
        return result
    except Exception:
        return default


# ============================================================================
# ERROR HANDLING HELPERS
# ============================================================================

def safe_execute(func, *args, default=None, log_error=True, **kwargs):
    """
    Execute a function with error handling.

    Args:
        func: Function to execute
        *args: Positional arguments
        default: Default return value on error
        log_error: Whether to log errors
        **kwargs: Keyword arguments

    Returns:
        Function result or default on error
    """
    try:
        return func(*args, **kwargs)
    except Exception as e:
        if log_error:
            logger.error("Error in %s: %s", func.__name__, str(e))
        return default


class SafeContext:
    """Context manager for safe execution with error handling."""

    def __init__(self, operation_name: str, reraise: bool = False):
        self.operation_name = operation_name
        self.reraise = reraise
        self.error = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.error = exc_val
            logger.error("Error in %s: %s", self.operation_name, str(exc_val))
            if self.reraise:
                return False
            return True  # Suppress exception
        return False


# ============================================================================
# SECURE API KEY STORAGE
# ============================================================================

class SecureKeyStorage:
    """
    Secure storage for API keys using Windows DPAPI or obfuscation fallback.

    DPAPI (Data Protection API) encrypts data using the user's Windows credentials,
    meaning only the same user on the same machine can decrypt the keys.
    """

    def __init__(self, config_path: str = None):
        """
        Initialize secure key storage.

        Args:
            config_path: Path to encrypted config file. Defaults to config/api_keys.enc
        """
        if config_path is None:
            # Get the base path (works for both dev and USB deployment)
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            config_path = os.path.join(base, "config", "api_keys.enc")

        self.config_path = config_path
        self.plaintext_path = config_path.replace(".enc", ".json")
        self._cache: Dict[str, str] = {}

    def _encrypt_dpapi(self, data: str) -> bytes:
        """Encrypt data using Windows DPAPI."""
        if not DPAPI_AVAILABLE:
            raise RuntimeError("DPAPI not available")
        return win32crypt.CryptProtectData(
            data.encode('utf-8'),
            "SOC Dashboard API Keys",
            None, None, None, 0
        )

    def _decrypt_dpapi(self, encrypted: bytes) -> str:
        """Decrypt data using Windows DPAPI."""
        if not DPAPI_AVAILABLE:
            raise RuntimeError("DPAPI not available")
        desc, decrypted = win32crypt.CryptUnprotectData(
            encrypted, None, None, None, 0
        )
        return decrypted.decode('utf-8')

    def _obfuscate(self, data: str) -> str:
        """Simple obfuscation fallback (not cryptographically secure)."""
        # XOR with a fixed key derived from machine-specific info
        machine_key = os.environ.get('COMPUTERNAME', 'default')[:16].ljust(16, 'x')
        result = []
        for i, char in enumerate(data):
            result.append(chr(ord(char) ^ ord(machine_key[i % len(machine_key)])))
        return base64.b64encode(''.join(result).encode('latin-1')).decode('ascii')

    def _deobfuscate(self, data: str) -> str:
        """Reverse obfuscation."""
        machine_key = os.environ.get('COMPUTERNAME', 'default')[:16].ljust(16, 'x')
        decoded = base64.b64decode(data.encode('ascii')).decode('latin-1')
        result = []
        for i, char in enumerate(decoded):
            result.append(chr(ord(char) ^ ord(machine_key[i % len(machine_key)])))
        return ''.join(result)

    def store_keys(self, keys: Dict[str, str]) -> bool:
        """
        Securely store API keys.

        Args:
            keys: Dictionary of key names to key values

        Returns:
            True if successful
        """
        try:
            json_data = json.dumps(keys)

            if DPAPI_AVAILABLE:
                # Use DPAPI for secure encryption
                encrypted = self._encrypt_dpapi(json_data)
                with open(self.config_path, 'wb') as f:
                    f.write(encrypted)
                logger.info("API keys stored with DPAPI encryption")
            else:
                # Fallback to obfuscation (less secure but better than plaintext)
                obfuscated = self._obfuscate(json_data)
                with open(self.config_path, 'w') as f:
                    json.dump({"_obfuscated": obfuscated}, f)
                logger.warning("API keys stored with obfuscation (DPAPI not available)")

            # Clear plaintext file if it exists
            if os.path.exists(self.plaintext_path):
                self._clear_plaintext_file()

            self._cache = keys.copy()
            return True

        except Exception as e:
            logger.error("Failed to store API keys: %s", e)
            return False

    def load_keys(self) -> Dict[str, str]:
        """
        Load API keys from secure storage.

        Returns:
            Dictionary of key names to key values
        """
        if self._cache:
            return self._cache.copy()

        # Try encrypted file first
        if os.path.exists(self.config_path):
            try:
                if DPAPI_AVAILABLE:
                    with open(self.config_path, 'rb') as f:
                        encrypted = f.read()
                    json_data = self._decrypt_dpapi(encrypted)
                    self._cache = json.loads(json_data)
                    return self._cache.copy()
                else:
                    with open(self.config_path, 'r') as f:
                        data = json.load(f)
                    if "_obfuscated" in data:
                        json_data = self._deobfuscate(data["_obfuscated"])
                        self._cache = json.loads(json_data)
                        return self._cache.copy()
            except Exception as e:
                logger.warning("Failed to load encrypted keys: %s", e)

        # Fallback to plaintext file (for migration)
        if os.path.exists(self.plaintext_path):
            try:
                with open(self.plaintext_path, 'r') as f:
                    data = json.load(f)
                # Filter out comments and empty values
                keys = {k: v for k, v in data.items()
                        if not k.startswith('_') and v}
                if keys:
                    # Auto-migrate to encrypted storage
                    logger.info("Migrating plaintext API keys to encrypted storage")
                    self.store_keys(keys)
                return keys
            except Exception as e:
                logger.warning("Failed to load plaintext keys: %s", e)

        return {}

    def get_key(self, key_name: str) -> Optional[str]:
        """
        Get a specific API key.

        Args:
            key_name: Name of the key (e.g., 'virustotal_api_key')

        Returns:
            The API key value or None if not found
        """
        keys = self.load_keys()
        return keys.get(key_name)

    def set_key(self, key_name: str, key_value: str) -> bool:
        """
        Set a specific API key.

        Args:
            key_name: Name of the key
            key_value: Value of the key

        Returns:
            True if successful
        """
        keys = self.load_keys()
        keys[key_name] = key_value
        return self.store_keys(keys)

    def _clear_plaintext_file(self):
        """Securely clear the plaintext API keys file."""
        try:
            # Overwrite with empty template before deleting
            with open(self.plaintext_path, 'w') as f:
                json.dump({
                    "virustotal_api_key": "",
                    "abuseipdb_api_key": "",
                    "_comment": "Keys have been migrated to encrypted storage (api_keys.enc)"
                }, f, indent=4)
            logger.info("Plaintext API keys file cleared")
        except Exception as e:
            logger.warning("Failed to clear plaintext file: %s", e)


# Global instance for easy access
_key_storage: Optional[SecureKeyStorage] = None


def get_key_storage() -> SecureKeyStorage:
    """Get the global secure key storage instance."""
    global _key_storage
    if _key_storage is None:
        _key_storage = SecureKeyStorage()
    return _key_storage


def get_api_key(key_name: str) -> Optional[str]:
    """
    Convenience function to get an API key.

    Args:
        key_name: Name of the key (e.g., 'virustotal_api_key')

    Returns:
        The API key value or None
    """
    return get_key_storage().get_key(key_name)
