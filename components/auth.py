"""
Authentication Component - PIN/password protection for dashboard.

Security features:
- PBKDF2 password hashing with salt
- Rate limiting on failed attempts
- Session timeout
"""
import hashlib
import hmac
import os
import json
import secrets
import time
import streamlit as st
from typing import Optional, Tuple
from datetime import datetime, timedelta

# Security constants
PBKDF2_ITERATIONS = 100000  # OWASP recommended minimum
LOCKOUT_THRESHOLD = 5  # Failed attempts before lockout
LOCKOUT_DURATION_SECONDS = 300  # 5 minute lockout
SESSION_TIMEOUT_MINUTES = 60  # Default session timeout

# Default PIN hash (using legacy format for backwards compatibility)
DEFAULT_PIN_HASH = hashlib.sha256("1234".encode()).hexdigest()


def get_config_path() -> str:
    """Get path to auth config file."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_dir, "config", "auth_config.json")


def load_auth_config() -> dict:
    """Load authentication configuration."""
    config_path = get_config_path()
    default_config = {
        "enabled": True,
        "pin_hash": DEFAULT_PIN_HASH,
        "first_run": True,
        "session_timeout_minutes": 60
    }

    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
                # Merge with defaults for any missing keys
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                return config
    except Exception:
        pass

    return default_config


def save_auth_config(config: dict):
    """Save authentication configuration."""
    config_path = get_config_path()
    try:
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        st.error(f"Failed to save config: {e}")


def hash_pin_pbkdf2(pin: str, salt: bytes = None) -> Tuple[str, str]:
    """
    Hash a PIN using PBKDF2-HMAC-SHA256 with salt.

    Args:
        pin: The PIN to hash
        salt: Optional salt (generated if not provided)

    Returns:
        Tuple of (hash_hex, salt_hex)
    """
    if salt is None:
        salt = secrets.token_bytes(32)
    key = hashlib.pbkdf2_hmac('sha256', pin.encode(), salt, PBKDF2_ITERATIONS)
    return key.hex(), salt.hex()


def hash_pin(pin: str) -> str:
    """Hash a PIN using SHA-256 (legacy, for backwards compatibility)."""
    return hashlib.sha256(pin.encode()).hexdigest()


def verify_pin(pin: str, config: dict) -> bool:
    """
    Verify if the provided PIN matches the stored hash.
    Supports both legacy SHA-256 and new PBKDF2 formats.
    """
    stored_hash = config.get("pin_hash", DEFAULT_PIN_HASH)
    stored_salt = config.get("pin_salt")

    if stored_salt:
        # New PBKDF2 format
        computed_hash, _ = hash_pin_pbkdf2(pin, bytes.fromhex(stored_salt))
        return hmac.compare_digest(computed_hash, stored_hash)
    else:
        # Legacy SHA-256 format
        return hmac.compare_digest(hash_pin(pin), stored_hash)


def check_rate_limit(config: dict) -> Tuple[bool, int]:
    """
    Check if login attempts are rate limited.

    Returns:
        Tuple of (is_locked, seconds_remaining)
    """
    lockout_until = config.get("lockout_until", 0)
    if lockout_until > time.time():
        return True, int(lockout_until - time.time())
    return False, 0


def record_failed_attempt(config: dict) -> dict:
    """Record a failed login attempt and update lockout if threshold reached."""
    failed_attempts = config.get("failed_attempts", 0) + 1
    config["failed_attempts"] = failed_attempts

    if failed_attempts >= LOCKOUT_THRESHOLD:
        config["lockout_until"] = time.time() + LOCKOUT_DURATION_SECONDS
        config["failed_attempts"] = 0  # Reset counter after lockout

    save_auth_config(config)
    return config


def clear_failed_attempts(config: dict) -> dict:
    """Clear failed attempt counter on successful login."""
    config["failed_attempts"] = 0
    config["lockout_until"] = 0
    save_auth_config(config)
    return config


def check_session_timeout() -> bool:
    """
    Check if the session has timed out.

    Returns:
        True if session is still valid, False if timed out
    """
    if not st.session_state.get("authenticated", False):
        return False

    last_activity = st.session_state.get("last_activity")
    if last_activity is None:
        return False

    config = load_auth_config()
    timeout_minutes = config.get("session_timeout_minutes", SESSION_TIMEOUT_MINUTES)
    timeout_delta = timedelta(minutes=timeout_minutes)

    if datetime.now() - last_activity > timeout_delta:
        # Session expired
        st.session_state.authenticated = False
        st.session_state.last_activity = None
        return False

    # Update last activity
    st.session_state.last_activity = datetime.now()
    return True


def update_activity():
    """Update the last activity timestamp."""
    if st.session_state.get("authenticated", False):
        st.session_state.last_activity = datetime.now()


def render_login_screen() -> bool:
    """
    Render the login screen.

    Returns:
        True if authenticated, False otherwise
    """
    config = load_auth_config()

    # Check if auth is disabled
    if not config.get("enabled", True):
        return True

    # Check if already authenticated in session
    if st.session_state.get("authenticated", False):
        return True

    # Login UI
    st.markdown('''<div style="display:flex;justify-content:center;align-items:center;min-height:60vh;">
<div style="background:linear-gradient(135deg,#0a0a15 0%,#1a1a2e 50%,#16213e 100%);border-radius:16px;padding:40px 50px;border:1px solid rgba(102,126,234,0.3);box-shadow:0 8px 32px rgba(0,0,0,0.4);max-width:400px;width:100%;">
<div style="text-align:center;margin-bottom:30px;">
<div style="background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);width:80px;height:80px;border-radius:16px;display:flex;align-items:center;justify-content:center;margin:0 auto 20px;box-shadow:0 4px 15px rgba(102,126,234,0.4);">
<span style="font-size:2.5rem;">🛡️</span>
</div>
<div style="color:white;font-size:1.5rem;font-weight:bold;">SOC Forensic Investigator</div>
<div style="color:#888;font-size:0.9rem;margin-top:8px;">Enter PIN to access dashboard</div>
</div>
</div>
</div>''', unsafe_allow_html=True)

    # Center the form
    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        # Check rate limiting first
        is_locked, seconds_remaining = check_rate_limit(config)
        if is_locked:
            st.error(f"Too many failed attempts. Try again in {seconds_remaining} seconds.")
            return False

        # First run - set new PIN
        if config.get("first_run", True):
            st.info("First time setup - please set a new PIN (minimum 6 characters)")
            new_pin = st.text_input("New PIN (6+ characters):", type="password", max_chars=20, key="new_pin")
            confirm_pin = st.text_input("Confirm PIN:", type="password", max_chars=20, key="confirm_pin")

            if st.button("Set PIN & Enter", type="primary", use_container_width=True):
                if not new_pin or len(new_pin) < 6:
                    st.error("PIN must be at least 6 characters")
                elif new_pin != confirm_pin:
                    st.error("PINs do not match")
                else:
                    # Use PBKDF2 for new PINs
                    pin_hash, pin_salt = hash_pin_pbkdf2(new_pin)
                    config["pin_hash"] = pin_hash
                    config["pin_salt"] = pin_salt
                    config["first_run"] = False
                    save_auth_config(config)
                    st.session_state.authenticated = True
                    st.session_state.last_activity = datetime.now()
                    st.success("PIN set successfully!")
                    st.rerun()
        else:
            # Normal login
            pin = st.text_input("Enter PIN:", type="password", max_chars=20, key="login_pin")

            # Show remaining attempts if there have been failures
            failed_attempts = config.get("failed_attempts", 0)
            if failed_attempts > 0:
                remaining = LOCKOUT_THRESHOLD - failed_attempts
                st.caption(f"{remaining} attempts remaining before lockout")

            col_a, col_b = st.columns(2)
            with col_a:
                if st.button("Login", type="primary", use_container_width=True):
                    if verify_pin(pin, config):
                        clear_failed_attempts(config)
                        st.session_state.authenticated = True
                        st.session_state.last_activity = datetime.now()
                        st.rerun()
                    else:
                        record_failed_attempt(config)
                        st.error("Invalid PIN")
                        st.rerun()

            with col_b:
                if st.button("Reset PIN", use_container_width=True):
                    st.session_state.show_reset = True

            # Reset PIN flow
            if st.session_state.get("show_reset", False):
                st.markdown("---")
                st.warning("To reset PIN, delete `config/auth_config.json` and restart")

    return False


def render_logout_button():
    """Render a logout button in the sidebar."""
    if st.session_state.get("authenticated", False):
        if st.sidebar.button("🔒 Logout", use_container_width=True):
            st.session_state.authenticated = False
            st.session_state.last_activity = None
            st.rerun()


def check_auth() -> bool:
    """
    Check if user is authenticated.
    Call this at the start of the dashboard.

    Includes session timeout checking.

    Returns:
        True if authenticated (or auth disabled), False otherwise
    """
    # Initialize session state
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "last_activity" not in st.session_state:
        st.session_state.last_activity = None

    config = load_auth_config()

    # Skip auth if disabled
    if not config.get("enabled", True):
        return True

    # Check for session timeout
    if st.session_state.get("authenticated", False):
        if not check_session_timeout():
            st.warning("Session timed out. Please login again.")
            return False

    return st.session_state.get("authenticated", False)
