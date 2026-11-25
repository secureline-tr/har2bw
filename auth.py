"""Optional shared-password gate for the local UI (HAR2BW_UI_PASSWORD). Not a user system."""
import hmac
import os

MAX_ATTEMPTS = 5
MIN_LENGTH = 12


def configured_password(env=None):
    """Return the configured password or None. Too-short passwords are rejected, not ignored."""
    value = (env if env is not None else os.environ).get('HAR2BW_UI_PASSWORD', '')
    if not value:
        return None
    if len(value) < MIN_LENGTH:
        raise ValueError(f'HAR2BW_UI_PASSWORD must be at least {MIN_LENGTH} characters')
    return value


def check(expected, supplied):
    """Constant-time comparison of two strings."""
    return hmac.compare_digest(expected.encode(), supplied.encode())
