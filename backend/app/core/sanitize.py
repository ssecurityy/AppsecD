"""Input sanitization to prevent stored XSS and invalid filenames."""
import os
import bleach

ALLOWED_TAGS = []  # No HTML in display names
ALLOWED_ATTRS = {}


def sanitize_text(value: str, max_length: int = 2000) -> str:
    """Remove HTML/script and control chars. Use for name, application_name, etc."""
    if value is None or not isinstance(value, str):
        return ""
    # Remove null bytes and control characters
    value = "".join(c for c in value if ord(c) >= 32 or c in "\t\n\r")
    value = bleach.clean(value, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)
    value = value.strip()
    if max_length and len(value) > max_length:
        value = value[:max_length]
    return value


def sanitize_filename(filename: str) -> str:
    """
    Return a safe basename: no path components, no null bytes, no leading dots.
    Raises ValueError if result is empty.
    """
    if not filename or not isinstance(filename, str):
        raise ValueError("Invalid filename")
    # Strip null bytes
    filename = filename.replace("\x00", "").strip()
    # Take basename only (no path traversal)
    safe = os.path.basename(filename)
    # Normalize path separators
    safe = safe.replace("\\", "/").split("/")[-1]
    safe = safe.strip(". ")
    if not safe:
        raise ValueError("Invalid filename")
    return safe
