"""Input validation and small parsing helpers."""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from .errors import ValidationError

_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")

# Values that explicitly clear an expiration.
_NEVER_TOKENS = {"", "none", "never", "clear", "null", "-"}

_WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")


def validate_username(username: str) -> str:
    """Return the normalised username or raise :class:`ValidationError`.

    Rules: 1-32 chars, ASCII letters/digits plus ``_ . -``, must start
    alphanumeric. This keeps the name safe to embed in shell-free ``exec`` argv,
    config comments and file names.
    """
    if not isinstance(username, str):
        raise ValidationError("username must be a string")
    username = username.strip()
    if not _USERNAME_RE.match(username):
        raise ValidationError(
            f"invalid username {username!r}: use 1-32 chars of [A-Za-z0-9_.-], "
            "starting with a letter or digit"
        )
    return username


def parse_expiration(value: str, *, now: datetime | None = None) -> str | None:
    """Parse a user-supplied expiration into an ISO-8601 UTC string (or ``None``).

    Accepted forms:
        * ``none`` / ``never`` / ``clear`` / ``""``     -> ``None`` (no expiry)
        * ``+30d`` / ``+12h`` / ``+8w``                 -> relative to *now*
        * ``YYYY-MM-DD``                                -> that date at 23:59:59 UTC
        * ``YYYY-MM-DD HH:MM`` / ``YYYY-MM-DDTHH:MM``   -> that instant, UTC
        * ``YYYY-MM-DDTHH:MM:SS[+ZZ:ZZ]``               -> ISO-8601, tz-aware or UTC

    Raises:
        ValidationError: The value matches none of the accepted forms.
    """
    now = now or datetime.now(timezone.utc)
    token = value.strip()
    if token.lower() in _NEVER_TOKENS:
        return None

    rel = re.fullmatch(r"\+(\d+)\s*([dhwm])", token, re.IGNORECASE)
    if rel:
        amount = int(rel.group(1))
        unit = rel.group(2).lower()
        delta = {
            "h": timedelta(hours=amount),
            "d": timedelta(days=amount),
            "w": timedelta(weeks=amount),
            "m": timedelta(days=30 * amount),
        }[unit]
        return _to_utc_iso(now + delta)

    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", token):
        dt = datetime.strptime(token, "%Y-%m-%d").replace(
            hour=23, minute=59, second=59, tzinfo=timezone.utc
        )
        return _to_utc_iso(dt)

    normalised = token.replace(" ", "T")
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(normalised, fmt).replace(tzinfo=timezone.utc)
            return _to_utc_iso(dt)
        except ValueError:
            pass

    try:
        dt = datetime.fromisoformat(normalised)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return _to_utc_iso(dt)
    except ValueError as exc:
        raise ValidationError(
            f"cannot parse date {value!r}. Try YYYY-MM-DD, 'YYYY-MM-DD HH:MM', "
            "'+30d', or 'never'."
        ) from exc


_TRAFFIC_UNITS = {
    "b": 1,
    "kb": 1024,
    "mb": 1024 ** 2,
    "gb": 1024 ** 3,
    "tb": 1024 ** 4,
    "kib": 1024,
    "mib": 1024 ** 2,
    "gib": 1024 ** 3,
    "tib": 1024 ** 4,
}


def parse_traffic_limit(value: str) -> int | None:
    """Parse a user-supplied lifetime traffic cap into a byte count (or ``None``).

    Accepted forms:
        * ``none`` / ``never`` / ``unlimited`` / ``clear`` / ``""`` / ``0`` -> ``None``
        * ``500MB`` / ``50GB`` / ``2TB`` / ``1024`` (bare bytes)           -> byte count

    Units are binary (``1GB`` == 1024**3 bytes), matching WireGuard's own
    ``rx_bytes``/``tx_bytes`` counters.

    Raises:
        ValidationError: The value matches none of the accepted forms.
    """
    token = value.strip()
    if token.lower() in _NEVER_TOKENS or token.lower() == "unlimited":
        return None

    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([A-Za-z]*)", token)
    if not m:
        raise ValidationError(
            f"cannot parse traffic limit {value!r}. Try '50GB', '500MB', a byte "
            "count, or 'unlimited'."
        )
    amount = float(m.group(1))
    unit = m.group(2).lower() or "b"
    if unit not in _TRAFFIC_UNITS:
        raise ValidationError(
            f"unknown traffic unit {m.group(2)!r} in {value!r}; use B/KB/MB/GB/TB"
        )
    total = int(amount * _TRAFFIC_UNITS[unit])
    return total or None


def format_bytes(n: int | None) -> str:
    """Human-readable byte count, e.g. ``1536`` -> ``1.50 KB``."""
    if n is None:
        return "unlimited"
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.2f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{value:.2f} TB"  # pragma: no cover - unreachable, satisfies linters


def is_expired(expires_at: str | None, *, now: datetime | None = None) -> bool:
    """True if *expires_at* (ISO-8601 string) is in the past."""
    if not expires_at:
        return False
    now = now or datetime.now(timezone.utc)
    try:
        dt = datetime.fromisoformat(expires_at)
    except ValueError:
        return False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt <= now


def looks_like_wg_key(value: str) -> bool:
    """Heuristic check that *value* is a base64-encoded 32-byte WireGuard key."""
    return bool(_WG_KEY_RE.match(value.strip()))


def _to_utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def utcnow_iso() -> str:
    """Current time as an ISO-8601 UTC string, second precision."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
