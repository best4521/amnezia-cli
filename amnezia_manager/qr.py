"""QR-code rendering for client configs.

Terminal rendering uses ``qrcode`` only (pure Python). PNG output additionally
needs Pillow (``pip install pillow``); we surface a clear error if it's missing.
"""
from __future__ import annotations

import io
from pathlib import Path

from .errors import AmneziaCliError
from .logging_setup import get_logger

log = get_logger("qr")


def _new_qr(data: str):
    try:
        import qrcode
    except ImportError as exc:  # pragma: no cover
        raise AmneziaCliError(
            "the 'qrcode' package is required for QR output (pip install qrcode)"
        ) from exc
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=2,
    )
    qr.add_data(data)
    qr.make(fit=True)
    return qr


def render_ascii(data: str, *, invert: bool = True) -> str:
    """Return the QR code as an ASCII-art string suitable for a dark terminal."""
    qr = _new_qr(data)
    buf = io.StringIO()
    qr.print_ascii(out=buf, invert=invert)
    return buf.getvalue()


def save_png(data: str, dest: str | Path) -> Path:
    """Write the QR code to *dest* as a PNG and return the path."""
    qr = _new_qr(data)
    try:
        img = qr.make_image(fill_color="black", back_color="white")
    except Exception as exc:  # qrcode raises a bare error when PIL is absent
        raise AmneziaCliError(
            f"PNG QR output needs Pillow (pip install pillow): {exc}"
        ) from exc
    dest_path = Path(dest)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    img.save(dest_path)
    log.info("wrote QR PNG to %s", dest_path)
    return dest_path
