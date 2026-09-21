"""In-memory AmneziaWG container simulation.

Enough of a fake to run the full CLI - key generation, config read/write, tool
discovery, public-IP detection and ``syncconf`` - without Docker or a server.
Enabled by ``--fake`` / ``AMNEZIA_CLI_FAKE=1`` / ``config.fake_backend``.

Keys are real random 32-byte base64 blobs; the "public" key is a deterministic
hash of the private key (not a real Curve25519 point) - fine for exercising the
pipeline, obviously not for production.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re

from .backend import Backend, ExecResult
from .config import Config
from .logging_setup import get_logger

log = get_logger("fake")

_DEFAULT_SERVER_PRIV = base64.b64encode(b"amnezia-cli-fake-server-priv-key!").decode()

_STARTER_WG0_CONF = f"""\
[Interface]
Address = 10.8.1.1/24
ListenPort = 51820
PrivateKey = {_DEFAULT_SERVER_PRIV}
Jc = 4
Jmin = 40
Jmax = 70
S1 = 66
S2 = 0
H1 = 1256714129
H2 = 1774876419
H3 = 1521283344
H4 = 2043303484
"""


def _fake_pubkey(private_key: str) -> str:
    try:
        seed = base64.b64decode(private_key, validate=True)
    except Exception:  # noqa: BLE001 - any malformed input
        seed = private_key.encode()
    return base64.b64encode(hashlib.sha256(seed).digest()).decode()


class FakeBackend(Backend):
    """Simulates the subset of container behaviour the manager relies on."""

    PUBLIC_IP = "203.0.113.7"

    def __init__(self, config: Config) -> None:
        super().__init__(config)
        base = config.server_dir.rstrip("/")
        self.fs: dict[str, str] = {
            f"{base}/{config.config_filename}": _STARTER_WG0_CONF,
            f"{base}/{config.server_pubkey_filename}": _fake_pubkey(_DEFAULT_SERVER_PRIV),
        }
        self._synced = 0
        # Test/demo hook: {public_key: (rx_bytes, tx_bytes)}, returned by "wg show
        # <iface> transfer". Empty by default (every peer reports zero usage).
        self.transfer: dict[str, tuple[int, int]] = {}

    # -- Backend interface ---------------------------------------
    def health_check(self) -> None:
        log.debug("fake backend healthy (container=%s)", self.config.container_name)

    def read_file(self, path: str) -> str:
        if path not in self.fs:
            from .errors import ContainerError

            raise ContainerError(f"[fake] no such file in container: {path}")
        return self.fs[path]

    def write_file(self, path: str, content: str, *, mode: int = 0o600) -> None:
        self.fs[path] = content
        log.info("[fake] wrote %d bytes to %s", len(content), path)

    def _exec(self, argv: list[str]) -> ExecResult:
        # Everything the manager runs goes through `sh -c "<script>"`.
        if len(argv) >= 3 and argv[0] == "sh" and argv[1] == "-c":
            return self._run_script(argv[2])
        return self._run_script(" ".join(argv))

    # -- simulated shell ----------------------------------------
    def _run_script(self, script: str) -> ExecResult:
        s = script.strip()

        if "command -v" in s:
            first = s.split("||")[0]
            tool = first.replace("command -v", "").strip()
            return ExecResult(0, f"/usr/bin/{tool}\n", "")

        if s.endswith("genkey") or re.search(r"\b(awg|wg)\s+genkey$", s):
            return ExecResult(0, base64.b64encode(os.urandom(32)).decode() + "\n", "")

        if s.endswith("genpsk") or re.search(r"\b(awg|wg)\s+genpsk$", s):
            return ExecResult(0, base64.b64encode(os.urandom(32)).decode() + "\n", "")

        m = re.match(r"printf %s (?P<key>\S+) \| \S*(?:awg|wg) pubkey", s)
        if m:
            key = m.group("key").strip("'\"")
            return ExecResult(0, _fake_pubkey(key) + "\n", "")

        m = re.match(r"cat (?P<path>\S+)", s)
        if m:
            path = m.group("path").strip("'\"")
            if path in self.fs:
                return ExecResult(0, self.fs[path], "")
            return ExecResult(1, "", f"cat: {path}: No such file or directory")

        if "syncconf" in s or "wg-quick strip" in s or "awg-quick strip" in s:
            self._synced += 1
            log.debug("[fake] syncconf #%d applied", self._synced)
            return ExecResult(0, "", "")

        if re.search(r"\b(awg|wg)\s+show\s+\S+\s+transfer", s):
            lines = [f"{pk}\t{rx}\t{tx}" for pk, (rx, tx) in self.transfer.items()]
            return ExecResult(0, ("\n".join(lines) + "\n") if lines else "", "")

        if re.search(r"\b(awg|wg)\s+show", s):
            return ExecResult(0, "", "")

        if any(tok in s for tok in ("ipify", "ifconfig.me", "ipinfo.io", "icanhazip")):
            return ExecResult(0, self.PUBLIC_IP, "")

        if s.startswith(("mkdir", "chmod", "test ", "true")):
            return ExecResult(0, "", "")

        log.warning("[fake] unhandled script, returning empty success: %s", s)
        return ExecResult(0, "", "")
