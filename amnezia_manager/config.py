"""Runtime configuration for the Amnezia CLI.

Resolution order (last wins):

1. Built-in defaults (:class:`Config`).
2. A JSON config file. Explicit ``--config PATH`` if given, otherwise the first
   of ``./amnezia_cli.json`` or ``~/.config/amnezia-cli/config.json`` that exists.
3. Environment variables prefixed ``AMNEZIA_CLI_`` (e.g. ``AMNEZIA_CLI_CONTAINER_NAME``).
4. Keyword overrides passed by the CLI layer (from command-line options).
"""
from __future__ import annotations

import dataclasses
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .errors import ConfigError

ENV_PREFIX = "AMNEZIA_CLI_"

DEFAULT_CONFIG_PATHS: tuple[Path, ...] = (
    Path.cwd() / "amnezia_cli.json",
    Path.home() / ".config" / "amnezia-cli" / "config.json",
)


@dataclass
class Config:
    """All knobs the manager needs. Every field is overridable via file/env/flag."""

    # --- Docker / container -------------------------------------------------
    container_name: str = "amnezia-awg"
    docker_base_url: str | None = None  # None -> docker.from_env(); e.g. "ssh://root@host"
    server_dir: str = "/opt/amnezia/awg"  # directory holding wg0.conf inside the container
    interface: str = "wg0"
    config_filename: str = "wg0.conf"
    clients_table_filename: str = "clientsTable"
    server_pubkey_filename: str = "wireguard_server_public_key.key"

    # --- Client-facing tunnel parameters ---------------------------------
    endpoint_host: str = "auto"  # "auto" -> detect the container's public IPv4
    endpoint_port: int = 0  # 0 -> read ListenPort from wg0.conf
    dns: str = "1.1.1.1, 1.0.0.1"
    client_allowed_ips: str = "0.0.0.0/0, ::/0"
    persistent_keepalive: int = 25

    # --- Local state -----------------------------------------------------
    db_path: str = "amnezia_users.db"
    log_path: str = "amnezia_cli.log"
    log_max_bytes: int = 2_000_000
    log_backup_count: int = 3

    # --- Behaviour -----------------------------------------------------
    # When true, talk to an in-memory fake instead of a real container. Handy for
    # the demo, CI and dry experiments. Also toggled by AMNEZIA_CLI_FAKE=1.
    fake_backend: bool = False

    # Path this config was loaded from (informational, not serialised back).
    source_path: str | None = field(default=None, compare=False)

    # ------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        data = dataclasses.asdict(self)
        data.pop("source_path", None)
        return data

    def with_overrides(self, **overrides: Any) -> "Config":
        """Return a copy with the given non-None overrides applied."""
        clean = {k: v for k, v in overrides.items() if v is not None}
        unknown = set(clean) - {f.name for f in dataclasses.fields(self)}
        if unknown:
            raise ConfigError(f"unknown config override(s): {', '.join(sorted(unknown))}")
        return dataclasses.replace(self, **clean)


def _coerce(field_type: Any, raw: str) -> Any:
    if field_type is bool or field_type == "bool":
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    if field_type is int or field_type == "int":
        try:
            return int(raw)
        except ValueError as exc:
            raise ConfigError(f"expected an integer, got {raw!r}") from exc
    return raw


def _apply_env(cfg: Config) -> Config:
    updates: dict[str, Any] = {}
    field_types = {f.name: f.type for f in dataclasses.fields(Config)}
    for name, ftype in field_types.items():
        env_key = ENV_PREFIX + name.upper()
        if env_key in os.environ:
            updates[name] = _coerce(ftype, os.environ[env_key])
    # Convenience alias.
    if os.environ.get(ENV_PREFIX + "FAKE", "").strip().lower() in {"1", "true", "yes", "on"}:
        updates["fake_backend"] = True
    return dataclasses.replace(cfg, **updates) if updates else cfg


def load_config(path: str | os.PathLike[str] | None = None, **overrides: Any) -> Config:
    """Build a :class:`Config` from file + environment + explicit overrides.

    Args:
        path: Explicit path to a JSON config file. If ``None`` the default search
            paths are tried; a missing default file is not an error.
        **overrides: Field overrides (typically CLI options). ``None`` values are
            ignored so callers can pass options unconditionally.

    Raises:
        ConfigError: The file is unreadable, not valid JSON, or contains unknown keys.
    """
    cfg = Config()

    candidate: Path | None = None
    if path is not None:
        candidate = Path(path)
        if not candidate.is_file():
            raise ConfigError(f"config file not found: {candidate}")
    else:
        candidate = next((p for p in DEFAULT_CONFIG_PATHS if p.is_file()), None)

    if candidate is not None:
        try:
            raw = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"cannot read config file {candidate}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ConfigError(f"config file {candidate} must contain a JSON object")
        known = {f.name for f in dataclasses.fields(Config)} - {"source_path"}
        unknown = set(raw) - known
        if unknown:
            raise ConfigError(
                f"config file {candidate} has unknown key(s): {', '.join(sorted(unknown))}"
            )
        cfg = dataclasses.replace(cfg, source_path=str(candidate), **raw)

    cfg = _apply_env(cfg)
    cfg = cfg.with_overrides(**overrides)
    return cfg


def write_example_config(dest: str | os.PathLike[str]) -> Path:
    """Write a fully-populated example config to *dest* and return its path."""
    dest_path = Path(dest)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    dest_path.write_text(json.dumps(Config().to_dict(), indent=2) + "\n", encoding="utf-8")
    return dest_path
