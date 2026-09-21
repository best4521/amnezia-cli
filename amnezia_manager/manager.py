"""High-level orchestration: the API behind every CLI command.

Design: **the SQLite database is the source of truth**. Each mutating call
updates the DB and then calls :meth:`AmneziaManager.sync`, which rewrites the
container's ``wg0.conf`` peer list from the set of *active* users (enabled and
not expired) and reloads the interface in place with ``syncconf`` - so existing
sessions for untouched peers are never dropped.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone

from .backend import Backend, make_backend
from .config import Config
from .database import Database, User
from .errors import AmneziaCliError, ContainerError, ValidationError
from .logging_setup import get_logger
from .qr import render_ascii, save_png
from .validators import parse_expiration, parse_traffic_limit, utcnow_iso, validate_username
from . import wireguard as wg

log = get_logger("manager")


@dataclass
class ServerContext:
    """Everything read once from the running container to build client configs."""

    interface: dict[str, str]
    interface_raw: str
    server_public_key: str
    endpoint_host: str
    endpoint_port: int

    @property
    def endpoint(self) -> str:
        return f"{self.endpoint_host}:{self.endpoint_port}"

    @property
    def awg_params(self) -> dict[str, str]:
        return {k: self.interface[k] for k in wg.AWG_INTERFACE_KEYS if k in self.interface}


@dataclass
class SyncReport:
    active_peers: int
    total_users: int
    applied: bool
    detail: str = ""


@dataclass
class QuotaReport:
    checked: int
    disabled: list[str]
    sync: "SyncReport | None"


class AmneziaManager:
    def __init__(self, config: Config, *, backend: Backend | None = None) -> None:
        self.config = config
        self.db = Database(config.db_path)
        self.backend = backend or make_backend(config)
        self._ctx: ServerContext | None = None

    # -- lifecycle ---------------------------------------------------
    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> "AmneziaManager":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- paths -----------------------------------------------------
    @property
    def _conf_path(self) -> str:
        return f"{self.config.server_dir.rstrip('/')}/{self.config.config_filename}"

    @property
    def _clients_table_path(self) -> str:
        return f"{self.config.server_dir.rstrip('/')}/{self.config.clients_table_filename}"

    @property
    def _users_dump_path(self) -> str:
        return f"{self.config.server_dir.rstrip('/')}/amnezia_cli_users.json"

    # -- server context ------------------------------------------
    def server_context(self, *, refresh: bool = False) -> ServerContext:
        """Read (and cache) interface + endpoint details from the container."""
        if self._ctx is not None and not refresh:
            return self._ctx

        self.backend.health_check()
        raw = self.backend.read_file(self._conf_path)
        parsed = wg.parse_config(raw)
        if not parsed.interface:
            raise ContainerError(
                f"{self._conf_path} has no [Interface] section - is this an AmneziaWG container?"
            )

        server_pub = self._resolve_server_pubkey(parsed.interface)
        host = self._resolve_endpoint_host()
        port = (
            self.config.endpoint_port
            or wg.parse_listen_port(parsed.interface)
            or 51820
        )

        self._ctx = ServerContext(
            interface=parsed.interface,
            interface_raw=parsed.interface_raw,
            server_public_key=server_pub,
            endpoint_host=host,
            endpoint_port=int(port),
        )
        log.debug("server context: endpoint=%s pubkey=%s", self._ctx.endpoint, server_pub[:12] + "…")
        return self._ctx

    def _resolve_server_pubkey(self, interface: dict[str, str]) -> str:
        pub_path = f"{self.config.server_dir.rstrip('/')}/{self.config.server_pubkey_filename}"
        try:
            value = self.backend.read_file(pub_path).strip()
            if value:
                return value
        except ContainerError:
            pass
        priv = interface.get("PrivateKey")
        if not priv:
            raise ContainerError("cannot determine server public key: no key file, no PrivateKey")
        return self.backend.pipe_into(priv, f"{self.backend.wg} pubkey").stdout.strip()

    def _resolve_endpoint_host(self) -> str:
        configured = (self.config.endpoint_host or "auto").strip()
        if configured.lower() != "auto":
            return configured
        probes = (
            "curl -fsS --max-time 8 https://api.ipify.org",
            "curl -fsS --max-time 8 https://ifconfig.me",
            "wget -qO- --timeout=8 https://ipinfo.io/ip",
        )
        result = self.backend.exec(" || ".join(probes), check=False)
        ip = result.stdout.strip().splitlines()[0].strip() if result.stdout.strip() else ""
        if not ip:
            raise ContainerError(
                "could not auto-detect the server's public IP; set 'endpoint_host' in the config"
            )
        return ip

    # -- key material -------------------------------------------
    def _generate_keypair(self) -> tuple[str, str, str]:
        wg_bin = self.backend.wg
        private = self.backend.exec(f"{wg_bin} genkey").stdout.strip()
        public = self.backend.pipe_into(private, f"{wg_bin} pubkey").stdout.strip()
        psk = self.backend.exec(f"{wg_bin} genpsk").stdout.strip()
        if not (private and public and psk):
            raise ContainerError("key generation returned empty output")
        return private, public, psk

    # -- commands ----------------------------------------------
    def create_user(
        self,
        username: str,
        *,
        expiration: str | None = None,
        note: str | None = None,
        traffic_limit: str | None = None,
    ) -> User:
        username = validate_username(username)
        if self.db.get_user(username) is not None:
            from .errors import UserExistsError

            raise UserExistsError(username)
        expires_at = parse_expiration(expiration) if expiration is not None else None
        traffic_limit_bytes = (
            parse_traffic_limit(traffic_limit) if traffic_limit is not None else None
        )

        ctx = self.server_context()
        private, public, psk = self._generate_keypair()
        address = wg.allocate_address(ctx.interface, self._all_taken_addresses())

        user = self.db.create_user(
            username=username,
            private_key=private,
            public_key=public,
            preshared_key=psk,
            address=address,
            expires_at=expires_at,
            note=note,
            traffic_limit_bytes=traffic_limit_bytes,
        )
        log.info("created user %s (%s, expires=%s)", username, address, expires_at or "never")
        self.db.audit("create-user", username=username, detail=address)
        self.sync()
        return user

    def set_traffic_limit(self, username: str, value: str) -> User:
        username = validate_username(username)
        self.db.require_user(username)
        limit_bytes = parse_traffic_limit(value)
        user = self.db.set_traffic_limit(username, limit_bytes)
        log.info("set-traffic-limit: %s -> %s", username, limit_bytes if limit_bytes else "unlimited")
        self.db.audit("set-traffic-limit", username=username,
                      detail=str(limit_bytes) if limit_bytes else "unlimited")
        self.sync()
        return user

    def list_users(self) -> list[User]:
        return self.db.list_users()

    def _all_taken_addresses(self) -> set[str]:
        """Addresses to avoid when allocating a new one.

        Union of what the database has assigned *and* whatever is actually
        live in the container's peer list right now (e.g. clients created
        directly through the Amnezia app) - the database alone doesn't know
        about those, and colliding with one breaks routing for both peers.
        """
        current = wg.parse_config(self.backend.read_file(self._conf_path))
        live = {p.allowed_ips for p in current.peers if p.allowed_ips}
        return self.db.used_addresses() | live

    def set_enabled(self, username: str, enabled: bool) -> User:
        username = validate_username(username)
        self.db.require_user(username)
        user = self.db.set_enabled(username, enabled)
        action = "enable-user" if enabled else "disable-user"
        log.info("%s: %s", action, username)
        self.db.audit(action, username=username)
        self.sync()
        return user

    def set_expiration(self, username: str, expiration: str) -> User:
        username = validate_username(username)
        self.db.require_user(username)
        expires_at = parse_expiration(expiration)
        user = self.db.set_expiration(username, expires_at)
        log.info("set-expiration: %s -> %s", username, expires_at or "never")
        self.db.audit("set-expiration", username=username, detail=expires_at or "never")
        self.sync()
        return user

    def delete_user(self, username: str) -> User:
        username = validate_username(username)
        user = self.db.delete_user(username)
        log.info("deleted user %s (%s)", username, user.address)
        self.db.audit("delete-user", username=username, detail=user.address)
        self.sync()
        return user

    def rekey_user(self, username: str) -> User:
        username = validate_username(username)
        self.db.require_user(username)
        private, public, psk = self._generate_keypair()
        user = self.db.rekey(username, private_key=private, public_key=public, preshared_key=psk)
        log.info("rekeyed user %s", username)
        self.db.audit("rekey-user", username=username)
        self.sync()
        return user

    # -- client config / QR ----------------------------------
    def client_config(self, username: str) -> str:
        username = validate_username(username)
        user = self.db.require_user(username)
        ctx = self.server_context()
        return wg.build_client_config(
            private_key=user.private_key,
            address=user.address,
            dns=self.config.dns,
            awg_params=ctx.awg_params,
            server_public_key=ctx.server_public_key,
            preshared_key=user.preshared_key,
            endpoint=ctx.endpoint,
            allowed_ips=self.config.client_allowed_ips,
            persistent_keepalive=self.config.persistent_keepalive,
        )

    def qr_ascii(self, username: str) -> str:
        return render_ascii(self.client_config(username))

    def qr_png(self, username: str, dest: str) -> str:
        return str(save_png(self.client_config(username), dest))

    # -- sync -------------------------------------------------
    def sync(self) -> SyncReport:
        """Rewrite the container peer list from active users and reload the interface."""
        ctx = self.server_context()
        all_users = self.db.list_users()
        active = [u for u in all_users if u.active]
        managed_keys = {u.public_key for u in all_users}

        # Preserve any peers already in wg0.conf that this tool does not manage
        # (e.g. clients created through the Amnezia app), so sync is non-destructive.
        # Peers whose key we ourselves retired (delete-user/rekey-user) are the one
        # exception: they must NOT come back as "foreign", or every delete/rekey
        # would leak an orphaned peer forever.
        retired_keys = self.db.retired_keys()
        current = wg.parse_config(self.backend.read_file(self._conf_path))
        foreign = [
            wg.Peer(
                public_key=p.public_key,
                preshared_key=p.preshared_key,
                allowed_ips=p.allowed_ips,
                endpoint=p.endpoint,
                comment=p.comment or "unmanaged (not created by amnezia_cli)",
            )
            for p in current.peers
            if p.public_key and p.public_key not in managed_keys
            and p.public_key not in retired_keys
        ]
        if foreign:
            log.info("preserving %d unmanaged peer(s) already in wg0.conf", len(foreign))

        managed = [
            wg.Peer(
                public_key=u.public_key,
                preshared_key=u.preshared_key,
                allowed_ips=u.address,
                comment=u.username,
            )
            for u in active
        ]
        new_conf = wg.build_server_config(ctx.interface_raw, foreign + managed)
        self.backend.write_file(self._conf_path, new_conf, mode=0o600)

        applied, detail = self._reload_interface()
        self._write_clients_table(all_users)
        self._dump_users(all_users)

        report = SyncReport(
            active_peers=len(active),
            total_users=len(all_users),
            applied=applied,
            detail=detail,
        )
        log.info(
            "sync: %d/%d users active, interface reload %s",
            report.active_peers, report.total_users, "ok" if applied else f"skipped ({detail})",
        )
        return report

    def _reload_interface(self) -> tuple[bool, str]:
        iface = self.config.interface
        tmp = "/tmp/amnezia-cli-sync.conf"
        script = (
            f"{self.backend.wg_quick} strip {self._conf_path} > {tmp} && "
            f"{self.backend.wg} syncconf {iface} {tmp}; rc=$?; rm -f {tmp}; exit $rc"
        )
        result = self.backend.exec(script, check=False)
        if result.exit_code == 0:
            return True, "syncconf"
        msg = result.output or f"exit {result.exit_code}"
        log.warning("interface reload failed: %s", msg)
        return False, msg

    def _write_clients_table(self, users: list[User]) -> None:
        """Keep Amnezia's ``clientsTable`` roughly in step (best effort, cosmetic)."""
        try:
            entries = [
                {
                    "clientId": u.public_key,
                    "userData": {
                        "clientName": u.username,
                        "creationDate": _amnezia_date(u.created_at),
                        "cliStatus": u.status,
                        "cliAddress": u.address,
                        "cliExpiresAt": u.expires_at or "",
                    },
                }
                for u in users
            ]
            self.backend.write_file(
                self._clients_table_path, json.dumps(entries, indent=4), mode=0o600
            )
        except AmneziaCliError as exc:
            log.warning("could not update clientsTable: %s", exc)

    def _dump_users(self, users: list[User]) -> None:
        """Write a JSON snapshot onto the container's persistent volume for recovery."""
        try:
            payload = {
                "generated_at": utcnow_iso(),
                "endpoint": self.server_context().endpoint,
                "users": [
                    {
                        "username": u.username,
                        "public_key": u.public_key,
                        "address": u.address,
                        "status": u.status,
                        "enabled": u.enabled,
                        "expires_at": u.expires_at,
                        "created_at": u.created_at,
                        "note": u.note,
                        "traffic_limit_bytes": u.traffic_limit_bytes,
                        "traffic_used_bytes": u.traffic_used_bytes,
                    }
                    for u in users
                ],
            }
            self.backend.write_file(
                self._users_dump_path, json.dumps(payload, indent=2), mode=0o600
            )
        except AmneziaCliError as exc:
            log.warning("could not write users snapshot: %s", exc)

    # -- traffic quotas ---------------------------------------
    def _poll_transfer(self) -> dict[str, tuple[int, int]]:
        """Return ``{public_key: (rx_bytes, tx_bytes)}`` from ``wg show <iface> transfer``."""
        iface = self.config.interface
        result = self.backend.exec(f"{self.backend.wg} show {iface} transfer", check=False)
        usage: dict[str, tuple[int, int]] = {}
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            pubkey = parts[0].strip()
            try:
                usage[pubkey] = (int(parts[1]), int(parts[2]))
            except ValueError:
                continue
        return usage

    def enforce_quotas(self) -> QuotaReport:
        """Accumulate live transfer counters and disable any user over their lifetime cap.

        Also runs :meth:`sync`, which drops any user whose *expiration* has passed
        in the meantime - so this single call is what a cron job needs to enforce
        both the time limit and the traffic limit.
        """
        transfer = self._poll_transfer()
        active = self.db.active_users()
        disabled: list[str] = []
        for user in active:
            rx, tx = transfer.get(user.public_key, (0, 0))
            delta_rx = rx - user.last_rx_bytes if rx >= user.last_rx_bytes else rx
            delta_tx = tx - user.last_tx_bytes if tx >= user.last_tx_bytes else tx
            used = user.traffic_used_bytes + delta_rx + delta_tx
            self.db.record_usage(user.username, used_bytes=used, rx_bytes=rx, tx_bytes=tx)
            if user.traffic_limit_bytes is not None and used >= user.traffic_limit_bytes:
                self.db.set_enabled(user.username, False)
                self.db.audit(
                    "disable-user", username=user.username,
                    detail=f"quota exceeded ({used}/{user.traffic_limit_bytes} bytes)",
                )
                log.info(
                    "disabled %s: quota exceeded (%d/%d bytes)",
                    user.username, used, user.traffic_limit_bytes,
                )
                disabled.append(user.username)
        report = self.sync()
        return QuotaReport(checked=len(active), disabled=disabled, sync=report)

    # -- diagnostics ----------------------------------------
    def doctor(self) -> dict[str, str]:
        """Return a dict of environment facts, raising nothing that isn't fatal."""
        facts: dict[str, str] = {"db_path": self.config.db_path}
        self.backend.health_check()
        facts["container"] = self.config.container_name
        facts["wg_binary"] = self.backend.wg
        facts["wg_quick_binary"] = self.backend.wg_quick
        ctx = self.server_context()
        facts["endpoint"] = ctx.endpoint
        facts["server_public_key"] = ctx.server_public_key
        facts["tunnel_network"] = str(wg.interface_network(ctx.interface))
        facts["awg_params"] = ", ".join(f"{k}={v}" for k, v in ctx.awg_params.items()) or "(none)"
        facts["users_total"] = str(len(self.db.list_users()))
        facts["users_active"] = str(len(self.db.active_users()))
        return facts


def _amnezia_date(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%a %b %d %H:%M:%S %Y")
    except ValueError:
        return iso
