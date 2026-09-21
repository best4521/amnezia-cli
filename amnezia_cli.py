#!/usr/bin/env python3
"""Amnezia VPN AWG2 (AmneziaWG) management CLI.

Manage AmneziaWG VPN users on a Dockerised Amnezia server: create/list/disable/
enable/expire/delete users, print a QR code or export a ``.conf`` for a client.

The local SQLite database (``amnezia_users.db``) is the source of truth. Every
mutating command updates it and then regenerates the container's ``wg0.conf``
peer list from the active users, reloading the interface in place.

Quick start
-----------
    pip install -r requirements.txt
    ./amnezia_cli.py doctor                       # verify the container is reachable
    ./amnezia_cli.py create-user alice --expires +30d --qr
    ./amnezia_cli.py list-users
    ./amnezia_cli.py export-config alice -o alice.conf

Try it without a server
-----------------------
    ./amnezia_cli.py --fake doctor
    python demo.py                                # provisions 5 demo users offline
"""
from __future__ import annotations

import json
import sys

import click

from amnezia_manager import __version__
from amnezia_manager.config import load_config, write_example_config
from amnezia_manager.errors import AmneziaCliError
from amnezia_manager.logging_setup import configure_logging, get_logger
from amnezia_manager.manager import AmneziaManager
from amnezia_manager.validators import format_bytes

log = get_logger("cli")

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"], "max_content_width": 100}


class AmneziaCLI(click.Group):
    """Group that turns expected errors into a clean message + exit code."""

    def invoke(self, ctx: click.Context):
        try:
            return super().invoke(ctx)
        except AmneziaCliError as exc:
            log.error("%s", exc)
            click.secho(f"error: {exc}", fg="red", err=True)
            ctx.exit(exc.exit_code)
        except KeyboardInterrupt:  # pragma: no cover
            click.secho("aborted", fg="yellow", err=True)
            ctx.exit(130)


def _build_manager(ctx: click.Context) -> AmneziaManager:
    cfg = ctx.obj["config"]
    mgr = AmneziaManager(cfg)
    ctx.call_on_close(mgr.close)
    return mgr


def with_manager(func):
    """Decorator: inject a ready :class:`AmneziaManager` as the first argument."""
    import functools

    @click.pass_context
    @functools.wraps(func)
    def wrapper(ctx: click.Context, *args, **kwargs):
        mgr = _build_manager(ctx)
        return func(mgr, *args, **kwargs)

    return wrapper


# ---------------------------------------------------------------------------
# root group
# ---------------------------------------------------------------------------
@click.group(cls=AmneziaCLI, context_settings=CONTEXT_SETTINGS)
@click.version_option(__version__, "-V", "--version", prog_name="amnezia_cli")
@click.option("--config", "config_path", type=click.Path(dir_okay=False),
              help="Path to a JSON config file (default: ./amnezia_cli.json or "
                   "~/.config/amnezia-cli/config.json).")
@click.option("--db", "db_path", type=click.Path(dir_okay=False),
              help="Override the SQLite database path.")
@click.option("--container", "container_name",
              help="Override the AmneziaWG container name.")
@click.option("--docker-url", "docker_base_url",
              help="Docker base URL, e.g. ssh://root@host or tcp://1.2.3.4:2375.")
@click.option("--endpoint-host",
              help="Public host/IP clients connect to (default: auto-detect).")
@click.option("--fake", is_flag=True, default=None,
              help="Use the in-memory fake backend (no Docker/server needed).")
@click.option("-v", "--verbose", is_flag=True, help="Verbose (DEBUG) console logging.")
@click.pass_context
def cli(ctx: click.Context, config_path, db_path, container_name, docker_base_url,
        endpoint_host, fake, verbose):
    """Manage AmneziaWG (AWG2) VPN users on a Dockerised Amnezia server."""
    try:
        cfg = load_config(
            config_path,
            db_path=db_path,
            container_name=container_name,
            docker_base_url=docker_base_url,
            endpoint_host=endpoint_host,
            fake_backend=fake,
        )
    except AmneziaCliError as exc:
        click.secho(f"error: {exc}", fg="red", err=True)
        ctx.exit(exc.exit_code)

    configure_logging(
        cfg.log_path,
        verbose=verbose,
        max_bytes=cfg.log_max_bytes,
        backup_count=cfg.log_backup_count,
    )
    ctx.obj = {"config": cfg}
    log.debug("config: %s", cfg.to_dict())


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------
@cli.command("create-user")
@click.argument("username")
@click.option("-e", "--expires", "expiration", default=None,
              help="Expiration: YYYY-MM-DD, 'YYYY-MM-DD HH:MM', '+30d', or 'never'.")
@click.option("-n", "--note", default=None, help="Free-text note stored with the user.")
@click.option("-t", "--traffic-limit", "traffic_limit", default=None,
              help="Lifetime traffic cap: '50GB', '500MB', a byte count, or 'unlimited'.")
@click.option("--qr", "show_qr", is_flag=True, help="Also print the config QR code.")
@click.option("--show-config", is_flag=True, help="Also print the client config.")
@click.option("--json", "as_json", is_flag=True,
              help="Emit a JSON object (user record + client config) instead of text - "
                   "for scripted callers such as a Telegram bot.")
@with_manager
def create_user(mgr: AmneziaManager, username, expiration, note, traffic_limit,
                 show_qr, show_config, as_json):
    """Create USERNAME: generate keys, assign an IP, add the peer, reload the interface."""
    user = mgr.create_user(username, expiration=expiration, note=note,
                            traffic_limit=traffic_limit)
    config_text = mgr.client_config(user.username)

    if as_json:
        click.echo(json.dumps({
            "username": user.username, "address": user.address, "status": user.status,
            "expires_at": user.expires_at,
            "traffic_limit_bytes": user.traffic_limit_bytes,
            "public_key": user.public_key,
            "config": config_text,
        }, indent=2))
        return

    click.secho(f"created user {user.username}", fg="green")
    _print_user(user)
    if show_config:
        click.echo()
        click.echo(config_text)
    if show_qr:
        click.echo(mgr.qr_ascii(user.username))


@cli.command("list-users")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of a table.")
@click.option("--status", type=click.Choice(["active", "disabled", "expired"]),
              default=None, help="Only show users in this state.")
@with_manager
def list_users(mgr: AmneziaManager, as_json, status):
    """List all users and their status."""
    users = mgr.list_users()
    if status:
        users = [u for u in users if u.status == status]

    if as_json:
        click.echo(json.dumps([
            {
                "username": u.username, "address": u.address, "status": u.status,
                "enabled": u.enabled, "expires_at": u.expires_at,
                "public_key": u.public_key, "created_at": u.created_at, "note": u.note,
                "traffic_limit_bytes": u.traffic_limit_bytes,
                "traffic_used_bytes": u.traffic_used_bytes,
            }
            for u in users
        ], indent=2))
        return

    if not users:
        click.echo("no users")
        return

    rows = [("USERNAME", "ADDRESS", "STATUS", "EXPIRES", "TRAFFIC", "CREATED", "NOTE")]
    for u in users:
        traffic = f"{format_bytes(u.traffic_used_bytes)} / {format_bytes(u.traffic_limit_bytes)}"
        rows.append((
            u.username,
            u.address,
            u.status,
            (u.expires_at or "never")[:19],
            traffic,
            u.created_at[:19],
            (u.note or "")[:24],
        ))
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    for idx, row in enumerate(rows):
        line = "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row))
        if idx == 0:
            click.secho(line, bold=True)
        else:
            colour = {"active": "green", "disabled": "yellow", "expired": "red"}[row[2]]
            click.secho(line, fg=colour)
    click.echo(f"\n{len(users)} user(s), {sum(u.active for u in users)} active")


@cli.command("disable-user")
@click.argument("username")
@with_manager
def disable_user(mgr: AmneziaManager, username):
    """Disable USERNAME: remove the peer from the live interface, keep the record."""
    user = mgr.set_enabled(username, False)
    click.secho(f"disabled {user.username}", fg="yellow")
    _print_user(user)


@cli.command("enable-user")
@click.argument("username")
@with_manager
def enable_user(mgr: AmneziaManager, username):
    """Re-enable a previously disabled USERNAME."""
    user = mgr.set_enabled(username, True)
    click.secho(f"enabled {user.username}", fg="green")
    _print_user(user)
    if user.expired:
        click.secho("note: user is still past its expiration date", fg="yellow")


@cli.command("set-expiration")
@click.argument("username")
@click.argument("date")
@with_manager
def set_expiration(mgr: AmneziaManager, username, date):
    """Set USERNAME's expiration to DATE (YYYY-MM-DD, '+30d', 'never', ...)."""
    user = mgr.set_expiration(username, date)
    click.secho(f"{user.username}: expires {user.expires_at or 'never'}", fg="green")
    _print_user(user)


@cli.command("set-traffic-limit")
@click.argument("username")
@click.argument("value")
@with_manager
def set_traffic_limit(mgr: AmneziaManager, username, value):
    """Set USERNAME's lifetime traffic cap ('50GB', '500MB', 'unlimited', ...)."""
    user = mgr.set_traffic_limit(username, value)
    click.secho(f"{user.username}: traffic limit {format_bytes(user.traffic_limit_bytes)}", fg="green")
    _print_user(user)


@cli.command("enforce-quotas")
@click.option("--json", "as_json", is_flag=True, help="Emit JSON instead of text.")
@with_manager
def enforce_quotas(mgr: AmneziaManager, as_json):
    """Poll live traffic counters and disable any user over quota or expired.

    Safe to run unattended (e.g. from cron every few minutes): it also re-runs
    ``sync``, so expired users are cut off the same way.
    """
    report = mgr.enforce_quotas()
    if as_json:
        click.echo(json.dumps({
            "checked": report.checked,
            "disabled": report.disabled,
            "active_peers": report.sync.active_peers if report.sync else None,
        }, indent=2))
        return
    click.echo(f"checked {report.checked} active user(s)")
    if report.disabled:
        click.secho(f"disabled (quota exceeded): {', '.join(report.disabled)}", fg="yellow")
    else:
        click.echo("no quota violations")


@cli.command("get-qr")
@click.argument("username")
@click.option("--png", type=click.Path(dir_okay=False), default=None,
              help="Write a PNG QR to this path instead of printing ASCII.")
@with_manager
def get_qr(mgr: AmneziaManager, username, png):
    """Print (or save) the client-config QR code for USERNAME."""
    if png:
        path = mgr.qr_png(username, png)
        click.secho(f"wrote QR to {path}", fg="green")
    else:
        click.echo(mgr.qr_ascii(username))


@cli.command("export-config")
@click.argument("username")
@click.option("-o", "--output", type=click.Path(dir_okay=False), default=None,
              help="Write to this file (default: <username>.conf; '-' for stdout).")
@with_manager
def export_config(mgr: AmneziaManager, username, output):
    """Export the AmneziaWG client config for USERNAME."""
    text = mgr.client_config(username)
    if output == "-":
        click.echo(text)
        return
    dest = output or f"{username}.conf"
    with open(dest, "w", encoding="utf-8") as fh:
        fh.write(text)
    click.secho(f"wrote {dest}", fg="green")


@cli.command("delete-user")
@click.argument("username")
@click.option("-y", "--yes", is_flag=True, help="Do not prompt for confirmation.")
@with_manager
def delete_user(mgr: AmneziaManager, username, yes):
    """Permanently delete USERNAME and remove the peer."""
    if not yes:
        click.confirm(f"delete user {username!r} and revoke access?", abort=True)
    user = mgr.delete_user(username)
    click.secho(f"deleted {user.username} ({user.address})", fg="red")


@cli.command("rekey-user")
@click.argument("username")
@click.option("-y", "--yes", is_flag=True, help="Do not prompt for confirmation.")
@with_manager
def rekey_user(mgr: AmneziaManager, username, yes):
    """Generate fresh keys for USERNAME (invalidates the old client config)."""
    if not yes:
        click.confirm(f"rotate keys for {username!r}? old configs will stop working.",
                      abort=True)
    user = mgr.rekey_user(username)
    click.secho(f"rekeyed {user.username}", fg="green")
    _print_user(user)


@cli.command("doctor")
@with_manager
def doctor(mgr: AmneziaManager):
    """Check connectivity to the container and print the detected server settings."""
    facts = mgr.doctor()
    width = max(len(k) for k in facts)
    for key, value in facts.items():
        click.echo(f"{key.rjust(width)} : {value}")
    click.secho("\nOK - container reachable and configuration parsed", fg="green")


@cli.command("audit")
@click.option("-n", "--limit", default=20, show_default=True, help="Rows to show.")
@with_manager
def audit(mgr: AmneziaManager, limit):
    """Show the most recent mutating actions recorded in the database."""
    rows = mgr.db.recent_audit(limit)
    if not rows:
        click.echo("no audit entries")
        return
    for r in rows:
        mark = "ok  " if r["success"] else "FAIL"
        detail = f"  {r['detail']}" if r["detail"] else ""
        line = f"{r['ts'][:19]}  {mark}  {r['action']:<15} {r['username'] or '-'}{detail}"
        click.secho(line, fg=None if r["success"] else "red")


@cli.command("init-config")
@click.argument("path", type=click.Path(dir_okay=False), default="amnezia_cli.json")
def init_config(path):
    """Write an example JSON config file to PATH."""
    dest = write_example_config(path)
    click.secho(f"wrote example config to {dest}", fg="green")
    click.echo("edit 'container_name', 'endpoint_host' and 'server_dir' to match your server.")


def _print_user(user) -> None:
    click.echo(f"  address    : {user.address}")
    click.echo(f"  status     : {user.status}")
    click.echo(f"  public key : {user.public_key}")
    click.echo(f"  expires    : {user.expires_at or 'never'}")
    click.echo(f"  traffic    : {format_bytes(user.traffic_used_bytes)} / "
               f"{format_bytes(user.traffic_limit_bytes)}")


def main() -> None:
    # QR codes and box-drawing output need UTF-8; the Windows console defaults to
    # a legacy code page. Best effort - ignore if the stream can't be reconfigured.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
        except (AttributeError, ValueError):  # pragma: no cover
            pass
    try:
        cli(standalone_mode=True)
    except AmneziaCliError as exc:  # safety net for errors outside group.invoke
        click.secho(f"error: {exc}", fg="red", err=True)
        sys.exit(exc.exit_code)


if __name__ == "__main__":
    main()
