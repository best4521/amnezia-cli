#!/usr/bin/env python3
"""End-to-end demo: provision 5 AmneziaWG users and exercise every command.

Runs entirely against the in-memory fake backend (no Docker, no server), in a
throwaway working directory, so it is safe to run anywhere:

    python demo.py

To watch it hit a real server instead, drop `--fake` and point it at your
container (edit CONTAINER / EXTRA_ARGS below), or run the same commands by hand.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CLI = [sys.executable, str(HERE / "amnezia_cli.py")]

# Global flags applied to every invocation. Use the fake backend + an isolated DB.
EXTRA_ARGS = ["--fake"]

DEMO_USERS = [
    ("alice",   ["--expires", "+30d", "--note", "marketing laptop"]),
    ("bob",     ["--expires", "+7d"]),
    ("carol",   ["--note", "no expiry - office desktop"]),
    ("dave",    ["--expires", "2026-12-31"]),
    ("eve",     ["--expires", "+90d", "--note", "contractor"]),
]


def run(*args: str, capture: bool = False) -> str:
    cmd = CLI + EXTRA_ARGS + list(args)
    print(f"\n$ amnezia_cli {' '.join(EXTRA_ARGS + list(args))}")
    result = subprocess.run(
        cmd, text=True, capture_output=capture,
        stdout=None if not capture else subprocess.PIPE,
    )
    if result.returncode != 0:
        print(f"  ! command exited {result.returncode}", file=sys.stderr)
        if capture and result.stdout:
            print(result.stdout)
        sys.exit(result.returncode)
    if capture:
        print(result.stdout)
        return result.stdout
    return ""


def banner(text: str) -> None:
    print("\n" + "=" * 72 + f"\n  {text}\n" + "=" * 72)


def main() -> None:
    workdir = Path(tempfile.mkdtemp(prefix="amnezia-demo-"))
    db = workdir / "amnezia_users.db"
    log = workdir / "amnezia_cli.log"
    EXTRA_ARGS.extend(["--db", str(db)])
    # Route the log file into the temp dir too (config option via env).
    import os
    os.environ["AMNEZIA_CLI_LOG_PATH"] = str(log)

    print(f"demo working directory: {workdir}")

    banner("0. doctor - inspect the (fake) server")
    run("doctor")

    banner("1. create-user x5")
    for username, opts in DEMO_USERS:
        run("create-user", username, *opts)

    banner("2. list-users")
    run("list-users")

    banner("3. disable-user bob, then list")
    run("disable-user", "bob")
    run("list-users")

    banner("4. enable-user bob")
    run("enable-user", "bob")

    banner("5. set-expiration carol 2027-01-01")
    run("set-expiration", "carol", "2027-01-01")

    banner("6. set-expiration alice never")
    run("set-expiration", "alice", "never")

    banner("7. get-qr eve (ASCII)")
    run("get-qr", "eve")

    banner("8. export-config dave")
    cfg_path = workdir / "dave.conf"
    run("export-config", "dave", "-o", str(cfg_path))
    print(f"--- {cfg_path} ---")
    print(cfg_path.read_text())

    banner("9. list-users --json")
    run("list-users", "--json")

    banner("10. delete-user eve")
    run("delete-user", "eve", "--yes")
    run("list-users")

    banner("11. audit log")
    run("audit")

    banner("done")
    print(f"artifacts left in: {workdir}")
    print("(safe to delete; the fake backend touched nothing on this machine)")


if __name__ == "__main__":
    main()
