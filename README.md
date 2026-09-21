# Amnezia AWG2 Management CLI

A command-line tool to manage **AmneziaWG (AWG2)** VPN users on a **Dockerised
Amnezia** server: provision users, revoke/restore access, set expirations, hand
out `.conf` files and QR codes — all from one place, with a local database as the
source of truth.

```
amnezia_cli.py create-user alice --expires +30d --qr
amnezia_cli.py list-users
amnezia_cli.py disable-user alice
amnezia_cli.py export-config alice -o alice.conf
```

---

## Contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Install](#install)
- [Configure](#configure)
- [Commands](#commands)
- [Try it without a server (demo)](#try-it-without-a-server-demo)
- [Deploying to your Amnezia host](#deploying-to-your-amnezia-host)
- [Database schema](#database-schema)
- [Project layout](#project-layout)
- [Tests](#tests)
- [Troubleshooting](#troubleshooting)

---

## How it works

```
             ┌─────────────────┐   docker exec / tar    ┌────────────────────────┐
 amnezia_cli │  amnezia_cli.py │ ─────────────────────► │  amnezia-awg container  │
     ▼       │  amnezia_manager│                        │  /opt/amnezia/awg/      │
┌──────────┐ │   ├ manager     │  read  wg0.conf        │   ├ wg0.conf            │
│ SQLite   │◄┤   ├ database    │  write wg0.conf        │   ├ clientsTable        │
│ *.db     │ │   ├ backend     │  awg syncconf wg0      │   └ *.key               │
│ (truth)  │ │   └ wireguard   │                        │  awg / awg-quick        │
└──────────┘ └─────────────────┘                        └────────────────────────┘
```

1. **The SQLite database is authoritative.** It records every user: keys, assigned
   tunnel IP, enabled flag, expiration, notes, timestamps, plus an append-only
   `audit_log`.
2. Every mutating command updates the database, then calls **`sync()`**, which:
   - rebuilds the `[Peer]` list in the container's `wg0.conf` from the set of
     **active** users (enabled **and** not expired), keeping the server
     `[Interface]` block — including the AmneziaWG obfuscation parameters
     `Jc/Jmin/Jmax/S1/S2/H1..H4` — byte-for-byte;
   - reloads the interface **in place** with `awg-quick strip | awg syncconf`, so
     sessions for untouched peers are never dropped;
   - refreshes Amnezia's `clientsTable` and writes a JSON snapshot of all users
     onto the container's persistent volume (`amnezia_cli_users.json`) for
     disaster recovery.
3. **Disable** simply drops a user from the active set — the record and its keys
   stay, so **enable** restores the exact same config. **Delete** removes the
   record entirely.
4. Key material (`genkey` / `pubkey` / `genpsk`) is generated **inside the
   container** using its own `awg`/`wg` binary — no crypto library needed locally.

---

## Requirements

- **Python 3.10+**
- Python packages (see `requirements.txt`):
  - `click` — CLI framework
  - `docker` (docker-py) — Docker Engine API client
  - `qrcode` — QR rendering (add `pillow` for `--png` output)
  - `sqlite3` — standard library, no install needed
- Access to the Docker daemon running the Amnezia server — either:
  - run the CLI **on the Amnezia host**, or
  - point it at a remote daemon with `--docker-url ssh://root@host`
    (needs an SSH key and `paramiko`: `pip install "docker[ssh]"`).
- An **Amnezia** server with the **AmneziaWG (AWG2)** protocol container
  (default name `amnezia-awg`, config at `/opt/amnezia/awg/wg0.conf`).

---

## Install

```bash
git clone https://github.com/best4521/amnezia-cli.git && cd amnezia-cli
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt

chmod +x amnezia_cli.py
./amnezia_cli.py --help
```

---

## Configure

Resolution order (last wins): **defaults → JSON file → `AMNEZIA_CLI_*` env vars → CLI flags**.

Generate a starter file:

```bash
./amnezia_cli.py init-config            # writes ./amnezia_cli.json
```

The CLI auto-loads `./amnezia_cli.json` or `~/.config/amnezia-cli/config.json`.
Point elsewhere with `--config /path/to.json`.

| Key | Default | Meaning |
|---|---|---|
| `container_name` | `amnezia-awg` | AmneziaWG container name or ID |
| `docker_base_url` | `null` | `null` = local daemon; else e.g. `ssh://root@1.2.3.4` |
| `server_dir` | `/opt/amnezia/awg` | Directory holding `wg0.conf` inside the container |
| `interface` | `wg0` | WireGuard interface name |
| `endpoint_host` | `auto` | Public host/IP for clients; `auto` = detect from the container |
| `endpoint_port` | `0` | `0` = read `ListenPort` from `wg0.conf` |
| `dns` | `1.1.1.1, 1.0.0.1` | `DNS =` line in client configs |
| `client_allowed_ips` | `0.0.0.0/0, ::/0` | `AllowedIPs =` in client configs (full tunnel) |
| `persistent_keepalive` | `25` | Client keepalive seconds |
| `db_path` | `amnezia_users.db` | SQLite database path |
| `log_path` | `amnezia_cli.log` | Rotating log file |
| `fake_backend` | `false` | Use the in-memory simulator (also `--fake` / `AMNEZIA_CLI_FAKE=1`) |

Example env override: `AMNEZIA_CLI_CONTAINER_NAME=amnezia-awg AMNEZIA_CLI_ENDPOINT_HOST=vpn.example.com`.

---

## Commands

Run `./amnezia_cli.py COMMAND --help` for full details.

### `create-user <username>`
Generate a keypair + PSK, allocate the lowest free `/32` in the tunnel subnet,
add the peer and reload the interface.

```bash
./amnezia_cli.py create-user alice
./amnezia_cli.py create-user bob --expires 2026-12-31 --note "contractor"
./amnezia_cli.py create-user carol --expires +90d --qr --show-config
./amnezia_cli.py create-user dave --expires +30d --traffic-limit 50GB --json
```
Usernames: 1–32 chars of `[A-Za-z0-9_.-]`, starting alphanumeric.
`--json` emits the user record plus the ready-to-send client config in one
object - meant for scripted callers (e.g. a Telegram bot creating users over
SSH: `ssh root@host amnezia-cli create-user NAME --expires +30d --traffic-limit 50GB --json`).

### `list-users`
```bash
./amnezia_cli.py list-users                 # coloured table
./amnezia_cli.py list-users --json          # machine-readable
./amnezia_cli.py list-users --status expired
```

### `disable-user <username>` / `enable-user <username>`
Revoke or restore access without losing the config. Disabled users are removed
from the live interface immediately.

### `set-expiration <username> <date>`
```bash
./amnezia_cli.py set-expiration alice 2026-12-31
./amnezia_cli.py set-expiration alice "2026-12-31 09:00"
./amnezia_cli.py set-expiration alice +30d
./amnezia_cli.py set-expiration alice never          # clear expiration
```
Expired users are automatically excluded from the peer list on the next `sync`.

### `set-traffic-limit <username> <value>`
```bash
./amnezia_cli.py set-traffic-limit alice 50GB
./amnezia_cli.py set-traffic-limit alice unlimited
```
Sets a **lifetime** traffic cap (binary units: `1GB` = 1024³ bytes). A bare
byte count also works. `unlimited`/`none`/`0` clears it.

### `enforce-quotas`
```bash
./amnezia_cli.py enforce-quotas --json
```
Polls live `wg show transfer` counters, adds the delta to each user's
cumulative usage, and disables anyone at or past their traffic cap. Also runs
`sync`, so expired users get cut off the same call. Meant for cron:
```
*/5 * * * * /usr/local/bin/amnezia-cli enforce-quotas >> /opt/amnezia-cli/enforce-quotas.log 2>&1
```

### `get-qr <username>`
```bash
./amnezia_cli.py get-qr alice                 # ASCII QR in the terminal
./amnezia_cli.py get-qr alice --png alice.png # needs pillow
```

### `export-config <username>`
```bash
./amnezia_cli.py export-config alice              # -> ./alice.conf
./amnezia_cli.py export-config alice -o /tmp/a.conf
./amnezia_cli.py export-config alice -o -         # stdout
```

### `delete-user <username>`
```bash
./amnezia_cli.py delete-user alice          # prompts
./amnezia_cli.py delete-user alice --yes     # no prompt
```
The freed IP is reused by the next `create-user`.

### Extras
| Command | Purpose |
|---|---|
| `doctor` | Verify the daemon/container is reachable; print detected endpoint, keys, subnet, AWG params |
| `rekey-user <username>` | Rotate a user's keys (old client config stops working) |
| `audit [-n N]` | Show recent mutating actions from `audit_log` |
| `init-config [path]` | Write an example config file |

Global flags: `--config`, `--db`, `--container`, `--docker-url`, `--endpoint-host`,
`--fake`, `-v/--verbose`, `-V/--version`.

Exit codes follow `sysexits.h` (`64` usage, `65` data error, `69` unavailable,
`70` internal, `78` config).

---

## Try it without a server (demo)

The `--fake` backend simulates a container (key generation, config I/O, tool
discovery, `syncconf`, public-IP detection) entirely in memory.

```bash
python demo.py
```

This provisions 5 users (`alice`…`eve`) in a throwaway directory and runs every
command — create, list, disable/enable, set-expiration, QR, export, JSON list,
delete, audit. Nothing on your machine or network is touched.

Manual poke:

```bash
./amnezia_cli.py --fake --db /tmp/demo.db doctor
./amnezia_cli.py --fake --db /tmp/demo.db create-user alice --expires +30d
./amnezia_cli.py --fake --db /tmp/demo.db get-qr alice
```

---

## Deploying to your Amnezia host

The database must live somewhere persistent and backed up. Recommended: run the
CLI directly on the Amnezia host.

```bash
# on the server
sudo apt install -y python3-venv    # if missing (Debian/Ubuntu)
git clone https://github.com/best4521/amnezia-cli.git /opt/amnezia-cli && cd /opt/amnezia-cli
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp amnezia_cli.json.example amnezia_cli.json
# edit amnezia_cli.json: container_name / interface / config_filename must match
# your container - check with `docker ps` and `docker exec <container> ip -o link show`
# (AmneziaWG containers are often named amnezia-awg2 with interface awg0, not the
# amnezia-awg/wg0 defaults)
sudo .venv/bin/python amnezia_cli.py doctor
sudo .venv/bin/python amnezia_cli.py create-user alice --expires +30d
```

To pull later updates on any server: `cd /opt/amnezia-cli && git pull`.

Optional wrapper at `/usr/local/bin/amnezia-cli`:

```bash
#!/usr/bin/env bash
cd /opt/amnezia-cli && exec .venv/bin/python amnezia_cli.py "$@"
```

**Remote** management (daemon over SSH):

```bash
pip install "docker[ssh]"
./amnezia_cli.py --docker-url ssh://root@YOUR_SERVER --endpoint-host YOUR_SERVER doctor
```

### Coexisting with users Amnezia created before the CLI
`sync()` is non-destructive: it keeps the server `[Interface]` block byte-for-byte
**and** preserves any `[Peer]` already in `wg0.conf` that this tool didn't create
(they're re-emitted with a `# unmanaged` comment). It only adds/removes the peers
it manages. So pre-existing Amnezia clients keep working. This tool can't hand out
their `.conf` though — it doesn't have their private keys; manage those in the
Amnezia app, or recreate them here with `create-user`.

> Still, back up `/opt/amnezia/awg/wg0.conf` before the first mutating command.

---

## Database schema

SQLite file `amnezia_users.db` (also see `schema.sql`), created automatically.

**`users`**

| column | type | notes |
|---|---|---|
| `id` | INTEGER PK | |
| `username` | TEXT UNIQUE | validated `[A-Za-z0-9_.-]{1,32}` |
| `private_key` / `public_key` | TEXT | client WireGuard keys (base64); `public_key` UNIQUE |
| `preshared_key` | TEXT | per-peer PSK (base64) |
| `address` | TEXT UNIQUE | assigned tunnel IP, e.g. `10.8.1.7/32` |
| `enabled` | INTEGER | `1` active, `0` disabled |
| `expires_at` | TEXT NULL | ISO-8601 UTC, `NULL` = never |
| `note` | TEXT NULL | |
| `created_at` / `updated_at` | TEXT | ISO-8601 UTC |

**`audit_log`** — `ts, action, username, detail, success` (append-only).

Derived status: `active` (enabled & not expired) · `disabled` · `expired`.

---

## Project layout

```
amnezia_cli.py              CLI entrypoint (Click)
demo.py                     5-user end-to-end demo (fake backend)
schema.sql                  reference schema
requirements.txt
amnezia_cli.json.example    example config
amnezia_manager/
  ├─ config.py              layered configuration
  ├─ errors.py              exception hierarchy + exit codes
  ├─ logging_setup.py       rotating file + console logging
  ├─ validators.py          username / date parsing & validation
  ├─ wireguard.py           pure config parse/generate, IP allocation
  ├─ database.py            SQLite persistence + audit log
  ├─ backend.py             Backend ABC + DockerBackend (docker-py, tar streams)
  ├─ fake_backend.py        in-memory container simulator (--fake)
  ├─ qr.py                  QR ASCII / PNG rendering
  └─ manager.py             orchestration: the API behind every command
tests/
  ├─ test_core.py           parsing, allocation, validation
  └─ test_manager_fake.py   manager flows against the fake backend
```

---

## Tests

```bash
python -m unittest discover -s tests -v
# or, if you have pytest:
pytest -q
```

23 tests, no network or Docker required.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `cannot reach the Docker daemon` | Run on the host, or `--docker-url`; check `docker ps` works for your user |
| `container 'amnezia-awg' not found` | `docker ps --format '{{.Names}}'` and set `container_name` |
| `could not auto-detect the server's public IP` | Set `endpoint_host` in the config to your server's IP/hostname |
| `interface reload failed` | The peer file was written; run `awg syncconf wg0 <(awg-quick strip wg0)` in the container, or restart it. Check `amnezia_cli.log` |
| `none of ('awg', 'wg') found in container` | Not an AmneziaWG container, or an unusual image — set `server_dir`/`interface` |
| QR shows as garbled blocks on Windows | Use Windows Terminal / a UTF-8 console, or `get-qr --png` |
| Clients don't connect after `create-user` | Verify `endpoint_host:port` is reachable and the AWG params in the client `.conf` match the server |

Logs: `amnezia_cli.log` (rotating, `INFO`+). Add `-v` for `DEBUG` on the console.
