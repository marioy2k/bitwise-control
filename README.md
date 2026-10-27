# Bitwise Control

Self-hosted company inventory and Linux agent monitoring. Python 3 and systemd; no Nginx, npm build, or external Python packages required.

## Implemented

- Server-enforced administrator login, hashed password, expiring HTTP-only sessions, login rate limiting, origin checks, and password changes that revoke other sessions.
- Durable SQLite company and device inventory with create, edit, delete, search, company filters, conflict detection, and JSON export/import.
- Existing browser-session inventory can be imported when opening an empty server inventory.
- Per-device agent enrollment tokens. Regenerating a token revokes the previous token; deleting the device revokes access and removes its metric history.
- Read-only Linux agent reporting CPU, memory, root disk usage, hostname, and OS uptime. Uses cgroup v2 limits when available for container CPU and memory. Root disk is the agent's root filesystem. Uptime may reflect the host kernel in some container configurations.
- Device status, last report, metric history chart, TCP reachability checks, and automatic 30-second dashboard refresh.
- Incidents for an enrolled agent missing for three minutes or CPU/memory/disk over 90%, automatic recovery, and server audit logs with CSV export.
- Thirty-day measurement retention and seven daily SQLite backups.

## Install or update

From a checkout, as root:

```sh
sh deploy/install.sh
```

Open `http://SERVER_IP:8080`. A first install prints its generated administrator credentials. Updates preserve credentials and the database. Change the initial password in Settings. Do not commit credentials, agent tokens, database files, or backups.

Application files: `/opt/bitwise-control`; database and daily backups: `/var/lib/bitwise-control`; administrator credential hash: `/etc/bitwise-control/auth.json`.

Use HTTPS before deploying across untrusted networks; HTTP does not encrypt passwords or agent credentials. The built-in service currently binds on all interfaces at port 8080. Configure `BITWISE_BIND` and `BITWISE_PORT` in a systemd override to change it. This release has one administrator account; company filtering organizes inventory and does not restrict access between users.

## Connect a Linux device

Create a company and device, open the device, select **Connect agent**, and run the generated installation commands inside that Linux machine. Python 3 and systemd must already be installed. The agent initiates outbound HTTP(S) to the central server; no inbound agent port is required. It sends real measurements only and cannot receive remote commands. CPU and memory percentages are bounded to 0–100.

A TCP connection check only tests the configured port from the central server; it does not authenticate to the device or establish metrics collection.

## Operations

```sh
systemctl status bitwise-control
journalctl -u bitwise-control -n 100
systemctl list-timers bitwise-backup.timer
systemctl start bitwise-backup.service
```

For database restoration, stop `bitwise-control`, back up the current database directory, replace `control.sqlite3` with a daily backup, remove stale `control.sqlite3-wal` and `control.sqlite3-shm`, ensure ownership by `bitwise-control`, and restart the service. The in-app JSON import restores inventory only, not credentials or metric history.

## Validation

```sh
python3 -m unittest discover -s tests -q
python3 -m py_compile server.py agent.py backup.py
node --check dist/app.js
```

Tests exercise authentication, persistence, revision conflicts, origin rejection, agent credential validation, metric validation, alerts and recovery, offline alerts, credential revocation, password change, and login rate limiting. Tests use an isolated temporary database.

## Remaining integrations

Proxmox host API, MikroTik, UniFi, SNMP, external notification delivery, multiple users and company access controls, and audited remote reboot/upgrade/PoE/configuration controls are not implemented. They require separate adapters and access to target systems for validation. No controls are simulated or presented as functioning. Container monitoring via the Linux agent does not provide Proxmox host administration.

The application is not a completed replacement for an enterprise remote monitoring platform. Deployment updates should be tested, committed to GitHub, and applied to the server together. No automatic deployment hook is installed.
