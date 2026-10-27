# Bitwise Control

Self-hosted infrastructure inventory, monitoring, alerts, and device management for Linux, Proxmox VE, MikroTik RouterOS 7, UniFi Network, and SNMPv3 devices. The interface starts empty; all measurements come from agents or configured device connections.

## Features

- Administrator login, scrypt password hashes, rate limits, expiring HTTP-only sessions, origin checks, password changes, and session revocation.
- Administrator, operator, and viewer accounts with server-enforced company access. Administrators manage all companies and credentials; operators edit inventory and execute enabled controls for assigned companies; viewers can read assigned companies and metrics. Only administrators can view the global audit log, notifications settings, users, and inventory exports. Changing user access revokes their sessions. Update company assignments after renaming a company.
- SQLite company and device inventory, create/edit/delete, company filters, search, revision checks to prevent lost updates, JSON inventory export/import, and migration from the earlier browser-session inventory.
- Linux agent enrollment, per-device credentials, token rotation and revocation, CPU/memory/disk/temperature readings where supported, uptime, last-report status, and a CPU history chart. Unsupported metrics are shown as unavailable.
- API/SNMP connection setup, credential redaction, optional private CA trust, controller discovery, manual connection tests and polling, and scheduled polling every minute. HTTPS certificate checks are always enabled for device HTTP APIs.
- Per-device maintenance windows that keep monitoring active while silencing incidents and notifications.
- Configurable resource thresholds and missing-report timeouts, incidents and recovery, and opt-in email (TLS SMTP) or HTTPS webhook notifications with up to five delivery attempts. Delivery is disabled until configured. Changing delivery settings cancels pending messages for the previous destination.
- Server audit log with user identity, device command history, CSV activity export, thirty-day measurements, and daily SQLite backups retaining seven snapshots.

## Device support

| Connection | Monitoring | Management operations |
| --- | --- | --- |
| Linux agent | CPU, memory, root filesystem usage, OS uptime | Reboot and cached Ubuntu package update checks, only when agent controls are explicitly enabled |
| Proxmox VE API | Host, QEMU VM, or LXC CPU, memory, disk, uptime, state | Host/guest reboot, guest start/shutdown, guest memory and CPU settings, host available-update listing, guest configuration or host network configuration reads |
| RouterOS 7 REST | CPU, memory, disk, uptime, version, available PoE interfaces | Reboot, update check/install, PoE off/auto/forced, configuration export |
| UniFi Network Integration API | CPU, memory, uptime, state, firmware availability, ports | Restart, PoE power-cycle, read adopted-device details |
| SNMPv3 SHA/AES | System uptime/name, HOST-RESOURCES CPU, UCD memory, optional temperature OID | Standard POWER-ETHERNET-MIB PoE administration where writable and supported |

Device versions, MIBs, controller capabilities, API permissions, and local network reachability determine which operations are available. UniFi firmware install and generic SNMP reboot/configuration writes are not offered by these adapters. A successful API request is recorded as **accepted**, not proof the device completed a disruptive operation. Real hardware has not been validated unless separately recorded in the deployment notes. The automated suite uses isolated databases and adapter fixtures; it does not reboot or change real equipment.

## Install or update

Ubuntu/Debian with Python 3 and systemd:

```sh
sudo sh deploy/install.sh
```

The installer installs Net-SNMP client tools if missing, installs the application, preserves existing credentials and the database, and enables the application and backup timer. A first install prints a generated administrator password. Open `http://SERVER_IP:8080` and change the initial password under Settings.

- Source: `/opt/bitwise-control`
- Database: `/var/lib/bitwise-control/control.sqlite3`
- Daily backups: `/var/lib/bitwise-control/backups`
- Primary administrator hash: `/etc/bitwise-control/auth.json`

Connection credentials and notification secrets are stored in the database in a service-owned private directory, protected by operating-system permissions. They are not encrypted separately from the database. Database backups contain these secrets and user password hashes. Keep these files private; never commit them to GitHub. The in-app inventory export omits credentials, users, and measurement history.

The built-in HTTP service is suitable for the user's trusted local network. HTTP does not encrypt sign-in passwords or agent credentials. For HTTPS without Nginx, provide a valid certificate and key readable by the service, then set these environment variables in a systemd override:

```ini
[Service]
Environment=BITWISE_TLS_CERT=/etc/bitwise-control/server.crt
Environment=BITWISE_TLS_KEY=/etc/bitwise-control/server.key
```

Restart `bitwise-control` and access it via HTTPS using the hostname or IP covered by the certificate. TLS uses version 1.2 or newer and sets Secure session cookies. `BITWISE_BIND` and `BITWISE_PORT` can also be configured in the override.

## Connect devices

Create a company and inventory device, open its detail panel, then choose **Connect agent** or **API / SNMP connection**.

### Ubuntu / Linux

Run the generated agent installation commands as root inside the target machine. Python 3 and systemd must already exist. The agent initiates outbound requests to the central server every minute and needs no inbound listener. Controls are disabled by default; the enrollment form can include control permission in the generated configuration. The only accepted command types are reboot and package update listing. The package listing uses the device's existing APT cache and does not install packages.

CPU and memory account for cgroup v2 limits when available. Some containers expose host kernel uptime and host filesystem accounting; the agent reports what the operating system exposes. It does not administer the Proxmox host.

### Proxmox

Use `https://HOST:8006`, an API token ID (`user@realm!token`) and its secret, a node name, and optionally an LXC/QEMU ID. **Discover targets** can list nodes/guests before saving. Grant read-only API permissions for monitoring; enable management actions and appropriate Proxmox privileges only for intended writes. Upload your private CA certificate when the API is not signed by a publicly trusted CA. Certificate verification cannot be disabled.

### MikroTik

Enable RouterOS 7 HTTPS REST (`www-ssl`) and enter the device's HTTPS origin plus a dedicated account. The account must have the relevant REST and read/write policies. Polling lists available PoE interfaces; it does not assume every Ethernet port supports PoE. Upgrade requests use the router's currently configured update channel.

### UniFi

Use the official local UniFi Network Integration API. A UniFi OS base commonly ends in `/proxy/network/integration/v1`; standalone deployments can use `/integration/v1`. Enter the API key and use discovery to choose the site UUID and adopted-device UUID. Older controllers lacking the official API are unsupported. Firmware availability is read from the controller; arbitrary firmware installation is not implemented.

### SNMP

Enable SNMPv3 authPriv with SHA authentication and AES privacy. Enter the IPv4 address/hostname, UDP port, security username, and passphrases. Numeric OIDs avoid dependencies on vendor MIB files. CPU/memory OIDs are optional; unsupported metrics stay blank. An optional temperature OID and divisor support vendor sensor units. Standard PoE writes require a valid PSE group and port index and device support for writable POWER-ETHERNET-MIB. SNMP credentials are passed using a private temporary config file rather than process arguments.

Switching from a Linux agent to an API connection revokes that device's agent token, and enrolling an agent removes its API connection. Deleting a device removes its credentials, samples, incidents, and command history. Commands queued for an offline Linux agent expire after ten minutes and are never retried automatically after being claimed.

## Notifications and access

Settings provides user/company assignments, password changes, alert thresholds, and notification configuration. Resource threshold 0 disables its rule; a missing-report timeout must be at least 60 seconds. Email supports STARTTLS or direct TLS on port 465. Webhooks receive JSON containing `subject`, `message`, `text`, and `content`; an optional bearer token is supported. No notification is sent until a delivery destination is saved and an incident or recovery occurs.

## Operations and recovery

```sh
systemctl status bitwise-control
journalctl -u bitwise-control -n 100
systemctl list-timers bitwise-backup.timer
systemctl start bitwise-backup.service
```

For database restoration: stop `bitwise-control`, back up the current data directory, replace `control.sqlite3` with a daily backup, remove stale `control.sqlite3-wal` and `control.sqlite3-shm`, set ownership to `bitwise-control`, and restart. Restore `/etc/bitwise-control/auth.json` separately if restoring the primary administrator account. Inventory JSON import restores inventory only; it is not a full database restore.

## Validation

```sh
python3 -m unittest discover -s tests -q
python3 -m py_compile server.py adapters.py notifications.py agent.py backup.py
node --check dist/app.js
```

Automated tests cover authentication, persistence, concurrency checks, secret redaction, agent metrics, adapter mappings and controls, command scoping, company access isolation, user revocation, alerts, notification delivery, and password changes. External connections and messages are mocked in tests.

## API references

- [Proxmox VE API viewer](https://pve.proxmox.com/pve-docs/api-viewer/)
- [RouterOS REST API](https://manual.mikrotik.com/docs/developer-guides/rest-api/)
- [Official UniFi Network OpenAPI specification](https://developer.ui.com/network/v10.6.106/openapi.json)
- [Net-SNMP client configuration](https://www.net-snmp.org/docs/man/snmp.conf.html)

Deployment policy: completed updates normally go to GitHub and `10.10.111.49` together. The current user instruction is GitHub-only work; server and device changes are on hold. An automatic GitHub deployment hook is not installed. Agents and device adapters still need to be connected to real targets and validated with their hardware-specific permissions; this repository is not a claim that every model supports every operation.

## Connection activation status

The application code and integrations are published. Hardware validation remains pending:

- The last server check found no inventory entries or saved device connections. Devices created in the original browser-only version require the in-app import prompt in that same browser session, or manual re-entry.
- SSH access to the Ubuntu container at `10.10.111.39` rejected the available public key. Its agent has not been installed.
- Proxmox host, MikroTik, UniFi controller, and SNMP device endpoints and credentials have not been provided.
- Notification delivery remains disabled until a real destination is configured.

When device work resumes, import or create the company/device inventory, establish authorized access, configure the relevant connection in the app, and verify real measurements, history, and incident recovery. Do not use a successful TCP port check as proof of authenticated monitoring. Reboots, upgrades, and PoE changes require separate explicit test instructions. Enter secrets in the application connection forms; never add them to the repository or commit history.
