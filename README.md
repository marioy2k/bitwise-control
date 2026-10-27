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

## Printer ink and toner monitoring

Add a device with type **Printer**, then open **API / SNMP connection → Printer supplies (SNMPv3)**. Enable SNMPv3 authPriv (SHA/AES) on the network printer and enter its host, UDP port (default 161), security username, and passphrases. Use a read-only account with access to the standard [RFC 3805 Printer-MIB](https://www.rfc-editor.org/rfc/rfc3805.html) supplies table. Printers without SNMPv3 or Printer-MIB support are not supported by this connection.

Set **Low supply warning** to your desired percentage (default 20%; 0 disables supply warnings), save, and select **Poll now**. Automatic polling runs every minute. Device details show each supply description and its remaining percentage; the inventory shows the lowest known consumed supply level. Percentages come from reported percentage units or valid level/capacity pairs. Unknown, negative sentinel, missing, or invalid measurements remain unavailable. Waste receptacles display remaining space but do not trigger low-ink warnings.

At or below the threshold, a consumed supply opens a warning naming the supply and remaining percentage. Repeated polls do not resend the same open incident. Recovery closes the incident; maintenance silences it. Alerts appear in the dashboard; email/webhook warnings require configuring **Settings → Configure monitoring → Notification delivery**. Existing one-incident-per-device behavior applies. Monitoring is read-only and offers no printer management commands. Printer hardware has not yet been validated.

### HP SNMP context

Some HP printers require the SNMP context name `Jetdirect` to grant access to their MIB objects. Set **SNMP context name** in the connection form when the device requires a non-default context. The HP Color LaserJet Pro MFP 3303 was verified to return four supplies using `Jetdirect`; an empty context returned `authorizationError`. Other devices can leave this field blank.

## Discord and SMTP email together

In **Settings → Configure monitoring**, choose **Discord + SMTP email** to send each new incident and recovery to both destinations. Discord-only, SMTP-only, and the existing generic HTTPS webhook option remain available. For Discord, create a webhook under the destination text channel’s **Edit Channel → Integrations → Webhooks**, then paste its URL into the app. Enter the SMTP server, port (587 STARTTLS or 465 TLS), username/password, sender, and recipient. All network connections verify TLS.

Discord messages disable mentions and are limited to 2,000 characters. Webhook URLs and SMTP passwords stay hidden in API responses and must never be committed. Each channel has its own delivery status and retries, so an SMTP failure does not resend an already delivered Discord message. As before, a transport failure after acceptance can result in a duplicate on retry. Changing destinations cancels pending deliveries. New settings apply to future incident and recovery events; existing open alerts are not resent.

### Test notification delivery

In **Settings → Configure monitoring**, choose a channel, fill in its settings, and click **Send test notification**. The test uses the form values and reuses saved secrets when their fields are blank. It sends one clearly labeled test message per selected channel and reports each result separately. Testing does not save settings or automatically retry. Select **Save monitoring settings** afterward to enable future incident and recovery messages. Only administrators can send tests, and each attempt appears in recent deliveries and the audit log. A sent result means the receiving service accepted the message; check email spam folders if needed.

## Recurring notifications

**Settings → Configure monitoring** provides two independent schedules: **Repeat unresolved alert reminders** and **Send status summaries**. Choose disabled, every 5 minutes, or every 10 minutes for each. Discord/SMTP destinations must be enabled and configured.

Open alerts still notify immediately, and recovery notifies once. Reminders continue only while an incident is open and outside maintenance. Pending alert/reminder messages are cancelled when the incident recovers or enters maintenance; a channel with a pending alert/reminder does not accumulate more reminders for that device. Status summaries include healthy devices, offline/warning counts, and available supply levels. Summary and reminder timers persist across restarts, run on the 5-second monitoring cycle, and do not replay every missed interval after an outage. Both schedules are disabled by default until explicitly enabled. Tests send once and do not change schedules.

## Windows security monitoring roadmap

Windows security integration is planned, not installed in this release. A Windows agent could collect Microsoft Defender protection status and detected threats, selected Windows security events, and applicable missing updates through Windows Update Agent. These are monitoring signals, not a replacement antivirus engine or complete SIEM. Full software/CVE vulnerability coverage requires a supported vulnerability data source or platform, with its own access and licensing. Windows setup was deferred at the user's request.

## Native service monitoring

Bitwise Control now has a **Monitors** workspace. Add monitors under an existing company, with 20-second to 24-hour check intervals, 1–30 second timeouts, consecutive-failure retries, tags, groups, pause/resume, cloning, bulk pause/resume, maintenance, and notification opt-out. Monitoring uses the existing company permissions; only administrators configure endpoints and credentials. Operators can check assigned devices and maintain inventory; viewers can read assigned companies.

Supported service checks:

| Type | What is actually checked |
| --- | --- |
| HTTP/HTTPS | GET, HEAD, or POST response and configured status ranges; custom headers/body, HTTP(S) proxy, private CA; redirects are not followed |
| HTTP keyword | Presence/absence of a case-sensitive string in a response of at most 2 MB |
| HTTP JSON value | Simple dot-separated key/index lookup and equality against a JSON value (not JSONata) |
| TCP port | Successful TCP connection |
| Ping | ICMP echo using iputils-ping |
| DNS | A/AAAA/CNAME/MX/TXT/NS/SOA/SRV/CAA/PTR via system or selected DNS server, optionally an exact expected answer |
| TLS certificate | Verified TLS handshake, expiry timestamp, and configurable days-before-expiry warning |
| WebSocket | Verified HTTP upgrade handshake; no application-message exchange |
| Docker | A verified HTTPS container-inspection API response with State.Running and optional health status; no Docker socket mounts or container writes |
| Steam | A2S_INFO query, including standard challenge response; split/compressed responses are unsupported |
| NTP | Server-mode synchronized response with matching origin timestamp; IPv4 UDP |
| Redis | Optional AUTH and PING/PONG over TLS or plain transport; no data writes |
| MQTT | MQTT 3.1.1 CONNECT/CONNACK and DISCONNECT, optional credentials and TLS; no publish/subscription |
| SMTP/IMAP/POP3 | Protocol NOOP, optional login, verified TLS/STARTTLS or explicitly selected plain transport; no email delivery, retrieval, or deletion |
| Push heartbeat | Private per-monitor GET/POST URL, optional status=down; hashed tokens, rotation/revocation, interval plus grace deadline |

The detail panel includes recent heartbeat bars, measured response-time chart, last 60 check rows, and time-weighted 24-hour/7-day/30-day uptime. Unobserved gaps beyond interval plus timeout are excluded, not counted as healthy. Retry periods have an unknown result until the down threshold is met. Uptime is observational and is not an SLA guarantee. Thirty-day sample retention continues to apply.

HTTPS certificate validation stays enabled. Endpoint URLs, custom headers, request bodies, proxy credentials, and push credentials are withheld from normal state responses; editing with blank private fields keeps the saved values. Push URLs are bearer credentials and must be kept private; access logs redact their token.

## Status pages, badges, and metrics

Administrators can publish multiple pages through **Status pages**, selecting exactly which device names/status/24-hour uptime to expose. Internal addresses, credentials, company assignments, and diagnostic messages stay private. Public descriptions are escaped as text. Published pages refresh every 30 seconds and are available at `/status/SLUG`; `/api/status/SLUG` provides the same limited data. Unpublishing removes public access. Optional custom hostnames route their root URL to the selected page after the user configures DNS and, if needed, HTTPS and port forwarding separately. No domain or public firewall settings are changed automatically.

A public SVG badge is available only for published devices at `/badge/SLUG/DEVICE_ID.svg`. Authenticated `/api/metrics` provides Prometheus device-up gauges limited to the current user's company access.

## Additional notification providers

**Settings → Configure monitoring → More providers (Apprise)** accepts one Apprise service URL per line, up to 20 destinations. The distribution's `apprise` package supplies its supported providers, including services such as Telegram, Slack, Gotify, ntfy, and Pushover. Provider URL syntax and supported capabilities follow the installed library; see [Apprise's provider documentation](https://appriseit.com/services/). Each destination has independent retries and test results. Provider URLs remain secret in normal API responses and logs from the Apprise library are suppressed to avoid disclosing them. The existing Discord/SMTP modes, test button, reminders, and summaries remain available.

## Uptime Kuma feature comparison

This is native Bitwise development, not an installed Uptime Kuma service and not full Uptime Kuma 2.5.8 parity. Delivered here: the service check types listed above, 20-second scheduling, retries, groups/tags, pause/resume/clone/bulk actions, response-time and uptime history, TLS expiry, HTTP proxy support, multiple public status pages, custom-hostname routing, status descriptions, public badges, authenticated metrics, and additional notification providers through Apprise. Existing printer monitoring and infrastructure controls remain.

Still outstanding for full parity: dedicated SQL/MongoDB/Kafka/AMQP/RADIUS/gRPC/Tailscale/Globalping integrations, real-browser transactions, full JSONata expressions, proxy support outside HTTP, advanced per-monitor notification routing, recurring maintenance calendars, status-page incident timelines/RSS/themes, TOTP 2FA/OIDC/API-key administration, localization, and other specialised provider-specific options. Windows security monitoring remains deferred. Do not present these outstanding features as implemented.

### Linux ICMP permission

Ping uses unprivileged ICMP echo sockets under the service account. On a dedicated monitoring server/container whose `net.ipv4.ping_group_range` excludes the service group, the installer attempts to restrict that range to the `bitwise-control` group and persists the value in `/etc/sysctl.d/90-bitwise-monitoring.conf`. Existing ranges already including the group are retained. If the container host prevents this setting, the installer reports the restriction and ping checks remain unavailable; HTTP/TCP and other monitors continue to work. The service keeps `NoNewPrivileges=yes` and receives no raw-socket capabilities.
