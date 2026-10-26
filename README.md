# Bitwise Control

Multi-company infrastructure monitoring and device management dashboard by Bitwise MSP.

## Current version: interactive preview

This repository preserves the approved dashboard design. It is a static browser application with sample data and simulated device controls, not a production monitoring backend.

- Company workspaces and filtering
- Searchable device inventory
- Sample CPU, memory, temperature, uptime and network activity
- Device detail panels and sample sensors
- Simulated reboot, upgrade check and switch PoE controls
- Locally saved configuration drafts and notification preferences
- Alert rule toggles and sample incidents
- Activity log with CSV export

All changes are stored in the browser's localStorage. There are no credentials, live device connections, background checks, real notifications, or server-side tenant isolation. Switching companies is an interface filter, not an authorization boundary.

## Run locally

No dependencies or build step are required. With Python 3:

```sh
python3 -m http.server 8080 --directory dist --bind 127.0.0.1
```

Open http://127.0.0.1:8080. The complete application is in `dist/index.html`.

Hosted preview: https://bitwise-control.rdoorson20.chatgpt.site (private; requires owner sign-in).

## Planned live implementation

1. Central self-hosted backend with authentication, company access controls, durable inventory and metrics storage.
2. Collector at each customer site, using authenticated outbound connections to the central server.
3. Device adapters for SNMP v3, server agents, Proxmox, MikroTik and UniFi APIs, subject to hardware support.
4. Alert evaluation, failure/recovery notifications, maintenance windows and delivery retries.
5. Permission-checked, audited device operations: reboot, PoE changes, upgrades and configuration writes.
6. Secret storage, configuration backups and validation before applying device changes.

Never enter real device credentials into this preview. Production control and monitoring components are not implemented yet.
