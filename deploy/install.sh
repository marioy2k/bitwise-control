#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] || { echo 'Run as root.'; exit 1; }
SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
command -v python3 >/dev/null
if ! command -v snmpget >/dev/null 2>&1; then
 apt-get update -qq
 DEBIAN_FRONTEND=noninteractive apt-get install -y snmp
fi
if ! command -v ping >/dev/null 2>&1 || ! python3 -c 'import dns.resolver,apprise' >/dev/null 2>&1; then
 apt-get update -qq
 DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iputils-ping python3-dnspython apprise
fi
getent passwd bitwise-control >/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin bitwise-control
# Permit unprivileged ICMP for the monitoring service without raw-socket capabilities.
BITWISE_PING_GID=$(id -g bitwise-control)
if ! python3 - "$BITWISE_PING_GID" <<'PYICMP'
import sys
from pathlib import Path
low,high=map(int,Path('/proc/sys/net/ipv4/ping_group_range').read_text().split())
raise SystemExit(0 if low<=int(sys.argv[1])<=high else 1)
PYICMP
then
 if sysctl -w "net.ipv4.ping_group_range=$BITWISE_PING_GID $BITWISE_PING_GID" >/dev/null 2>&1; then
  printf 'net.ipv4.ping_group_range = %s %s\n' "$BITWISE_PING_GID" "$BITWISE_PING_GID" > /etc/sysctl.d/90-bitwise-monitoring.conf
 else
  echo 'ICMP echo permission is restricted by the host; ping monitors will report unavailable until the service group is permitted.' >&2
 fi
fi
install -d -m 755 /opt/bitwise-control/dist
install -d -m 700 -o bitwise-control -g bitwise-control /etc/bitwise-control /var/lib/bitwise-control
install -m 644 "$SOURCE/server.py" "$SOURCE/agent.py" "$SOURCE/adapters.py" "$SOURCE/notifications.py" "$SOURCE/backup.py" "$SOURCE/service_checks.py" /opt/bitwise-control/
install -m 644 "$SOURCE/dist/index.html" "$SOURCE/dist/login.html" "$SOURCE/dist/app.js" "$SOURCE/dist/monitors.js" /opt/bitwise-control/dist/
if [ ! -f /etc/bitwise-control/auth.json ]; then
 python3 - <<'PY'
import secrets,hashlib,json
from pathlib import Path
password=secrets.token_urlsafe(18);salt=secrets.token_bytes(16)
Path('/etc/bitwise-control/auth.json').write_text(json.dumps({'username':'admin','salt':salt.hex(),'hash':hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1).hex()}))
print('Initial administrator username: admin\nInitial password: '+password)
PY
fi
chown bitwise-control:bitwise-control /etc/bitwise-control/auth.json
chmod 600 /etc/bitwise-control/auth.json
install -m 644 "$SOURCE/deploy/bitwise-control.service" "$SOURCE/deploy/bitwise-backup.service" "$SOURCE/deploy/bitwise-backup.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now bitwise-backup.timer
systemctl enable bitwise-control
systemctl restart bitwise-control
