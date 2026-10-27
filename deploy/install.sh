#!/bin/sh
set -eu
[ "$(id -u)" = 0 ] || { echo 'Run as root.'; exit 1; }
SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
command -v python3 >/dev/null
if ! command -v snmpget >/dev/null 2>&1; then
 apt-get update -qq
 DEBIAN_FRONTEND=noninteractive apt-get install -y snmp
fi
getent passwd bitwise-control >/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin bitwise-control
install -d -m 755 /opt/bitwise-control/dist
install -d -m 700 -o bitwise-control -g bitwise-control /etc/bitwise-control /var/lib/bitwise-control
install -m 644 "$SOURCE/server.py" "$SOURCE/agent.py" "$SOURCE/adapters.py" "$SOURCE/notifications.py" "$SOURCE/backup.py" /opt/bitwise-control/
install -m 644 "$SOURCE/dist/index.html" "$SOURCE/dist/login.html" "$SOURCE/dist/app.js" /opt/bitwise-control/dist/
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
