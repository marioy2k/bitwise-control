"""Consistent SQLite backup; keep the most recent seven daily snapshots."""
import os,sqlite3,time
from pathlib import Path
base=Path(os.environ.get('BITWISE_DATA','/var/lib/bitwise-control'))
folder=base/'backups';folder.mkdir(mode=0o700,exist_ok=True)
target=folder/time.strftime('control-%Y%m%d.sqlite3')
with sqlite3.connect(base/'control.sqlite3') as source,sqlite3.connect(target) as destination:source.backup(destination)
target.chmod(0o600)
for old in sorted(folder.glob('control-*.sqlite3'))[:-7]:old.unlink()
print(target)
