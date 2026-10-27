#!/usr/bin/env python3
"""Read-only Linux metrics agent. Configuration: /etc/bitwise-agent.json."""
import json,os,socket,time
from pathlib import Path
from urllib.request import Request,urlopen
CONFIG=Path(os.environ.get('BITWISE_AGENT_CONFIG','/etc/bitwise-agent.json'))

def read_number(path):
 try:
  value=Path(path).read_text().strip();return None if value=='max' else int(value)
 except (OSError,ValueError):return None

def cpu_snapshot():
 values=list(map(int,Path('/proc/stat').read_text().splitlines()[0].split()[1:9]));return sum(values),values[3]+values[4]

def usage_usec():
 try:return int(dict(line.split() for line in Path('/sys/fs/cgroup/cpu.stat').read_text().splitlines())['usage_usec'])
 except (OSError,ValueError,KeyError):return None

def cpu_count():
 count=os.cpu_count() or 1
 try:
  quota,period=Path('/sys/fs/cgroup/cpu.max').read_text().split()
  if quota!='max':count=min(count,int(quota)/int(period))
 except (OSError,ValueError):pass
 return max(count,0.01)

def sample():
 total,idle=cpu_snapshot();cg=usage_usec();start=time.monotonic();time.sleep(1);total2,idle2=cpu_snapshot();cg2=usage_usec()
 cpu=100*(1-(idle2-idle)/max(1,total2-total))
 if cg is not None and cg2 is not None:cpu=100*(cg2-cg)/1_000_000/(time.monotonic()-start)/cpu_count()
 mem={}
 for line in Path('/proc/meminfo').read_text().splitlines():
  key,value=line.split(':',1);mem[key]=int(value.strip().split()[0])*1024
 limit=read_number('/sys/fs/cgroup/memory.max');used=read_number('/sys/fs/cgroup/memory.current')
 if limit and limit<mem['MemTotal'] and used is not None:memory=100*used/limit
 else:memory=100*(1-mem.get('MemAvailable',mem['MemFree'])/mem['MemTotal'])
 disk=os.statvfs('/');disk_use=100*(disk.f_blocks-disk.f_bfree)/max(1,disk.f_blocks)
 return {'hostname':socket.gethostname(),'cpu':round(max(0,min(100,cpu)),2),'memory':round(max(0,min(100,memory)),2),'disk':round(max(0,min(100,disk_use)),2),'uptimeSeconds':float(Path('/proc/uptime').read_text().split()[0])}

def main():
 config=json.loads(CONFIG.read_text());url=config['server'].rstrip('/')+'/api/agent/report'
 if not url.startswith(('http://','https://')):raise ValueError('Server must be an HTTP or HTTPS URL.')
 while True:
  try:
   request=Request(url,data=json.dumps(sample()).encode(),headers={'Authorization':'Bearer '+config['token'],'Content-Type':'application/json'})
   with urlopen(request,timeout=15) as response:
    if response.status!=200:raise RuntimeError('Unexpected response '+str(response.status))
   print('Metrics delivered',flush=True)
  except Exception as e:print('Delivery failed:',type(e).__name__,str(e),flush=True)
  time.sleep(max(15,int(config.get('interval',60))))
if __name__=='__main__':main()
