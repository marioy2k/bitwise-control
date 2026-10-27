#!/usr/bin/env python3
"""Read-only Linux metrics agent. Configuration: /etc/bitwise-agent.json."""
import json,os,socket,time,subprocess
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

def handle_job(job,config,send):
 action=job.get('action')
 if action not in ('reboot','upgrade_check'):
  return send('/api/agent/result',{'job':job['id'],'status':'failed','result':'Unsupported command.'})
 if not config.get('allowControl',False):
  return send('/api/agent/result',{'job':job['id'],'status':'failed','result':'Device controls are disabled in the agent configuration.'})
 if action=='reboot':
  # Acknowledge before reboot; accepted means requested, not verified completed.
  send('/api/agent/result',{'job':job['id'],'status':'accepted','result':'Reboot accepted by agent. Verify recovery in the dashboard.'})
  subprocess.run(['/usr/bin/systemctl','reboot'],check=True,timeout=20)
 else:
  try:
   result=subprocess.run(['/usr/bin/apt','list','--upgradable'],capture_output=True,text=True,timeout=60)
   send('/api/agent/result',{'job':job['id'],'status':'completed' if result.returncode==0 else 'failed','result':(result.stdout or result.stderr)[:32000]})
  except (OSError,subprocess.TimeoutExpired) as e:
   send('/api/agent/result',{'job':job['id'],'status':'failed','result':'Update check failed: '+type(e).__name__})

def main():
 config=json.loads(CONFIG.read_text());base=config['server'].rstrip('/')
 if not base.startswith(('http://','https://')):raise ValueError('Server must be an HTTP or HTTPS URL.')
 def send(path,body=None):
  request=Request(base+path,data=json.dumps(body).encode() if body is not None else None,headers={'Authorization':'Bearer '+config['token'],'Content-Type':'application/json'})
  with urlopen(request,timeout=15) as response:return json.load(response)
 while True:
  try:
   send('/api/agent/report',sample());print('Metrics delivered',flush=True)
   for job in send('/api/agent/jobs'):handle_job(job,config,send)
  except Exception as e:print('Agent operation failed:',type(e).__name__,str(e),flush=True)
  time.sleep(max(15,int(config.get('interval',60))))
if __name__=='__main__':main()
