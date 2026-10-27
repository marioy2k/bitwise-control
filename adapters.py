"""Device adapters. Only documented, explicitly selected operations are exposed."""
import base64,json,math,os,re,ssl,subprocess,tempfile
from urllib.parse import quote,urlsplit
from urllib.request import Request,build_opener,HTTPSHandler,HTTPRedirectHandler
from urllib.error import HTTPError,URLError

class AdapterError(Exception):
 def __init__(self,message,uncertain=False):super().__init__(message);self.uncertain=uncertain
class NoRedirect(HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise AdapterError('Controller redirect refused; enter its direct API URL.')

def bounded(value):
 try:
  value=float(value)
  return round(max(0,min(100,value)),2) if math.isfinite(value) else None
 except (TypeError,ValueError):return None

def ratio(used,total):
 try:return bounded(float(used)/float(total)*100) if float(total)>0 else None
 except (TypeError,ValueError):return None

def seconds(value):
 if isinstance(value,(int,float)):return max(0,value)
 value=str(value or '')
 total=sum(float(n)*{'w':604800,'d':86400,'h':3600,'m':60,'s':1}[unit] for n,unit in re.findall(r'(\d+(?:\.\d+)?)([wdhms])',value))
 if ':' in value:
  try:
   parts=value.split(':');total+=float(parts[-1])+float(parts[-2])*60+(float(parts[-3])*3600 if len(parts)>2 else 0)
  except ValueError:pass
 return total

def http(config,path,method='GET',body=None,headers=None):
 url=config['url'].rstrip('/')+path
 context=ssl.create_default_context(cadata=config.get('caPem') or None)
 request=Request(url,method=method,data=json.dumps(body).encode() if body is not None else None,headers={'Accept':'application/json','Content-Type':'application/json',**(headers or {})})
 try:
  with build_opener(NoRedirect(),HTTPSHandler(context=context)).open(request,timeout=12) as response:
   raw=response.read(2_000_001)
   if len(raw)>2_000_000:raise AdapterError('Controller response exceeds 2 MB.')
   return json.loads(raw) if raw else {}
 except HTTPError as e:raise AdapterError(f'Controller returned HTTP {e.code}. Check API permissions and settings.')
 except URLError:raise AdapterError('Connection or certificate verification failed. Check address, network, and CA certificate.',uncertain=method!='GET')
 except (ValueError,ssl.SSLError):raise AdapterError('Invalid API response or CA certificate.')

def safe_part(value):return quote(str(value),safe='')
def pve_headers(c):return {'Authorization':'PVEAPIToken='+c['tokenId']+'='+c['tokenSecret']}
def pve_path(c):
 node=safe_part(c['node']);kind=c.get('target','node')
 return '/api2/json/nodes/'+node+('/'+kind+'/'+str(c['vmid']) if kind in ('lxc','qemu') else '')
def pve(c,path,method='GET',body=None):return http(c,path,method,body,pve_headers(c)).get('data')
def pve_poll(c):
 kind=c.get('target','node');d=pve(c,pve_path(c)+('/status' if kind=='node' else '/status/current'))
 memory=d.get('memory',{});root=d.get('rootfs',{})
 return {'source':'Proxmox API','cpu':bounded(d['cpu']*100) if d.get('cpu') is not None else None,'memory':ratio(memory.get('used'),memory.get('total')) if kind=='node' else ratio(d.get('mem'),d.get('maxmem')),'disk':ratio(root.get('used'),root.get('total')) if kind=='node' else ratio(d.get('disk'),d.get('maxdisk')),'uptimeSeconds':d.get('uptime'),'operationalOnline':d.get('status','running')=='running','hostname':c['node']}
def pve_discover(c):return pve(c,'/api2/json/cluster/resources')
def pve_action(c,action,args):
 path=pve_path(c);kind=c.get('target','node')
 if action=='reboot':return pve(c,path+'/status','POST',{'command':'reboot'}) if kind=='node' else pve(c,path+'/status/reboot','POST',{})
 if action in ('start','shutdown') and kind!='node':return pve(c,path+'/status/'+action,'POST',{})
 if action=='config_backup':return pve(c,path+('/config' if kind!='node' else '/network'))
 if action=='upgrade_check' and kind=='node':return pve(c,path+'/apt/update')
 if action=='configure' and kind in ('lxc','qemu'):
  updates={}
  for key in ('memory','cores'):
   if key in args:
    value=args[key]
    if type(value)!=int or not 1<=value<=(1048576 if key=='memory' else 256):raise AdapterError('Invalid '+key+' value.')
    updates[key]=value
  if not updates:raise AdapterError('Provide memory (MiB) or CPU cores.')
  return pve(c,path+'/config','PUT',updates)
 raise AdapterError('This operation is not supported for this Proxmox target.')

def mt_headers(c):return {'Authorization':'Basic '+base64.b64encode((c['username']+':'+c['password']).encode()).decode()}
def mt(c,path,method='GET',body=None):return http(c,'/rest'+path,method,body,mt_headers(c))
def mt_poll(c):
 d=mt(c,'/system/resource');d=d[0] if isinstance(d,list) else d
 out={'source':'MikroTik REST','cpu':bounded(d.get('cpu-load')),'memory':ratio(float(d.get('total-memory',0))-float(d.get('free-memory',0)),d.get('total-memory')),'disk':ratio(float(d.get('total-hdd-space',0))-float(d.get('free-hdd-space',0)),d.get('total-hdd-space')),'uptimeSeconds':seconds(d.get('uptime')),'hostname':d.get('board-name','MikroTik'),'version':d.get('version')}
 try:out['ports']=mt(c,'/interface/ethernet/poe')
 except AdapterError:out['ports']=[]
 return out

def mt_action(c,action,args):
 if action=='reboot':return mt(c,'/system/reboot','POST',{})
 if action=='upgrade_check':return mt(c,'/system/package/update/check-for-updates','POST',{})
 if action=='upgrade':return mt(c,'/system/package/update/install','POST',{})
 if action=='config_backup':return mt(c,'/export','POST',{'compact':''})
 if action=='poe':
  mode=args.get('mode');port=args.get('port')
  if mode not in ('off','auto-on','forced-on') or not isinstance(port,str) or not re.fullmatch(r'\*[0-9A-Fa-f]+',port):raise AdapterError('Select a valid PoE port and mode.')
  return mt(c,'/interface/ethernet/poe/'+safe_part(port),'PATCH',{'poe-out':mode})
 raise AdapterError('Unsupported MikroTik operation.')

def ui(c,path,method='GET',body=None):return http(c,path,method,body,{'X-API-Key':c['apiKey']})
def ui_path(c):return '/sites/'+safe_part(c['siteId'])+'/devices/'+safe_part(c['deviceId'])
def ui_poll(c):
 path=ui_path(c);d=ui(c,path);m=ui(c,path+'/statistics/latest')
 return {'source':'UniFi API','cpu':bounded(m.get('cpuUtilizationPct')),'memory':bounded(m.get('memoryUtilizationPct')),'disk':None,'uptimeSeconds':m.get('uptimeSec'),'hostname':d.get('name'),'operationalOnline':d.get('state')=='ONLINE','ports':d.get('interfaces',{}).get('ports',[]),'version':d.get('firmwareVersion'),'firmwareUpdatable':d.get('firmwareUpdatable')}
def ui_action(c,action,args):
 if action=='reboot':return ui(c,ui_path(c)+'/actions','POST',{'action':'RESTART'})
 if action=='poe_cycle':
  port=args.get('port')
  if type(port)!=int or not 1<=port<=1024:raise AdapterError('Enter a valid port number.')
  return ui(c,ui_path(c)+'/interfaces/ports/'+str(port)+'/actions','POST',{'action':'POWER_CYCLE'})
 if action=='config_backup':return ui(c,ui_path(c))
 raise AdapterError('This operation is not exposed by the supported official UniFi API.')

def snmp(c,oid,walk=False,value=None,indexed=False):
 if not re.fullmatch(r'\.?[0-9]+(?:\.[0-9]+)+',oid):raise AdapterError('Invalid numeric SNMP OID.')
 with tempfile.TemporaryDirectory(prefix='bitwise-snmp-') as folder:
  def q(s):return '"'+str(s).replace('\\','\\\\').replace('"','\\"')+'"'
  settings=['defVersion 3','defSecurityLevel authPriv','defSecurityName '+q(c['username']),'defAuthType SHA','defPrivType AES','defAuthPassphrase '+q(c['authPassword']),'defPrivPassphrase '+q(c['privPassword'])]
  conf=os.path.join(folder,'snmp.conf')
  with open(conf,'w') as f:f.write('\n'.join(settings)+'\n')
  os.chmod(conf,0o600)
  target='udp:'+c['host']+':'+str(c.get('port',161))
  command=['snmpset' if value is not None else ('snmpwalk' if walk else 'snmpget'),'-v','3','-t','3','-r','0','-Onq' if indexed else '-Oqv','-Ot',target,oid]
  if value is not None:command+=['i',str(value)]
  try:
   r=subprocess.run(command,env={**os.environ,'SNMPCONFPATH':folder,'MIBS':''},capture_output=True,text=True,timeout=8)
  except FileNotFoundError:raise AdapterError('Install the snmp package on the central server.')
  except subprocess.TimeoutExpired:raise AdapterError('SNMP request timed out.',uncertain=value is not None)
  if r.returncode or 'No Such' in r.stdout:raise AdapterError('SNMP request failed. Check SNMPv3 credentials, permissions, OID support, and network access.')
  return r.stdout.strip()

def snmp_poll(c):
 uptime=snmp(c,'.1.3.6.1.2.1.1.3.0');m=re.search(r'\((\d+)\)',uptime)
 try:uptime=int(m.group(1) if m else uptime)/100
 except ValueError:uptime=seconds(uptime)
 out={'source':'SNMPv3','cpu':None,'memory':None,'disk':None,'uptimeSeconds':uptime}
 try:out['hostname']=snmp(c,'.1.3.6.1.2.1.1.5.0').strip('"')
 except AdapterError:pass
 try:
  values=[float(x) for x in snmp(c,'.1.3.6.1.2.1.25.3.3.1.2',walk=True).splitlines()];out['cpu']=bounded(sum(values)/len(values)) if values else None
 except (AdapterError,ValueError):pass
 try:
  total=float(snmp(c,'.1.3.6.1.4.1.2021.4.5.0'));free=float(snmp(c,'.1.3.6.1.4.1.2021.4.6.0'));out['memory']=ratio(total-free,total)
 except (AdapterError,ValueError):pass
 if c.get('temperatureOid'):
  try:out['temp']=float(snmp(c,c['temperatureOid']))/float(c.get('temperatureDivisor',1))
  except (AdapterError,ValueError):pass
 return out

# RFC 3805 Printer-MIB: retain the full (device, supply) index when joining columns.
def printer_poll(c):
 root='.1.3.6.1.2.1.43.11.1.1'
 raw=snmp(c,root,walk=True,indexed=True)
 rows={}
 for line in raw.splitlines():
  match=re.fullmatch(r'\.?1\.3\.6\.1\.2\.1\.43\.11\.1\.1\.(4|5|6|7|8|9)\.(\d+\.\d+)\s+(.+)',line.strip())
  if not match:continue
  col,index,value=match.groups();rows.setdefault(index,{})[int(col)]=value.strip().strip('"')
 supplies=[]
 for index,row in sorted(rows.items()):
  def number(col):
   try:return int(row.get(col,''))
   except ValueError:return None
  level,capacity,unit,kind=number(9),number(8),number(7),number(4)
  percent=None
  if level is not None and level>=0:
   if unit==19 and level<=100:percent=float(level)
   elif unit not in (None,1,2,19) and capacity is not None and capacity>0 and level<=capacity:percent=round(level/capacity*100,2)
  supplies.append({'id':index,'name':row.get(6) or 'Supply '+index,'class':kind,'type':number(5),'percent':percent,'level':level,'capacity':capacity,'unit':unit})
 if not supplies:raise AdapterError('Printer supplies unavailable. Check Printer-MIB support and SNMP read permissions.')
 return {'source':'Printer SNMPv3','supplies':supplies,'cpu':None,'memory':None,'disk':None}

def printer_action(c,action,args):raise AdapterError('Printer monitoring is read-only.')

def snmp_action(c,action,args):
 if action!='poe':raise AdapterError('Only standard POWER-ETHERNET-MIB PoE control is supported for SNMP devices.')
 group=args.get('group',1);port=args.get('port');mode=args.get('mode')
 if type(group)!=int or type(port)!=int or not 1<=group<=1024 or not 1<=port<=1024 or mode not in ('on','off'):raise AdapterError('Enter a valid PSE group, port, and on/off mode.')
 return snmp(c,'.1.3.6.1.2.1.105.1.1.1.3.'+str(group)+'.'+str(port),value=1 if mode=='on' else 2)

POLL={'proxmox':pve_poll,'mikrotik':mt_poll,'unifi':ui_poll,'snmp':snmp_poll,'printer':printer_poll}
ACTION={'proxmox':pve_action,'mikrotik':mt_action,'unifi':ui_action,'snmp':snmp_action,'printer':printer_action}
SECRETS={'tokenSecret','password','apiKey','authPassword','privPassword'}

def validate(config):
 kind=config.get('kind')
 if kind not in POLL:raise ValueError('Choose Proxmox, MikroTik, UniFi, SNMPv3, or Printer SNMPv3.')
 allowed={'kind','url','caPem','node','target','vmid','tokenId','tokenSecret','username','password','siteId','deviceId','apiKey','host','port','authPassword','privPassword','temperatureOid','temperatureDivisor','allowControl','supplyThreshold'}
 c={k:v for k,v in config.items() if k in allowed}
 for key,value in c.items():
  if isinstance(value,str) and (len(value)>16384 or '\x00' in value or ('\n' in value and key!='caPem') or '\r' in value):raise ValueError('Invalid '+key+' value.')
 if type(c.get('allowControl',False))!=bool:raise ValueError('Invalid controls setting.')
 required={'proxmox':['url','node','tokenId','tokenSecret'],'mikrotik':['url','username','password'],'unifi':['url','siteId','deviceId','apiKey'],'snmp':['host','username','authPassword','privPassword'],'printer':['host','username','authPassword','privPassword']}[kind]
 for key in required:
  if not isinstance(c.get(key),str) or not c[key].strip():raise ValueError('Required setting: '+key)
 if kind not in ('snmp','printer'):
  u=urlsplit(c['url'])
  if u.scheme!='https' or not u.hostname or u.username or u.password or u.query or u.fragment:raise ValueError('Use a direct HTTPS URL without embedded credentials or query parameters.')
  if kind in ('proxmox','mikrotik') and u.path not in ('','/'):raise ValueError('Use the server origin only; API paths are added automatically.')
  if c.get('caPem'):
   try:ssl.create_default_context(cadata=c['caPem'])
   except ssl.SSLError:raise ValueError('Invalid CA certificate PEM.')
 if kind=='proxmox':
  if c.get('target','node') not in ('node','lxc','qemu'):raise ValueError('Choose node, lxc, or qemu.')
  if c.get('target') in ('lxc','qemu') and (type(c.get('vmid'))!=int or not 100<=c['vmid']<=999999999):raise ValueError('Enter a valid VM/container ID.')
 if kind in ('snmp','printer'):
  if any(x in c['host'] for x in [' ','/','\n',':']):raise ValueError('Use an IPv4 address or hostname for SNMP.')
  if any(len(c[k])<8 for k in ['authPassword','privPassword']):raise ValueError('SNMPv3 passphrases need at least 8 characters.')
  if type(c.get('port',161))!=int or not 1<=c.get('port',161)<=65535:raise ValueError('Invalid SNMP port.')
  if c.get('temperatureOid') and not re.fullmatch(r'\.?[0-9]+(?:\.[0-9]+)+',c['temperatureOid']):raise ValueError('Use a numeric temperature OID.')
  divisor=c.get('temperatureDivisor',1)
  if type(divisor) not in (float,int) or not math.isfinite(divisor) or divisor<=0:raise ValueError('Temperature divisor must be positive.')
 if kind=='printer':
  threshold=c.get('supplyThreshold',20)
  if type(threshold)!=int or not 0<=threshold<=100:raise ValueError('Printer supply threshold must be 0–100 percent; 0 disables warnings.')
  c['supplyThreshold']=threshold;c['allowControl']=False
 return c

def public(config):return {**{k:v for k,v in config.items() if k not in SECRETS},'credentialsConfigured':True}
def poll(c):return POLL[c['kind']](c)
def action(c,name,args):
 if not c.get('allowControl'):raise AdapterError('Enable device controls in connection settings first.')
 return ACTION[c['kind']](c,name,args)
