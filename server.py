"""Bitwise Control: authenticated inventory and Linux agent monitoring."""
import hashlib,hmac,json,math,os,re,secrets,socket,sqlite3,threading,time,ssl
from concurrent.futures import ThreadPoolExecutor
import adapters,notifications,service_checks
from urllib.parse import parse_qs,urlsplit
import html
from pathlib import Path
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from http.cookies import SimpleCookie
from urllib.parse import urlparse

ROOT=Path(__file__).resolve().parent
DATA=Path(os.environ.get('BITWISE_DATA','/var/lib/bitwise-control'))
AUTH=Path(os.environ.get('BITWISE_AUTH','/etc/bitwise-control/auth.json'))
DB=DATA/'control.sqlite3'
LOCK=threading.RLock()
SESSIONS={};ATTEMPTS={}
STOP=threading.Event()
POOL=ThreadPoolExecutor(max_workers=6)
POLLING=set()
AUDIT_CONTEXT=threading.local()

@contextmanager
def connect():
 c=sqlite3.connect(DB,timeout=15);c.row_factory=sqlite3.Row;c.execute('PRAGMA foreign_keys=ON')
 try:
  with c:yield c
 finally:c.close()

def init():
 DATA.mkdir(parents=True,exist_ok=True)
 with connect() as c:
  c.executescript('''PRAGMA journal_mode=WAL;
  CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY,salt TEXT NOT NULL,hash TEXT NOT NULL,role TEXT NOT NULL,companies TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1);
  CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY,subject TEXT NOT NULL,message TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',attempts INTEGER NOT NULL DEFAULT 0,next_attempt REAL NOT NULL DEFAULT 0,created REAL NOT NULL);
  CREATE TABLE IF NOT EXISTS connections(device INTEGER PRIMARY KEY, config TEXT NOT NULL, last_attempt REAL NOT NULL DEFAULT 0, last_error TEXT);
  CREATE TABLE IF NOT EXISTS jobs(id INTEGER PRIMARY KEY, device INTEGER NOT NULL, action TEXT NOT NULL, arguments TEXT NOT NULL, status TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL, result TEXT);
  CREATE TABLE IF NOT EXISTS inventory(id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, data TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS samples(id INTEGER PRIMARY KEY, device INTEGER NOT NULL, time REAL NOT NULL, data TEXT NOT NULL);
  CREATE INDEX IF NOT EXISTS samples_device_time ON samples(device,time);
  CREATE INDEX IF NOT EXISTS samples_time ON samples(time);
  CREATE TABLE IF NOT EXISTS tokens(device INTEGER PRIMARY KEY, digest TEXT NOT NULL);
  CREATE UNIQUE INDEX IF NOT EXISTS tokens_digest ON tokens(digest);
  CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, time REAL NOT NULL, action TEXT NOT NULL, device TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS incidents(device INTEGER PRIMARY KEY, opened REAL NOT NULL, message TEXT NOT NULL);
  ''')
  c.execute('CREATE TABLE IF NOT EXISTS push_tokens(device INTEGER PRIMARY KEY,digest TEXT NOT NULL UNIQUE)')
  c.execute('CREATE TABLE IF NOT EXISTS status_pages(slug TEXT PRIMARY KEY,title TEXT NOT NULL,devices TEXT NOT NULL)')
  for column in ('domain','description'):
   if column not in [row['name'] for row in c.execute('PRAGMA table_info(status_pages)')]:c.execute("ALTER TABLE status_pages ADD COLUMN "+column+" TEXT NOT NULL DEFAULT ''")
  if 'failures' not in [row['name'] for row in c.execute('PRAGMA table_info(connections)')]:c.execute('ALTER TABLE connections ADD COLUMN failures INTEGER NOT NULL DEFAULT 0')
  if 'last_notified' not in [row['name'] for row in c.execute('PRAGMA table_info(incidents)')]:c.execute('ALTER TABLE incidents ADD COLUMN last_notified REAL NOT NULL DEFAULT 0')
  for column,definition in [('device','INTEGER'),('category',"TEXT NOT NULL DEFAULT ''")]:
   if column not in [row['name'] for row in c.execute('PRAGMA table_info(outbox)')]:c.execute('ALTER TABLE outbox ADD COLUMN '+column+' '+definition)
  if 'channel' not in [row['name'] for row in c.execute('PRAGMA table_info(outbox)')]:c.execute("ALTER TABLE outbox ADD COLUMN channel TEXT NOT NULL DEFAULT ''")
  if 'actor' not in [row['name'] for row in c.execute('PRAGMA table_info(audit)')]:c.execute("ALTER TABLE audit ADD COLUMN actor TEXT NOT NULL DEFAULT 'system'")
  c.execute('INSERT OR IGNORE INTO inventory VALUES(1,0,?)',(json.dumps({'companies':[],'devices':[],'rules':[],'channels':{}}),))

def audit(c,action,device=''):
 c.execute('INSERT INTO audit(time,action,device,actor) VALUES(?,?,?,?)',(time.time(),action,str(device),getattr(AUDIT_CONTEXT,'user','system')))

def load(c):
 row=c.execute('SELECT * FROM inventory WHERE id=1').fetchone();return json.loads(row['data']),row['revision']

def store(c,state):
 c.execute('UPDATE inventory SET data=?,revision=revision+1 WHERE id=1',(json.dumps(state,allow_nan=False),))

def get_settings(c):
 row=c.execute("SELECT value FROM settings WHERE key='monitoring'").fetchone()
 return json.loads(row['value']) if row else {'rules':dict(notifications.DEFAULT_RULES),'delivery':{'mode':'none'}}

def queue_notification(c,subject,message,device=None,category=''):
 if device is not None:
  row=c.execute('SELECT config FROM connections WHERE device=?',(device,)).fetchone()
  if row and json.loads(row['config']).get('notify',True) is False:return
 for channel in notifications.channels(get_settings(c)['delivery']):
  if category=='reminder' and c.execute("SELECT 1 FROM outbox WHERE device=? AND channel=? AND status='pending' AND category IN ('alert','reminder')",(device,channel)).fetchone():continue
  c.execute('INSERT INTO outbox(subject,message,created,channel,device,category) VALUES(?,?,?,?,?,?)',(subject,message,time.time(),channel,device,category))

def deliver_notifications():
 with connect() as c:
  config=get_settings(c)['delivery'];rows=[dict(r) for r in c.execute("SELECT * FROM outbox WHERE status='pending' AND next_attempt<=? ORDER BY id LIMIT 5",(time.time(),))]
 if config.get('mode','none')=='none':return
 for row in rows:
  channel=row['channel'] or config.get('mode','none')
  if channel not in notifications.channels(config):
   with LOCK,connect() as c:c.execute("UPDATE outbox SET status='cancelled' WHERE id=?",(row['id'],))
   continue
  try:notifications.send({**config,'mode':channel},row['subject'],row['message']);status='sent'
  except Exception:status='failed' if row['attempts']>=4 else 'pending'
  with LOCK,connect() as c:c.execute('UPDATE outbox SET status=?,attempts=attempts+1,next_attempt=? WHERE id=?',(status,time.time()+60*2**row['attempts'],row['id']))

def monitor_stats(c,ident,config):
 now=time.time();rows=[(r['time'],json.loads(r['data'])) for r in c.execute('SELECT time,data FROM samples WHERE device=? AND time>=? ORDER BY time',(ident,now-30*86400))]
 result={'recent':[{'time':t,'up':d.get('serviceOnline'),'responseMs':d.get('responseMs')} for t,d in rows[-60:]]}
 for label,window in [('day',86400),('week',7*86400),('month',30*86400)]:
  total=up=0;latencies=[]
  for i,(t,d) in enumerate(rows):
   end=min(now,rows[i+1][0] if i+1<len(rows) else now,t+config.get('interval',60)+config.get('timeout',10));duration=max(0,end-max(t,now-window));online=d.get('serviceOnline')
   if online is not None:total+=duration;up+=duration if online else 0
   if t>=now-window and d.get('responseMs') is not None:latencies.append(d['responseMs'])
  result[label]={'uptime':round(up/total*100,3) if total else None,'observedSeconds':round(total),'averageMs':round(sum(latencies)/len(latencies),2) if latencies else None}
 return result

def public_status(slug):
 with connect() as c:row=c.execute('SELECT title,devices,description FROM status_pages WHERE slug=?',(slug,)).fetchone()
 if not row:return None
 ids=set(json.loads(row['devices']));state=view_state()
 return {'slug':slug,'title':row['title'],'description':row['description'],'time':time.time(),'devices':[{'id':d['id'],'name':d['name'],'status':d['status'],'uptime':d.get('availability',{}).get('day',{}).get('uptime')} for d in state['devices'] if d['id'] in ids]}

def status_html(page):
 title=html.escape(page['title']);rows=''.join('<article><strong>'+html.escape(d['name'])+'</strong><span>'+html.escape(d['status'])+'</span><small>'+('24h uptime: '+str(d['uptime'])+'%' if d['uptime'] is not None else 'Uptime: awaiting measurements')+'</small></article>' for d in page['devices'])
 return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="30"><title>'+title+'</title><style>body{font:16px system-ui;background:#f6f7fb;color:#18233d;max-width:800px;margin:60px auto;padding:20px}article{background:white;padding:24px;margin:12px 0;border-radius:12px}span{float:right}small{display:block;margin-top:10px;color:#526078}</style></head><body><h1>'+title+'</h1><p>'+html.escape(page.get('description',''))+'</p><p>Service status · Updates every 30 seconds</p>'+rows+'<footer>Powered by Bitwise Control</footer></body></html>'

def view_state(user=None):
 with LOCK,connect() as c:
  state,rev=load(c);settings=get_settings(c);rules=settings['rules']
  state['monitoring']=notifications.public(settings)
  state['notificationStatus']=[dict(r) for r in c.execute('SELECT id,subject,status,attempts,created,channel FROM outbox ORDER BY id DESC LIMIT 10')]
  for d in state['devices']:
   sample=c.execute('SELECT time,data FROM samples WHERE device=? ORDER BY time DESC LIMIT 1',(d['id'],)).fetchone()
   d.update(cpu=None,memory=None,temp=None,uptime=0,disk=None,lastSeen=None,status='Pending',poe=[],supplies=[])
   connection=c.execute('SELECT config,last_error,last_attempt FROM connections WHERE device=?',(d['id'],)).fetchone()
   d['integration']=adapters.public(json.loads(connection['config'])) if connection else None
   d['connectionError']=connection['last_error'] if connection else None
   if sample:
    data=json.loads(sample['data']);d.update(data);d['lastSeen']=sample['time'];d['status']='Online' if time.time()-sample['time']<rules['offlineSeconds'] else 'Offline'
   if d.get('operationalOnline') is False:d['status']='Offline'
   if d['connectionError']:d['status']='Offline'
   if d['status']=='Online' and any(rules.get('temperature' if k=='temp' else k,0)>0 and d.get(k) is not None and d[k]>rules['temperature' if k=='temp' else k] for k in ('cpu','memory','disk','temp')):d['status']='Warning'
   if d['integration'] and d['integration'].get('kind')=='service':
    cfg=d['integration'];deadline=cfg.get('interval',60)+cfg.get('timeout',10)
    if cfg.get('paused'):d['status']='Paused'
    elif sample:
     if time.time()-sample['time']>deadline:d['status']='Offline'
     elif d.get('serviceOnline') is None:d['status']='Pending'
     elif not d.get('serviceOnline',d.get('operationalOnline',False)):d['status']='Offline'
     else:d['status']='Warning' if d.get('monitorWarning') else 'Online'
    d['availability']=monitor_stats(c,d['id'],cfg)
   d['lowSupplies']=[]
   if d['integration'] and d['integration']['kind']=='printer':
    threshold=d['integration'].get('supplyThreshold',20)
    d['lowSupplies']=[s for s in d['supplies'] if threshold>0 and s.get('class')==3 and s.get('percent') is not None and s['percent']<=threshold]
    if d['status']=='Online' and d['lowSupplies']:d['status']='Warning'
  state['logs']=[{'time':time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(r['time'])),'action':r['action'],'actor':r['actor'],'device':r['device'],'company':''} for r in c.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 500')]
  state['incidents']=[dict(r) for r in c.execute('SELECT * FROM incidents ORDER BY opened DESC')]
  state['revision']=rev;state['serverTime']=time.time()
  if user:
   state['currentUser']={k:user[k] for k in ('username','role','companies')}
   if user['role']!='admin':
    allowed=set(user['companies']);state['companies']=[x for x in state['companies'] if x in allowed];state['devices']=[d for d in state['devices'] if d['company'] in allowed]
    ids={d['id'] for d in state['devices']};state['incidents']=[i for i in state['incidents'] if i['device'] in ids];state['logs']=[];state['notificationStatus']=[];state['monitoring']={'rules':state['monitoring']['rules'],'delivery':{'mode':'Managed by administrator'}}
  return state

def text(value,maxlen=128):
 if not isinstance(value,str) or not value.strip() or len(value)>maxlen:raise ValueError('Please provide a valid text value.')
 return value.strip()

def validate(body):
 companies=body.get('companies');devices=body.get('devices')
 if not isinstance(companies,list) or not isinstance(devices,list) or len(companies)>200 or len(devices)>5000:raise ValueError('Inventory exceeds supported limits.')
 companies=[text(x) for x in companies]
 if len(set(x.lower() for x in companies))!=len(companies):raise ValueError('Company names must be unique.')
 output=[];ids=set()
 for d in devices:
  ident=d.get('id')
  if type(ident)!=int or not 0<ident<2**53 or ident in ids:raise ValueError('Invalid or duplicate device ID.')
  ids.add(ident)
  company=text(d.get('company'))
  if company not in companies:raise ValueError('A device must belong to an existing company.')
  address=text(d.get('ip'),253)
  if any(ch.isspace() for ch in address) or any(ch in address for ch in '/@?#'):raise ValueError('Use a hostname or IP address without a URL or port.')
  port=d.get('port',22)
  if type(port)!=int or not 1<=port<=65535:raise ValueError('Port must be between 1 and 65535.')
  maintenance=d.get('maintenanceUntil',0)
  if type(maintenance) not in (int,float) or not math.isfinite(maintenance) or not 0<=maintenance<=time.time()+366*86400:raise ValueError('Invalid maintenance window.')
  output.append({'maintenanceUntil':maintenance,'id':ident,'name':text(d.get('name')),'company':company,'type':text(d.get('type')),'ip':address,'platform':text(d.get('platform')),'port':port})
 return {'companies':companies,'devices':output,'rules':[],'channels':{}}

def update_inventory(body,user=None):
 if user and user['role']!='admin':
  if user['role']!='operator':raise PermissionError('Administrator or operator access is required.')
  with connect() as c:original,_=load(c)
  allowed=set(user['companies']);visible=[name for name in original['companies'] if name in allowed]
  if body.get('companies')!=visible:raise PermissionError('Only administrators can change companies.')
  if not isinstance(body.get('devices'),list) or any(d.get('company') not in allowed for d in body['devices']):raise PermissionError('Device company is outside your access.')
  hidden=[d for d in original['devices'] if d['company'] not in allowed]
  body={**body,'companies':original['companies'],'devices':hidden+body['devices']}
 state=validate(body)
 with LOCK,connect() as c:
  old,rev=load(c)
  if body.get('revision')!=rev:raise RuntimeError('Inventory changed in another window. Refresh and try again.')
  oldids={d['id'] for d in old['devices']};newids={d['id'] for d in state['devices']}
  for ident in oldids-newids:
   c.execute('DELETE FROM push_tokens WHERE device=?',(ident,));c.execute('DELETE FROM connections WHERE device=?',(ident,));c.execute('DELETE FROM jobs WHERE device=?',(ident,));c.execute('DELETE FROM samples WHERE device=?',(ident,));c.execute('DELETE FROM tokens WHERE device=?',(ident,));c.execute('DELETE FROM incidents WHERE device=?',(ident,))
  olddevices={d['id']:d for d in old['devices']}
  for device in state['devices']:
   if device.get('maintenanceUntil',0)!=olddevices.get(device['id'],{}).get('maintenanceUntil',0):audit(c,'Maintenance window updated',device['name'])
  if old!=state:audit(c,'Inventory updated',f"{len(state['companies'])} companies, {len(state['devices'])} devices")
  store(c,state)
 incidents()
 return view_state(user)

def record(ident,data):
 now=time.time()
 with LOCK,connect() as c:
  state,_=load(c)
  if not any(d['id']==ident for d in state['devices']):raise ValueError('Device no longer exists.')
  c.execute('INSERT INTO samples(device,time,data) VALUES(?,?,?)',(ident,now,json.dumps(data,allow_nan=False)))
  c.execute('DELETE FROM samples WHERE time<?',(now-30*86400,))

def incidents():
 state=view_state();now=time.time()
 with LOCK,connect() as c:
  for d in state['devices']:
   message=('Device connection failed' if d.get('connectionError') else 'Device stopped reporting') if d['status']=='Offline' else ('Resource monitoring threshold exceeded' if d['status']=='Warning' else None)
   if d['status']=='Warning' and d.get('lowSupplies'):
    message='Printer supply low: '+', '.join(s['name']+' ('+str(s['percent'])+'% remaining)' for s in d['lowSupplies'])
   if d.get('integration',{} ) and d['integration'].get('kind')=='service' and d['status'] in ('Offline','Warning'):message=d.get('monitorMessage') or ('Monitor stopped reporting' if d['status']=='Offline' else 'Monitor warning')
   maintenance=d.get('maintenanceUntil',0)>now or d['status']=='Paused'
   if maintenance:message=None
   old=c.execute('SELECT message,last_notified,opened FROM incidents WHERE device=?',(d['id'],)).fetchone()
   if message:
    c.execute('INSERT INTO incidents(device,opened,message,last_notified) VALUES(?,?,?,?) ON CONFLICT(device) DO UPDATE SET message=excluded.message',(d['id'],now,message,now))
    if not old:
     audit(c,'Alert opened: '+message,d['name']);queue_notification(c,'Bitwise alert: '+d['name'],d['company']+' / '+d['name']+' ('+d['ip']+'): '+message,d['id'],'alert')
    else:
     interval=state['monitoring']['delivery'].get('reminderMinutes',0)*60
     if interval and now-max(old['last_notified'],old['opened'])>=interval:
      queue_notification(c,'Bitwise reminder: '+d['name'],d['company']+' / '+d['name']+' ('+d['ip']+'): '+message,d['id'],'reminder')
      c.execute('UPDATE incidents SET last_notified=? WHERE device=?',(now,d['id']))
   elif old:
    c.execute("UPDATE outbox SET status='cancelled' WHERE device=? AND category IN ('alert','reminder') AND status='pending'",(d['id'],))
    c.execute('DELETE FROM incidents WHERE device=?',(d['id'],));audit(c,'Alert silenced for maintenance' if maintenance else 'Alert recovered',d['name'])
    if not maintenance:queue_notification(c,'Bitwise recovery: '+d['name'],d['company']+' / '+d['name']+' is reporting normally again.',d['id'],'recovery')

def status_summaries():
 state=view_state();now=time.time()
 with LOCK,connect() as c:
  delivery=get_settings(c)['delivery'];interval=delivery.get('summaryMinutes',0)*60
  if not interval or not notifications.channels(delivery):return
  row=c.execute("SELECT value FROM settings WHERE key='summary_last_queued'").fetchone()
  last=float(row['value']) if row else now
  if not row:
   c.execute("INSERT INTO settings VALUES('summary_last_queued',?)",(str(now),));return
  if now-last<interval:return
  devices=state['devices'];lines=[f"{len(devices)} devices; {sum(d['status']=='Offline' for d in devices)} offline; {sum(d['status']=='Warning' for d in devices)} warnings; {len(state['incidents'])} open incidents."]
  for d in devices[:50]:
   detail=', '.join(s['name']+': '+(str(s['percent'])+'%' if s.get('percent') is not None else 'unavailable') for s in d.get('supplies',[]))
   lines.append(d['company']+' / '+d['name']+': '+d['status']+(' (maintenance)' if d.get('maintenanceUntil',0)>now else '')+(' — '+detail if detail else ''))
  if len(devices)>50:lines.append('Showing the first 50 devices; open the dashboard for the full inventory.')
  queue_notification(c,'Bitwise status summary','\n'.join(lines),category='summary')
  c.execute("UPDATE settings SET value=? WHERE key='summary_last_queued'",(str(now),))

def poll_device(ident):
 try:
  with connect() as c:
   row=c.execute('SELECT config FROM connections WHERE device=?',(ident,)).fetchone()
  if not row:raise ValueError('No device connection configured.')
  config=json.loads(row['config'])
  if config.get('kind')=='service' and (config.get('paused') or config.get('monitorType')=='push'):raise adapters.AdapterError('Paused and push monitors do not run active checks.')
  measurements=adapters.poll(config)
  if config.get('kind')=='service':
   with LOCK,connect() as c:
    current=c.execute('SELECT failures FROM connections WHERE device=?',(ident,)).fetchone();failures=0 if measurements.get('checkSuccess') else (current['failures'] if current else 0)+1
    c.execute('UPDATE connections SET failures=? WHERE device=?',(failures,ident))
    active=c.execute('SELECT 1 FROM incidents WHERE device=?',(ident,)).fetchone()
   measurements['serviceOnline']=True if measurements.get('checkSuccess') else (False if failures>config.get('retries',2) or active else None)
   measurements['failures']=failures
  record(ident,measurements)
  with LOCK,connect() as c:c.execute('UPDATE connections SET last_attempt=?,last_error=NULL WHERE device=?',(time.time(),ident))
  return measurements
 except Exception as e:
  message=str(e) if isinstance(e,adapters.AdapterError) else 'Polling failed. Check the connection settings and device API compatibility.'
  with LOCK,connect() as c:c.execute('UPDATE connections SET last_attempt=?,last_error=? WHERE device=?',(time.time(),message,ident))
  raise adapters.AdapterError(message)
 finally:
  with LOCK:POLLING.discard(ident)

def scheduled_poll(ident):
 try:poll_device(ident)
 except adapters.AdapterError:pass

def run_action(ident,name,args):
 with connect() as c:
  row=c.execute('SELECT config FROM connections WHERE device=?',(ident,)).fetchone()
  if not row:raise ValueError('Configure the device connection first.')
  config=json.loads(row['config'])
  cur=c.execute('INSERT INTO jobs(device,action,arguments,status,created,updated) VALUES(?,?,?,?,?,?)',(ident,name,json.dumps(args),'running',time.time(),time.time()));job=cur.lastrowid
  audit(c,'Requested '+name,ident)
 try:
  result=adapters.action(config,name,args);status='accepted' if name in ('reboot','shutdown','start','upgrade','configure','poe','poe_cycle') else 'completed'
 except adapters.AdapterError as e:result={'error':str(e)};status='unknown' if e.uncertain else 'failed'
 except Exception:result={'error':'Device operation could not be confirmed. Check device state before retrying.'};status='unknown'
 with LOCK,connect() as c:
  c.execute('UPDATE jobs SET status=?,updated=?,result=? WHERE id=?',(status,time.time(),json.dumps(result),job));audit(c,name+' '+status,ident)
 return {'job':job,'status':status,'result':result}

def monitor():
 while not STOP.wait(5):
  try:
   incidents();status_summaries();deliver_notifications()
   with LOCK,connect() as c:
    for row in c.execute('SELECT device,config,last_attempt FROM connections'):
     cfg=json.loads(row['config'])
     if cfg.get('kind')=='service' and (cfg.get('paused') or cfg.get('monitorType')=='push'):continue
     if time.time()-row['last_attempt']<(cfg.get('interval',60) if cfg.get('kind')=='service' else 60):continue
     ident=row['device']
     if ident not in POLLING:POLLING.add(ident);POOL.submit(scheduled_poll,ident)
    c.execute("UPDATE jobs SET status='unknown',result=?,updated=? WHERE status='running' AND updated<?",(json.dumps({'error':'Agent did not confirm completion; do not assume the operation succeeded.'}),time.time(),time.time()-600))
  except Exception as e:print('Monitor error:',e,flush=True)

class Handler(BaseHTTPRequestHandler):
 def log_message(self,format,*args):
  safe=tuple(re.sub(r'/api/push/[^ ?"\s]+','/api/push/[redacted]',str(arg)) for arg in args)
  super().log_message(format,*safe)
 def push_heartbeat(self,token):
  if len(token)>128:return self.reply(401,{'error':'Invalid push credential.'})
  digest=hashlib.sha256(token.encode()).hexdigest()
  with connect() as c:
   row=c.execute('SELECT p.device,c.config FROM push_tokens p JOIN connections c ON c.device=p.device WHERE p.digest=?',(digest,)).fetchone()
  if not row:return self.reply(401,{'error':'Invalid push credential.'})
  config=json.loads(row['config'])
  if config.get('monitorType')!='push' or config.get('paused'):return self.reply(409,{'error':'Push monitor is paused or unavailable.'})
  params=parse_qs(urlparse(self.path).query);status=params.get('status',['up'])[0]
  if status not in ('up','down'):return self.reply(400,{'error':'Use status=up or status=down.'})
  record(row['device'],{'source':'Service monitor','checkSuccess':status=='up','serviceOnline':status=='up','operationalOnline':status=='up','monitorMessage':'Push heartbeat reports down.' if status=='down' else 'Push heartbeat received.'});incidents()
  return self.reply(200,{'ok':True})
 def setup(self):
  super().setup();self.connection.settimeout(20)
 server_version='BitwiseControl/1.0'
 def reply(self,status,body=b'',headers=None,kind='application/json'):
  if isinstance(body,(dict,list)):body=json.dumps(body,allow_nan=False).encode()
  if isinstance(body,str):body=body.encode()
  self.send_response(status)
  for k,v in {'Content-Type':kind,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'same-origin','Content-Length':str(len(body)),**(headers or {})}.items():self.send_header(k,v)
  self.end_headers();self.wfile.write(body)
 def session(self):
  try:
   c=SimpleCookie();c.load(self.headers.get('Cookie',''));token=c['bitwise_session'].value
  except (KeyError,ValueError):return None
  with LOCK:
   session=SESSIONS.get(token)
   if session and session['expires']>time.time():
    username=session['username'];root=json.loads(AUTH.read_text())
    if username==root['username']:return token
    with connect() as db:row=db.execute('SELECT enabled FROM users WHERE username=?',(username,)).fetchone()
    if row and row['enabled']:return token
   SESSIONS.pop(token,None)
 def identity(self):
  token=self.session()
  if not token:return None
  with LOCK:username=SESSIONS[token]['username']
  root=json.loads(AUTH.read_text())
  if username==root['username']:return {'username':username,'role':'admin','companies':[]}
  with connect() as c:row=c.execute('SELECT username,role,companies FROM users WHERE username=?',(username,)).fetchone()
  return {'username':username,'role':row['role'],'companies':json.loads(row['companies'])} if row else None
 def device_access(self,ident):
  user=self.identity()
  if not user:raise PermissionError('Sign in required.')
  if not any(d['id']==ident for d in view_state(user)['devices']):raise PermissionError('Device is unavailable or outside your company access.')
 def body(self):
  try:n=int(self.headers.get('Content-Length','0'))
  except ValueError:raise ValueError('Invalid request size.')
  if not 0<n<=2_000_000:raise ValueError('Invalid request size.')
  try:data=json.loads(self.rfile.read(n))
  except (ValueError,UnicodeError):raise ValueError('Invalid JSON request.')
  if not isinstance(data,dict):raise ValueError('Expected a JSON object.')
  if urlparse(self.path).path.startswith('/api/') and 'id' in data:self.device_access(data['id'])
  return data
 def do_GET(self):
  path=urlparse(self.path).path
  if path.startswith('/api/push/'):return self.push_heartbeat(path.split('/')[-1])
  if path.startswith('/badge/'):
   parts=path.split('/')
   page=public_status(parts[2]) if len(parts)==4 else None
   device=next((d for d in page['devices'] if str(d['id'])==parts[3].removesuffix('.svg')),None) if page else None
   if not device:return self.reply(404,'Badge not found.',kind='text/plain')
   color='#25996b' if device['status'] in ('Online','Warning') else '#c94e5e' if device['status']=='Offline' else '#77839a'
   svg='<svg xmlns="http://www.w3.org/2000/svg" width="180" height="24" role="img" aria-label="'+html.escape(device['status'],quote=True)+'"><rect width="180" height="24" rx="4" fill="'+color+'"/><text x="90" y="16" text-anchor="middle" fill="white" font-family="sans-serif" font-size="12">'+html.escape(device['status'])+'</text></svg>'
   return self.reply(200,svg,kind='image/svg+xml')
  if path=='/':
   host=urlsplit('http://'+self.headers.get('Host','')).hostname or ''
   with connect() as c:mapped=c.execute("SELECT slug FROM status_pages WHERE domain<>'' AND lower(domain)=?",(host.lower(),)).fetchone()
   if mapped:return self.reply(200,status_html(public_status(mapped['slug'])),kind='text/html; charset=utf-8')
  if path.startswith('/api/status/'):
   page=public_status(path.split('/')[-1]);return self.reply(200 if page else 404,page or {'error':'Status page not found.'})
  if path.startswith('/status/'):
   page=public_status(path.split('/')[-1])
   if not page:return self.reply(404,'Status page not found.',kind='text/plain')
   return self.reply(200,status_html(page),kind='text/html; charset=utf-8')
  if path=='/login':return self.reply(200,(ROOT/'dist/login.html').read_bytes(),kind='text/html; charset=utf-8')
  if path=='/health':return self.reply(200,{'status':'ok','version':'1.2','revision':(ROOT/'REVISION').read_text().strip() if (ROOT/'REVISION').exists() else 'development'})
  if path=='/api/agent/jobs':return self.agent_jobs()
  if path=='/agent.py':return self.reply(200,(ROOT/'agent.py').read_bytes(),kind='text/plain; charset=utf-8')
  if not self.session():return self.reply(401,{'error':'Sign in required.'}) if path.startswith('/api/') else self.reply(303,headers={'Location':'/login'})
  if path in ('/','/index.html'):return self.reply(200,(ROOT/'dist/index.html').read_bytes(),kind='text/html; charset=utf-8')
  if path=='/monitors.js':return self.reply(200,(ROOT/'dist/monitors.js').read_bytes(),kind='text/javascript; charset=utf-8')
  if path=='/app.js':return self.reply(200,(ROOT/'dist/app.js').read_bytes(),kind='text/javascript; charset=utf-8')
  if path=='/api/metrics':
   state=view_state(self.identity());lines=['# TYPE bitwise_device_up gauge']
   for d in state['devices']:
    label=json.dumps(''.join(ch if ord(ch)>=32 else ' ' for ch in d['name']),ensure_ascii=False);lines.append('bitwise_device_up{id="'+str(d['id'])+'",name='+label+'} '+str(1 if d['status'] in ('Online','Warning') else 0))
   return self.reply(200,'\n'.join(lines)+'\n',kind='text/plain; version=0.0.4')
  if path=='/api/status-pages':
   if self.identity()['role']!='admin':return self.reply(403,{'error':'Administrator access required.'})
   with connect() as c:pages=[{**dict(row),'devices':json.loads(row['devices'])} for row in c.execute('SELECT * FROM status_pages')]
   return self.reply(200,pages)
  if path=='/api/state':return self.reply(200,view_state(self.identity()))
  if path=='/api/users':
   if self.identity()['role']!='admin':return self.reply(403,{'error':'Administrator access required.'})
   with connect() as c:rows=[{**dict(r),'companies':json.loads(r['companies'])} for r in c.execute('SELECT username,role,companies,enabled FROM users ORDER BY username')]
   return self.reply(200,rows)
  if path.startswith('/api/jobs/'):
   if self.identity()['role']=='viewer':return self.reply(403,{'error':'Operator or administrator access required.'})
   try:ident=int(path.rsplit('/',1)[1])
   except ValueError:return self.reply(400,{'error':'Invalid device ID.'})
   try:self.device_access(ident)
   except PermissionError as e:return self.reply(403,{'error':str(e)})
   with connect() as c:rows=[{**dict(r),'result':json.loads(r['result']) if r['result'] else None} for r in c.execute('SELECT id,action,status,created,updated,result FROM jobs WHERE device=? ORDER BY id DESC LIMIT 20',(ident,))]
   return self.reply(200,rows)
  if path.startswith('/api/history/'):
   try:ident=int(path.rsplit('/',1)[1])
   except ValueError:return self.reply(400,{'error':'Invalid device ID.'})
   try:self.device_access(ident)
   except PermissionError as e:return self.reply(403,{'error':str(e)})
   with connect() as c:rows=[{'time':r['time'],**json.loads(r['data'])} for r in c.execute('SELECT time,data FROM samples WHERE device=? ORDER BY time DESC LIMIT 100',(ident,))]
   return self.reply(200,rows)
  if path=='/api/backup':
   if self.identity()['role']!='admin':return self.reply(403,{'error':'Administrator access required.'})
   return self.reply(200,view_state(),{'Content-Disposition':'attachment; filename="bitwise-inventory.json"'})
  self.reply(404,{'error':'Not found.'})
 def do_PUT(self):self.mutate()
 def do_POST(self):self.mutate()
 def mutate(self):
  try:
   identity=self.identity();AUDIT_CONTEXT.user=identity['username'] if identity else ('agent' if self.headers.get('Authorization','').startswith('Bearer ') else 'anonymous')
   self.action()
  except PermissionError as e:self.reply(403,{'error':str(e)})
  except ValueError as e:self.reply(400,{'error':str(e)})
  except adapters.AdapterError as e:self.reply(502,{'error':str(e)})
  except RuntimeError as e:self.reply(409,{'error':str(e)})
  except Exception as e:
   print('Request error:',type(e).__name__,str(e),flush=True);self.reply(500,{'error':'Server error. Check service logs.'})
 def action(self):
  path=urlparse(self.path).path
  if path.startswith('/api/push/'):return self.push_heartbeat(path.split('/')[-1])
  if path=='/api/agent/report':return self.report()
  if path=='/api/agent/result':return self.agent_result()
  origin=self.headers.get('Origin')
  # Browsers must make mutations from this application's own origin.
  if self.headers.get('Sec-Fetch-Site')=='cross-site' or (origin and origin not in ('http://'+self.headers.get('Host',''),'https://'+self.headers.get('Host',''))):return self.reply(403,{'error':'Request origin rejected.'})
  if path=='/login':return self.login()
  if not self.session():return self.reply(401,{'error':'Sign in required.'})
  if path=='/logout':
   token=self.session()
   with LOCK:SESSIONS.pop(token,None)
   return self.reply(204,headers={'Set-Cookie':'bitwise_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'})
  user=self.identity()
  if path.startswith('/api/') and path!='/api/password':
   if user['role']=='viewer':raise PermissionError('Read-only account. Operator or administrator access required.')
   if path in ('/api/monitors','/api/monitor-control','/api/status-pages','/api/users','/api/monitoring','/api/monitoring/test','/api/integration','/api/enroll','/api/discover') and user['role']!='admin':raise PermissionError('Administrator access required.')
  if path=='/api/state' and self.command=='PUT':return self.reply(200,update_inventory(self.body(),user))
  if path=='/api/monitors':
   body=self.body();ident=body.get('id');incoming=body.get('config')
   if not isinstance(incoming,dict):raise ValueError('Provide monitor settings.')
   with LOCK,connect() as c:
    c.execute('BEGIN IMMEDIATE');state,_=load(c);old=c.execute('SELECT config FROM connections WHERE device=?',(ident,)).fetchone() if ident else None
    if old:
     saved=json.loads(old['config'])
     if saved.get('kind')!='service':raise ValueError('This device is not a service monitor.')
     for key in service_checks.PRIVATE:
      if not incoming.get(key) and saved.get(key):incoming[key]=saved[key]
    config=service_checks.validate(incoming);name=text(body.get('name'));company=text(body.get('company'))
    if company not in state['companies']:raise ValueError('Select an existing company.')
    if ident and not any(d['id']==ident for d in state['devices']):raise ValueError('Monitor not found.')
    ident=ident or int(time.time()*1000)
    if not body.get('id') and any(d['id']==ident for d in state['devices']):ident+=1
    endpoint=urlsplit(config.get('endpoint',''));host=endpoint.hostname or config.get('host') or 'push';check_port=endpoint.port or (443 if endpoint.scheme in ('https','wss') else 80) if endpoint.hostname else config.get('port',443)
    device={'id':ident,'name':name,'company':company,'type':'Service','ip':host,'platform':config['monitorType'].upper()+' monitor','port':check_port,'maintenanceUntil':0}
    if body.get('id'):
     existing=next(d for d in state['devices'] if d['id']==ident);device['maintenanceUntil']=existing.get('maintenanceUntil',0);state['devices']=[device if d['id']==ident else d for d in state['devices']]
    else:state['devices'].append(device)
    store(c,validate(state));c.execute('INSERT INTO connections(device,config) VALUES(?,?) ON CONFLICT(device) DO UPDATE SET config=excluded.config,last_attempt=0,last_error=NULL,failures=0',(ident,json.dumps(config)))
    c.execute('DELETE FROM tokens WHERE device=?',(ident,));audit(c,'Service monitor saved',name)
    token=None
    if config['monitorType']=='push' and not c.execute('SELECT 1 FROM push_tokens WHERE device=?',(ident,)).fetchone():
     token=secrets.token_urlsafe(32);c.execute('INSERT INTO push_tokens VALUES(?,?)',(ident,hashlib.sha256(token.encode()).hexdigest()))
    if config['monitorType']!='push':c.execute('DELETE FROM push_tokens WHERE device=?',(ident,))
   incidents();return self.reply(200,{'id':ident,'pushToken':token})
  if path=='/api/monitor-control':
   body=self.body();ident=body.get('id');action=body.get('action');token=None
   with LOCK,connect() as c:
    row=c.execute('SELECT config FROM connections WHERE device=?',(ident,)).fetchone()
    if not row:raise ValueError('Monitor not found.')
    config=json.loads(row['config'])
    if config.get('kind')!='service':raise ValueError('Select a service monitor.')
    if action in ('pause','resume'):
     config['paused']=action=='pause';c.execute('UPDATE connections SET config=?,last_attempt=0 WHERE device=?',(json.dumps(config),ident))
    elif action=='clone':
     state,_=load(c);original=next(d for d in state['devices'] if d['id']==ident);newid=int(time.time()*1000)
     while any(d['id']==newid for d in state['devices']):newid+=1
     copy={**original,'id':newid,'name':(original['name'][:120]+' copy'),'maintenanceUntil':0};state['devices'].append(copy);store(c,validate(state));c.execute('INSERT INTO connections(device,config) VALUES(?,?)',(newid,json.dumps(config)))
     if config['monitorType']=='push':
      token=secrets.token_urlsafe(32);c.execute('INSERT INTO push_tokens VALUES(?,?)',(newid,hashlib.sha256(token.encode()).hexdigest()))
    elif action=='rotate-push' and config['monitorType']=='push':
     token=secrets.token_urlsafe(32);c.execute('INSERT INTO push_tokens VALUES(?,?) ON CONFLICT(device) DO UPDATE SET digest=excluded.digest',(ident,hashlib.sha256(token.encode()).hexdigest()))
    else:raise ValueError('Unsupported monitor operation.')
    audit(c,'Monitor '+action,ident)
   incidents();return self.reply(200,{'ok':True,'pushToken':token})
  if path=='/api/status-pages':
   body=self.body();slug=body.get('slug','')
   if not isinstance(slug,str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}',slug):raise ValueError('Use a lowercase status-page slug.')
   if body.get('delete'):
    with LOCK,connect() as c:c.execute('DELETE FROM status_pages WHERE slug=?',(slug,));audit(c,'Status page removed',slug)
    return self.reply(200,{'ok':True})
   with LOCK,connect() as c:
    title=text(body.get('title'));ids=body.get('devices');domain=body.get('domain','');description=body.get('description','')
    if not isinstance(domain,str):raise ValueError('Invalid status page domain.')
    domain=domain.strip().lower()
    if domain and not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?',domain):raise ValueError('Enter a hostname without scheme or port.')
    if not isinstance(description,str) or len(description)>2048:raise ValueError('Description must be at most 2048 characters.')
    if domain and c.execute('SELECT 1 FROM status_pages WHERE domain=? AND slug<>?',(domain,slug)).fetchone():raise ValueError('Domain is already assigned to another status page.')
    state,_=load(c);valid={d['id'] for d in state['devices']}
    if not isinstance(ids,list) or len(ids)>500 or any(type(i)!=int or i not in valid for i in ids):raise ValueError('Select existing devices to publish.')
    c.execute('INSERT INTO status_pages(slug,title,devices,domain,description) VALUES(?,?,?,?,?) ON CONFLICT(slug) DO UPDATE SET title=excluded.title,devices=excluded.devices,domain=excluded.domain,description=excluded.description',(slug,title,json.dumps(list(dict.fromkeys(ids))),domain,description));audit(c,'Status page published',slug)
   return self.reply(200,{'ok':True,'url':'/status/'+slug})
  if path=='/api/users':
   body=self.body();username=body.get('username','');role=body.get('role','viewer');companies=body.get('companies',[]);enabled=body.get('enabled',True);password=body.get('password','')
   if not isinstance(username,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{3,64}',username):raise ValueError('Use 3–64 letters, numbers, dots, underscores, or hyphens for usernames.')
   if username==json.loads(AUTH.read_text())['username']:raise ValueError('The primary administrator is managed through Change password.')
   if username==user['username']:raise ValueError('Use another administrator to change your own role or access.')
   if role not in ('admin','operator','viewer') or type(enabled)!=bool:raise ValueError('Invalid account role or status.')
   if not isinstance(companies,list) or any(c not in view_state()['companies'] for c in companies):raise ValueError('Choose existing companies.')
   with LOCK,connect() as c:
    old=c.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
    if not old and not password:raise ValueError('A password is required for a new user.')
    if password:
     if not isinstance(password,str) or not 12<=len(password)<=1024:raise ValueError('Use a password between 12 and 1024 characters.')
     salt=secrets.token_bytes(16).hex();hashed=digest(password,bytes.fromhex(salt))
    else:salt=old['salt'];hashed=old['hash']
    c.execute('INSERT INTO users VALUES(?,?,?,?,?,?) ON CONFLICT(username) DO UPDATE SET salt=excluded.salt,hash=excluded.hash,role=excluded.role,companies=excluded.companies,enabled=excluded.enabled',(username,salt,hashed,role,json.dumps(companies),int(enabled)));audit(c,'User access updated: '+username)
    for token,session in list(SESSIONS.items()):
     if session['username']==username:SESSIONS.pop(token,None)
   return self.reply(200,{'ok':True})
  if path=='/api/monitoring/test':
   body=self.body()
   with connect() as c:previous=get_settings(c)
   config=notifications.validate(body,previous)['delivery'];channels=notifications.channels(config)
   if not channels:raise ValueError('Choose a notification channel before testing.')
   results=[]
   for channel in channels:
    status='sent';message='Accepted by the delivery service. Check the destination, including email spam folders.'
    try:notifications.send({**config,'mode':channel},'Bitwise Control test notification','This is a test notification from Bitwise Control. Your notification connection is working.')
    except Exception:
     status='failed';message='Delivery failed. Check '+('SMTP server, port, credentials, and sender permissions.' if channel=='email' else 'the webhook URL, destination permissions, and server network access.')
    with LOCK,connect() as c:
     c.execute('INSERT INTO outbox(subject,message,status,attempts,created,channel) VALUES(?,?,?,?,?,?)',('Bitwise Control test notification','Administrator-requested delivery test.',status,1,time.time(),channel))
     audit(c,'Test notification '+status+': '+channel)
    results.append({'channel':channel,'status':status,'message':message})
   return self.reply(200,{'results':results})
  if path=='/api/monitoring':
   body=self.body()
   with LOCK,connect() as c:
    previous=get_settings(c);settings=notifications.validate(body,previous)
    if settings['delivery'].get('summaryMinutes',0)!=previous['delivery'].get('summaryMinutes',0):c.execute("INSERT INTO settings VALUES('summary_last_queued',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(str(time.time()),))
    if settings['delivery']!=previous['delivery']:c.execute("UPDATE outbox SET status='cancelled' WHERE status='pending'")
    c.execute("INSERT INTO settings VALUES('monitoring',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(json.dumps(settings),));audit(c,'Monitoring rules and delivery settings updated')
   incidents();return self.reply(200,notifications.public(settings))
  if path=='/api/integration':
   body=self.body();ident=body.get('id');config=body.get('config')
   if not any(d['id']==ident for d in view_state()['devices']):raise ValueError('Device not found.')
   with LOCK,connect() as c:
    if config is None:
     c.execute('DELETE FROM connections WHERE device=?',(ident,));audit(c,'Device connection removed',ident)
     return self.reply(200,{'ok':True})
    if not isinstance(config,dict):raise ValueError('Invalid connection settings.')
    old=c.execute('SELECT config FROM connections WHERE device=?',(ident,)).fetchone()
    if old:
     old=json.loads(old['config'])
     if old.get('kind')==config.get('kind'):
      for key in adapters.SECRETS:
       if not config.get(key) and old.get(key):config[key]=old[key]
    config=adapters.validate(config)
    c.execute('INSERT INTO connections(device,config) VALUES(?,?) ON CONFLICT(device) DO UPDATE SET config=excluded.config,last_attempt=0,last_error=NULL',(ident,json.dumps(config)))
    c.execute('DELETE FROM tokens WHERE device=?',(ident,));audit(c,'Device connection configured: '+config['kind'],ident)
   return self.reply(200,{'ok':True})
  if path=='/api/poll':
   ident=self.body().get('id')
   with LOCK:
    if ident in POLLING:raise RuntimeError('A device poll is already in progress.')
    POLLING.add(ident)
   poll_device(ident);incidents();return self.reply(200,view_state(user))
  if path=='/api/discover':
   body=self.body();ident=body.get('id');incoming=body.get('config')
   with connect() as c:row=c.execute('SELECT config FROM connections WHERE device=?',(ident,)).fetchone()
   if incoming is not None:
    if not isinstance(incoming,dict):raise ValueError('Invalid connection settings.')
    config=dict(incoming)
    if row:
     old=json.loads(row['config'])
     if old['kind']==config.get('kind'):
      for key in adapters.SECRETS:
       if not config.get(key):config[key]=old.get(key,'')
    if config.get('kind')=='proxmox':config.setdefault('node','discovery');config['node']=config['node'] or 'discovery';config['target']='node'
    if config.get('kind')=='unifi':config['siteId']=config.get('siteId') or 'discovery';config['deviceId']=config.get('deviceId') or 'discovery'
    config=adapters.validate(config)
   elif row:config=json.loads(row['config'])
   else:raise ValueError('Enter connection credentials first.')
   kind=config['kind']
   if kind=='proxmox':result=adapters.pve_discover(config)
   elif kind=='mikrotik':result=adapters.mt(config,'/interface')
   elif kind=='unifi':result=adapters.ui(config,'/sites?limit=200' if body.get('scope')=='sites' else '/sites/'+adapters.safe_part(config['siteId'])+'/devices?limit=200')
   else:raise ValueError('Discovery is available for Proxmox, MikroTik, and UniFi.')
   return self.reply(200,result)
  if path=='/api/action':
   body=self.body();ident=body.get('id');name=body.get('action');args=body.get('arguments',{})
   if name not in ('reboot','shutdown','start','upgrade_check','upgrade','config_backup','configure','poe','poe_cycle') or not isinstance(args,dict):raise ValueError('Unsupported device action.')
   with LOCK,connect() as c:
    connection=c.execute('SELECT config FROM connections WHERE device=?',(ident,)).fetchone()
    token=c.execute('SELECT device FROM tokens WHERE device=?',(ident,)).fetchone()
    if not connection and token:
     if name not in ('reboot','upgrade_check'):raise ValueError('The Linux agent supports reboot and update checks only.')
     cur=c.execute('INSERT INTO jobs(device,action,arguments,status,created,updated) VALUES(?,?,?,?,?,?)',(ident,name,'{}','queued',time.time(),time.time()));audit(c,'Queued '+name,ident)
     return self.reply(200,{'job':cur.lastrowid,'status':'queued'})
   return self.reply(200,run_action(ident,name,args))
  if path=='/api/password':
   body=self.body();root=json.loads(AUTH.read_text())
   if user['username']==root['username']:config=root
   else:
    with connect() as c:config=dict(c.execute('SELECT * FROM users WHERE username=?',(user['username'],)).fetchone())
   if not verify(body.get('current',''),config):return self.reply(403,{'error':'Current password is incorrect.'})
   password=body.get('password','')
   if not isinstance(password,str) or not 12<=len(password)<=1024:raise ValueError('Use a password between 12 and 1024 characters.')
   salt=secrets.token_bytes(16);config.update(salt=salt.hex(),hash=digest(password,salt))
   if user['username']==root['username']:
    tmp=AUTH.with_suffix('.tmp');tmp.write_text(json.dumps(config));tmp.chmod(0o600);tmp.replace(AUTH)
   else:
    with LOCK,connect() as c:c.execute('UPDATE users SET salt=?,hash=? WHERE username=?',(config['salt'],config['hash'],user['username']))
   token=self.session()
   with LOCK:
    for key,session in list(SESSIONS.items()):
     if session['username']==user['username'] and key!=token:SESSIONS.pop(key,None)
   with connect() as c:audit(c,'Password changed: '+user['username'])
   return self.reply(200,{'ok':True})
  if path=='/api/enroll':
   body=self.body();ident=body.get('id');state=view_state()
   if not any(d['id']==ident for d in state['devices']):raise ValueError('Select an existing device.')
   token=secrets.token_urlsafe(32)
   with LOCK,connect() as c:
    c.execute('DELETE FROM connections WHERE device=?',(ident,))
    c.execute('INSERT INTO tokens VALUES(?,?) ON CONFLICT(device) DO UPDATE SET digest=excluded.digest',(ident,hashlib.sha256(token.encode()).hexdigest()));audit(c,'Agent token generated',ident)
   return self.reply(200,{'device':ident,'token':token})
  if path=='/api/check':
   ident=self.body().get('id');device=next((d for d in view_state()['devices'] if d['id']==ident),None)
   if not device:raise ValueError('Device not found.')
   start=time.monotonic()
   try:
    with socket.create_connection((device['ip'],device['port']),timeout=3):pass
    result={'reachable':True,'latencyMs':round((time.monotonic()-start)*1000,1),'port':device['port']}
   except OSError:result={'reachable':False,'port':device['port'],'message':'Connection refused or timed out.'}
   with connect() as c:audit(c,'Connection check: '+('reachable' if result['reachable'] else 'unreachable'),device['name'])
   return self.reply(200,result)
  self.reply(404,{'error':'Not found.'})
 def agent_device(self):
  token=self.headers.get('Authorization','')
  if not token.startswith('Bearer '):return None
  hashed=hashlib.sha256(token[7:].encode()).hexdigest()
  with connect() as c:row=c.execute('SELECT device FROM tokens WHERE digest=?',(hashed,)).fetchone()
  return row['device'] if row else None
 def agent_jobs(self):
  ident=self.agent_device()
  if ident is None:return self.reply(401,{'error':'Agent authentication required.'})
  with LOCK,connect() as c:
   # Expire reboot requests rather than execute a stale reboot after a long outage.
   c.execute("UPDATE jobs SET status='expired',updated=? WHERE device=? AND status='queued' AND created<?",(time.time(),ident,time.time()-600))
   rows=[dict(r) for r in c.execute("SELECT id,action FROM jobs WHERE device=? AND status='queued' ORDER BY id LIMIT 1",(ident,))]
   for row in rows:c.execute("UPDATE jobs SET status='running',updated=? WHERE id=?",(time.time(),row['id']))
  self.reply(200,rows)
 def agent_result(self):
  ident=self.agent_device()
  if ident is None:return self.reply(401,{'error':'Agent authentication required.'})
  body=self.body();status=body.get('status');result=body.get('result','')
  if status not in ('completed','failed','accepted') or not isinstance(result,str) or len(result)>32000:raise ValueError('Invalid command result.')
  with LOCK,connect() as c:
   row=c.execute("SELECT action FROM jobs WHERE id=? AND device=? AND status='running'",(body.get('job'),ident)).fetchone()
   if not row:raise ValueError('No active command found.')
   c.execute('UPDATE jobs SET status=?,updated=?,result=? WHERE id=?',(status,time.time(),json.dumps({'message':result}),body['job']));audit(c,row['action']+' '+status,ident)
  self.reply(200,{'ok':True})
 def report(self):
  token=self.headers.get('Authorization','')
  if not token.startswith('Bearer '):return self.reply(401,{'error':'Agent authentication required.'})
  hashed=hashlib.sha256(token[7:].encode()).hexdigest()
  with connect() as c:row=c.execute('SELECT device FROM tokens WHERE digest=?',(hashed,)).fetchone()
  if not row:return self.reply(401,{'error':'Invalid agent token.'})
  body=self.body();data={}
  for key in ('cpu','memory','disk'):
   value=body.get(key)
   if value is not None and (type(value) not in (int,float) or not math.isfinite(value) or not 0<=value<=100):raise ValueError('Invalid '+key+' measurement.')
   data[key]=value
  uptime=body.get('uptimeSeconds',0)
  if type(uptime) not in (int,float) or not math.isfinite(uptime) or uptime<0:raise ValueError('Invalid uptime.')
  data['uptimeSeconds']=uptime;data['hostname']=text(body.get('hostname','unknown'));data['source']='Linux agent'
  record(row['device'],data);incidents();self.reply(200,{'ok':True})
 def login(self):
  ip=self.client_address[0];now=time.time()
  with LOCK:
   for key in list(ATTEMPTS):
    ATTEMPTS[key]=[x for x in ATTEMPTS[key] if now-x<900]
    if not ATTEMPTS[key]:ATTEMPTS.pop(key,None)
   attempts=ATTEMPTS.setdefault(ip,[])
   if len(attempts)>=10:return self.reply(429,{'error':'Too many attempts. Try again in 15 minutes.'})
   attempts.append(now)
  body=self.body();root=json.loads(AUTH.read_text());username=str(body.get('username',''))
  with connect() as c:row=c.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
  config=dict(row) if row else root
  valid=verify(body.get('password',''),config)
  if not (hmac.compare_digest(username,config['username']) and valid and (not row or row['enabled'])):return self.reply(401,{'error':'Username or password is incorrect.'})
  token=secrets.token_urlsafe(32)
  with LOCK:
   for key,expiry in list(SESSIONS.items()):
    if expiry['expires']<=now:SESSIONS.pop(key,None)
   SESSIONS[token]={'expires':now+28800,'username':username};ATTEMPTS.pop(ip,None)
  AUDIT_CONTEXT.user=username
  with connect() as c:audit(c,'User signed in: '+username)
  self.reply(200,{'ok':True},headers={'Set-Cookie':f'bitwise_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800'+('; Secure' if isinstance(self.connection,ssl.SSLSocket) else '')})

def digest(password,salt):return hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1).hex()
def verify(password,config):
 if not isinstance(password,str) or len(password)>1024:return False
 return hmac.compare_digest(digest(password,bytes.fromhex(config['salt'])),config['hash'])

if __name__=='__main__':
 init();threading.Thread(target=monitor,daemon=True).start()
 server=ThreadingHTTPServer((os.environ.get('BITWISE_BIND','0.0.0.0'),int(os.environ.get('BITWISE_PORT','8080'))),Handler)
 if os.environ.get('BITWISE_TLS_CERT') and os.environ.get('BITWISE_TLS_KEY'):
  context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(os.environ['BITWISE_TLS_CERT'],os.environ['BITWISE_TLS_KEY']);server.socket=context.wrap_socket(server.socket,server_side=True)
 server.serve_forever()
