"""Bitwise Control: authenticated inventory and Linux agent monitoring."""
import hashlib,hmac,json,math,os,secrets,socket,sqlite3,threading,time
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
  CREATE TABLE IF NOT EXISTS inventory(id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, data TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS samples(id INTEGER PRIMARY KEY, device INTEGER NOT NULL, time REAL NOT NULL, data TEXT NOT NULL);
  CREATE INDEX IF NOT EXISTS samples_device_time ON samples(device,time);
  CREATE TABLE IF NOT EXISTS tokens(device INTEGER PRIMARY KEY, digest TEXT NOT NULL);
  CREATE UNIQUE INDEX IF NOT EXISTS tokens_digest ON tokens(digest);
  CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, time REAL NOT NULL, action TEXT NOT NULL, device TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS incidents(device INTEGER PRIMARY KEY, opened REAL NOT NULL, message TEXT NOT NULL);
  ''')
  c.execute('INSERT OR IGNORE INTO inventory VALUES(1,0,?)',(json.dumps({'companies':[],'devices':[],'rules':[],'channels':{}}),))

def audit(c,action,device=''):
 c.execute('INSERT INTO audit(time,action,device) VALUES(?,?,?)',(time.time(),action,str(device)))

def load(c):
 row=c.execute('SELECT * FROM inventory WHERE id=1').fetchone();return json.loads(row['data']),row['revision']

def store(c,state):
 c.execute('UPDATE inventory SET data=?,revision=revision+1 WHERE id=1',(json.dumps(state,allow_nan=False),))

def view_state():
 with LOCK,connect() as c:
  state,rev=load(c)
  for d in state['devices']:
   sample=c.execute('SELECT time,data FROM samples WHERE device=? ORDER BY time DESC LIMIT 1',(d['id'],)).fetchone()
   d.update(cpu=None,memory=None,temp=None,uptime=0,disk=None,lastSeen=None,status='Pending',poe=[])
   if sample:
    data=json.loads(sample['data']);d.update(data);d['lastSeen']=sample['time'];d['status']='Online' if time.time()-sample['time']<180 else 'Offline'
   if d['status']=='Online' and any((d.get(k) or 0)>90 for k in ('cpu','memory','disk')):d['status']='Warning'
  state['logs']=[{'time':time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(r['time'])),'action':r['action'],'device':r['device'],'company':''} for r in c.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 500')]
  state['incidents']=[dict(r) for r in c.execute('SELECT * FROM incidents ORDER BY opened DESC')]
  state['revision']=rev;state['serverTime']=time.time();return state

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
  output.append({'id':ident,'name':text(d.get('name')),'company':company,'type':text(d.get('type')),'ip':address,'platform':text(d.get('platform')),'port':port})
 return {'companies':companies,'devices':output,'rules':[],'channels':{}}

def update_inventory(body):
 state=validate(body)
 with LOCK,connect() as c:
  old,rev=load(c)
  if body.get('revision')!=rev:raise RuntimeError('Inventory changed in another window. Refresh and try again.')
  oldids={d['id'] for d in old['devices']};newids={d['id'] for d in state['devices']}
  for ident in oldids-newids:
   c.execute('DELETE FROM samples WHERE device=?',(ident,));c.execute('DELETE FROM tokens WHERE device=?',(ident,));c.execute('DELETE FROM incidents WHERE device=?',(ident,))
  if old!=state:audit(c,'Inventory updated',f"{len(state['companies'])} companies, {len(state['devices'])} devices")
  store(c,state)
 return view_state()

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
   message='Agent stopped reporting' if d['status']=='Offline' else ('Resource usage above 90%' if d['status']=='Warning' else None)
   old=c.execute('SELECT message FROM incidents WHERE device=?',(d['id'],)).fetchone()
   if message:
    c.execute('INSERT INTO incidents VALUES(?,?,?) ON CONFLICT(device) DO UPDATE SET message=excluded.message',(d['id'],now,message))
    if not old:audit(c,'Alert opened: '+message,d['name'])
   elif old:
    c.execute('DELETE FROM incidents WHERE device=?',(d['id'],));audit(c,'Alert recovered',d['name'])

def monitor():
 while not STOP.wait(30):
  try:incidents()
  except Exception as e:print('Monitor error:',e,flush=True)

class Handler(BaseHTTPRequestHandler):
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
   if SESSIONS.get(token,0)>time.time():return token
   SESSIONS.pop(token,None)
 def body(self):
  try:n=int(self.headers.get('Content-Length','0'))
  except ValueError:raise ValueError('Invalid request size.')
  if not 0<n<=2_000_000:raise ValueError('Invalid request size.')
  try:return json.loads(self.rfile.read(n))
  except (ValueError,UnicodeError):raise ValueError('Invalid JSON request.')
 def do_GET(self):
  path=urlparse(self.path).path
  if path=='/login':return self.reply(200,(ROOT/'dist/login.html').read_bytes(),kind='text/html; charset=utf-8')
  if path=='/health':return self.reply(200,{'status':'ok','version':'1.0'})
  if path=='/agent.py':return self.reply(200,(ROOT/'agent.py').read_bytes(),kind='text/plain; charset=utf-8')
  if not self.session():return self.reply(401,{'error':'Sign in required.'}) if path.startswith('/api/') else self.reply(303,headers={'Location':'/login'})
  if path in ('/','/index.html'):return self.reply(200,(ROOT/'dist/index.html').read_bytes(),kind='text/html; charset=utf-8')
  if path=='/app.js':return self.reply(200,(ROOT/'dist/app.js').read_bytes(),kind='text/javascript; charset=utf-8')
  if path=='/api/state':return self.reply(200,view_state())
  if path.startswith('/api/history/'):
   try:ident=int(path.rsplit('/',1)[1])
   except ValueError:return self.reply(400,{'error':'Invalid device ID.'})
   with connect() as c:rows=[{'time':r['time'],**json.loads(r['data'])} for r in c.execute('SELECT time,data FROM samples WHERE device=? ORDER BY time DESC LIMIT 100',(ident,))]
   return self.reply(200,rows)
  if path=='/api/backup':return self.reply(200,view_state(),{'Content-Disposition':'attachment; filename="bitwise-inventory.json"'})
  self.reply(404,{'error':'Not found.'})
 def do_PUT(self):self.mutate()
 def do_POST(self):self.mutate()
 def mutate(self):
  try:self.action()
  except ValueError as e:self.reply(400,{'error':str(e)})
  except RuntimeError as e:self.reply(409,{'error':str(e)})
  except Exception as e:
   print('Request error:',type(e).__name__,str(e),flush=True);self.reply(500,{'error':'Server error. Check service logs.'})
 def action(self):
  path=urlparse(self.path).path
  if path=='/api/agent/report':return self.report()
  origin=self.headers.get('Origin')
  # Browsers must make mutations from this application's own origin.
  if self.headers.get('Sec-Fetch-Site')=='cross-site' or (origin and origin not in ('http://'+self.headers.get('Host',''),'https://'+self.headers.get('Host',''))):return self.reply(403,{'error':'Request origin rejected.'})
  if path=='/login':return self.login()
  if not self.session():return self.reply(401,{'error':'Sign in required.'})
  if path=='/logout':
   token=self.session()
   with LOCK:SESSIONS.pop(token,None)
   return self.reply(204,headers={'Set-Cookie':'bitwise_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'})
  if path=='/api/state' and self.command=='PUT':return self.reply(200,update_inventory(self.body()))
  if path=='/api/password':
   body=self.body();config=json.loads(AUTH.read_text())
   if not verify(body.get('current',''),config):return self.reply(403,{'error':'Current password is incorrect.'})
   password=body.get('password','')
   if not isinstance(password,str) or not 12<=len(password)<=1024:raise ValueError('Use a password between 12 and 1024 characters.')
   salt=secrets.token_bytes(16);config.update(salt=salt.hex(),hash=digest(password,salt))
   tmp=AUTH.with_suffix('.tmp');tmp.write_text(json.dumps(config));tmp.chmod(0o600);tmp.replace(AUTH)
   token=self.session()
   with LOCK:SESSIONS.clear();SESSIONS[token]=time.time()+28800
   with connect() as c:audit(c,'Administrator password changed')
   return self.reply(200,{'ok':True})
  if path=='/api/enroll':
   body=self.body();ident=body.get('id');state=view_state()
   if not any(d['id']==ident for d in state['devices']):raise ValueError('Select an existing device.')
   token=secrets.token_urlsafe(32)
   with LOCK,connect() as c:
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
  body=self.body();config=json.loads(AUTH.read_text())
  valid=verify(body.get('password',''),config)
  if not (hmac.compare_digest(str(body.get('username','')),config['username']) and valid):return self.reply(401,{'error':'Username or password is incorrect.'})
  token=secrets.token_urlsafe(32)
  with LOCK:
   for key,expiry in list(SESSIONS.items()):
    if expiry<=now:SESSIONS.pop(key,None)
   SESSIONS[token]=now+28800;ATTEMPTS.pop(ip,None)
  with connect() as c:audit(c,'Administrator signed in')
  self.reply(200,{'ok':True},headers={'Set-Cookie':f'bitwise_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800'})

def digest(password,salt):return hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1).hex()
def verify(password,config):
 if not isinstance(password,str) or len(password)>1024:return False
 return hmac.compare_digest(digest(password,bytes.fromhex(config['salt'])),config['hash'])

if __name__=='__main__':
 init();threading.Thread(target=monitor,daemon=True).start()
 ThreadingHTTPServer((os.environ.get('BITWISE_BIND','0.0.0.0'),int(os.environ.get('BITWISE_PORT','8080'))),Handler).serve_forever()
