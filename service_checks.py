"""Native service checks. No shell commands or simulated results."""
import base64,hashlib,json,math,re,secrets,socket,ssl,subprocess,time,struct,smtplib,imaplib,poplib
from urllib.parse import urlsplit,urlunsplit
from urllib.request import Request,build_opener,ProxyHandler,HTTPSHandler,HTTPRedirectHandler
from urllib.error import HTTPError
TYPES=('http','keyword','json','tcp','ping','dns','tls','websocket','docker','steam','push','ntp','redis','mqtt','smtp','imap','pop3')
PRIVATE={'endpoint','headersJson','requestBody','proxyUrl','password'}
class CheckError(Exception):pass
class NoRedirect(HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None

def validate(body):
 c={k:v for k,v in body.items() if k in {'kind','monitorType','endpoint','host','port','interval','timeout','retries','method','headersJson','requestBody','expectedCodes','keyword','invert','jsonPath','expectedValue','dnsType','dnsServer','certWarnDays','caPem','proxyUrl','paused','tags','group','notify','username','password','tlsMode'}}
 for key in ('monitorType','endpoint','host','method','headersJson','requestBody','expectedCodes','keyword','jsonPath','expectedValue','dnsType','dnsServer','caPem','proxyUrl','group','username','password','tlsMode'):
  if key in c and not isinstance(c[key],str):raise ValueError('Invalid monitor '+key+'.')
 c['kind']='service';kind=c.get('monitorType')
 if kind not in TYPES:raise ValueError('Choose a supported service monitor type.')
 for key,default,minimum,maximum in [('interval',60,20,86400),('timeout',10,1,30),('retries',2,0,10),('certWarnDays',14,0,365),('port',{'tls':443,'steam':27015,'dns':53,'ntp':123,'redis':6379,'mqtt':8883,'smtp':587,'imap':993,'pop3':995}.get(kind,80),1,65535)]:
  value=c.get(key,default)
  if type(value)!=int or not minimum<=value<=maximum:raise ValueError('Invalid monitor '+key+'.')
  c[key]=value
 if c['timeout']>=c['interval']:raise ValueError('Timeout must be shorter than the check interval.')
 for key,value in c.items():
  if isinstance(value,str) and (len(value)>16384 or '\x00' in value or (key not in ('caPem','headersJson','requestBody') and any(x in value for x in '\r\n'))):raise ValueError('Invalid monitor '+key+'.')
 for key in ('paused','invert','notify'):
  if type(c.get(key,key=='notify'))!=bool:raise ValueError('Invalid '+key+'.')
  c[key]=c.get(key,key=='notify')
 tags=c.get('tags',[])
 if not isinstance(tags,list) or len(tags)>20 or any(not isinstance(t,str) or not t.strip() or len(t)>40 for t in tags):raise ValueError('Use up to 20 tags of 40 characters.')
 c['tags']=list(dict.fromkeys(t.strip() for t in tags));c['group']=c.get('group','')
 if not isinstance(c['group'],str) or len(c['group'])>128:raise ValueError('Invalid monitor group.')
 if kind in ('http','keyword','json','websocket','docker'):
  endpoint=c.get('endpoint','');u=urlsplit(endpoint)
  schemes=('ws','wss') if kind=='websocket' else ('http','https')
  if u.scheme not in schemes or not u.hostname or u.username or u.password or u.fragment or any(x.isspace() for x in endpoint):raise ValueError('Enter a direct URL without embedded credentials, whitespace, or fragments.')
  try:u.port
  except ValueError:raise ValueError('Invalid endpoint port.')
  if kind=='docker' and u.scheme!='https':raise ValueError('Use a verified HTTPS Docker API endpoint.')
 else:
  if kind!='push' and (not isinstance(c.get('host'),str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,253}',c['host']) or c['host'].startswith('-')):raise ValueError('Enter a hostname or IP address.')
 method=c.get('method','GET')
 if method not in ('GET','HEAD','POST'):raise ValueError('Choose GET, HEAD, or POST.')
 c['method']=method
 if c.get('tlsMode','starttls' if kind=='smtp' else 'tls') not in ('tls','starttls','plain'):raise ValueError('Choose TLS, STARTTLS, or plain transport.')
 c['tlsMode']=c.get('tlsMode','starttls' if kind=='smtp' else 'tls')
 if kind in ('mqtt','redis') and c['tlsMode']=='starttls':raise ValueError('This monitor supports TLS or plain transport.')
 if c.get('password') and not c.get('username') and kind!='redis':raise ValueError('A username is required when a password is provided.')
 try:headers=json.loads(c.get('headersJson') or '{}')
 except ValueError:raise ValueError('Headers must be a JSON object.')
 if not isinstance(headers,dict) or len(headers)>30 or any(not isinstance(k,str) or not isinstance(v,str) or not re.fullmatch(r'[A-Za-z0-9-]+',k) or any(x in v for x in '\r\n') or k.lower() in ('host','content-length','connection','upgrade','sec-websocket-key','sec-websocket-version') for k,v in headers.items()):raise ValueError('Invalid custom headers.')
 codes=c.get('expectedCodes','200-299')
 if not isinstance(codes,str) or len(codes)>128 or any(not re.fullmatch(r'[1-5][0-9]{2}(?:-[1-5][0-9]{2})?',part.strip()) for part in codes.split(',')):raise ValueError('Use HTTP status codes such as 200-299,301.')
 for part in codes.split(','):
  values=list(map(int,part.strip().split('-')))
  if len(values)==2 and values[0]>values[1]:raise ValueError('Invalid status code range.')
 c['expectedCodes']=codes
 if kind=='keyword' and not c.get('keyword'):raise ValueError('Enter a keyword to check.')
 if kind=='json' and (not c.get('jsonPath') or not isinstance(c.get('expectedValue'),str)):raise ValueError('Enter a dot-separated JSON path and expected JSON value.')
 if kind=='json':
  if not re.fullmatch(r'[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*',c['jsonPath']):raise ValueError('Use a simple dot-separated JSON path (for example status.ready or items.0.id).')
  try:json.loads(c['expectedValue'])
  except ValueError:raise ValueError('Expected value must be valid JSON, for example true or "ok".')
 if c.get('dnsType','A') not in ('A','AAAA','CNAME','MX','TXT','NS','SOA','SRV','CAA','PTR'):raise ValueError('Unsupported DNS record type.')
 if c.get('dnsServer'):
  import ipaddress
  try:ipaddress.ip_address(c['dnsServer'])
  except ValueError:raise ValueError('DNS server must be an IP address.')
 if c.get('proxyUrl'):
  u=urlsplit(c['proxyUrl'])
  if u.scheme not in ('http','https') or not u.hostname or u.query or u.fragment or u.path not in ('','/'):raise ValueError('Enter an HTTP(S) proxy origin.')
  if kind not in ('http','keyword','json','docker'):raise ValueError('Proxy support is available for HTTP monitors only.')
 if c.get('caPem'):
  try:ssl.create_default_context(cadata=c['caPem'])
  except (ssl.SSLError,ValueError):raise ValueError('Invalid CA certificate.')
 return c

def public(c):
 result={k:v for k,v in c.items() if k not in PRIVATE}
 if c.get('endpoint'):
  u=urlsplit(c['endpoint']);result['displayEndpoint']=urlunsplit((u.scheme,u.netloc,u.path,'',''))
 return {**result,'credentialsConfigured':True}

def http_check(c):
 headers=json.loads(c.get('headersJson') or '{}');body=c.get('requestBody','').encode() if c.get('requestBody') and c['method']=='POST' else None
 request=Request(c['endpoint'],data=body,method=c['method'],headers={'User-Agent':'BitwiseControl-Monitor/1.0',**headers})
 proxy=ProxyHandler({'http':c['proxyUrl'],'https':c['proxyUrl']} if c.get('proxyUrl') else {})
 opener=build_opener(proxy,NoRedirect(),HTTPSHandler(context=ssl.create_default_context(cadata=c.get('caPem') or None)))
 try:response=opener.open(request,timeout=c['timeout'])
 except HTTPError as error:response=error
 with response:
  code=response.status;raw=response.read(2_000_001)
  if len(raw)>2_000_000:raise CheckError('Response exceeds the 2 MB check limit.')
 good=False
 for part in c['expectedCodes'].split(','):
  values=list(map(int,part.strip().split('-')));good|=(values[0]<=code<=values[-1])
 if not good:raise CheckError('Unexpected HTTP status '+str(code)+'.')
 kind=c['monitorType']
 if kind=='keyword':
  found=c['keyword'] in raw.decode('utf-8',errors='replace')
  if found==c.get('invert',False):raise CheckError('Keyword assertion failed.')
 if kind=='json':
  try:
   value=json.loads(raw)
   for part in c['jsonPath'].split('.'):value=value[int(part)] if isinstance(value,list) else value[part]
   if value!=json.loads(c['expectedValue']):raise CheckError('JSON assertion failed.')
  except (ValueError,KeyError,IndexError,TypeError):raise CheckError('JSON path or response could not be read.')
 if kind=='docker':
  try:
   data=json.loads(raw);state=data['State']
   if state.get('Running') is not True or state.get('Health',{}).get('Status')=='unhealthy':raise CheckError('Docker container is stopped or unhealthy.')
  except (ValueError,KeyError,TypeError):raise CheckError('Expected a Docker container inspection response.')
 return {'httpStatus':code}

def websocket_check(c):
 u=urlsplit(c['endpoint']);secure=u.scheme=='wss';port=u.port or (443 if secure else 80);key=base64.b64encode(secrets.token_bytes(16)).decode()
 sock=socket.create_connection((u.hostname,port),timeout=c['timeout'])
 try:
  if secure:sock=ssl.create_default_context(cadata=c.get('caPem') or None).wrap_socket(sock,server_hostname=u.hostname)
  sock.settimeout(c['timeout']);path=(u.path or '/')+('?' +u.query if u.query else '')
  headers={'Host':u.netloc,'Upgrade':'websocket','Connection':'Upgrade','Sec-WebSocket-Key':key,'Sec-WebSocket-Version':'13',**json.loads(c.get('headersJson') or '{}')}
  sock.sendall(('GET '+path+' HTTP/1.1\r\n'+''.join(k+': '+v+'\r\n' for k,v in headers.items())+'\r\n').encode('ascii'))
  raw=b''
  while b'\r\n\r\n' not in raw and len(raw)<65536:
   chunk=sock.recv(4096)
   if not chunk:break
   raw+=chunk
  lines=raw.decode('iso-8859-1').split('\r\n');parts=lines[0].split()
  parsed={line.split(':',1)[0].lower():line.split(':',1)[1].strip() for line in lines[1:] if ':' in line}
  expected=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
  if len(parts)<2 or parts[1]!='101' or parsed.get('sec-websocket-accept')!=expected:raise CheckError('WebSocket upgrade handshake failed.')
  return {'httpStatus':101}
 finally:sock.close()

def recv_exact(sock,count):
 result=b''
 while len(result)<count:
  chunk=sock.recv(count-len(result))
  if not chunk:raise CheckError('Connection closed before a complete response.')
  result+=chunk
 return result

def transport(c):
 raw=socket.create_connection((c['host'],c['port']),timeout=c['timeout'])
 if c['tlsMode']=='tls':
  try:return ssl.create_default_context(cadata=c.get('caPem') or None).wrap_socket(raw,server_hostname=c['host'])
  except Exception:raw.close();raise
 return raw

def broker_check(c):
 with transport(c) as sock:
  sock.settimeout(c['timeout'])
  if c['monitorType']=='redis':
   def command(parts):
    encoded=[p.encode('utf-8') for p in parts];sock.sendall(('*'+str(len(parts))+'\r\n').encode()+b''.join(('$'+str(len(p))+'\r\n').encode()+p+b'\r\n' for p in encoded));result=b''
    while not result.endswith(b'\r\n') and len(result)<4096:result+=recv_exact(sock,1)
    return result
   if c.get('password'):
    parts=['AUTH']+([c['username']] if c.get('username') else [])+[c['password']]
    if command(parts)!=b'+OK\r\n':raise CheckError('Redis authentication was rejected.')
   if command(['PING'])!=b'+PONG\r\n':raise CheckError('Redis did not return PONG.')
  else:
   def field(value):
    raw=value.encode('utf-8');return struct.pack('!H',len(raw))+raw
   payload=field('bitwise-'+secrets.token_hex(6));flags=2
   if c.get('username'):flags|=128;payload+=field(c['username'])
   if c.get('password'):flags|=64;payload+=field(c['password'])
   packet=b'\x00\x04MQTT\x04'+bytes([flags])+b'\x00\x0a'+payload;length=len(packet);prefix=b''
   while True:
    digit=length%128;length//=128;prefix+=bytes([digit|(128 if length else 0)])
    if not length:break
   sock.sendall(b'\x10'+prefix+packet);response=recv_exact(sock,4)
   if response[:2]!=b'\x20\x02' or response[3]!=0:raise CheckError('MQTT connection was rejected.')
   sock.sendall(b'\xe0\x00')
 return {}

def mail_check(c):
 context=ssl.create_default_context(cadata=c.get('caPem') or None);kind=c['monitorType'];mode=c['tlsMode']
 if kind=='smtp':
  client=smtplib.SMTP_SSL(c['host'],c['port'],timeout=c['timeout'],context=context) if mode=='tls' else smtplib.SMTP(c['host'],c['port'],timeout=c['timeout'])
  with client:
   client.ehlo()
   if mode=='starttls':client.starttls(context=context);client.ehlo()
   if c.get('username'):client.login(c['username'],c.get('password',''))
   if client.noop()[0]!=250:raise CheckError('SMTP NOOP check failed.')
 elif kind=='imap':
  client=imaplib.IMAP4_SSL(c['host'],c['port'],ssl_context=context,timeout=c['timeout']) if mode=='tls' else imaplib.IMAP4(c['host'],c['port'],timeout=c['timeout'])
  try:
   if mode=='starttls':client.starttls(ssl_context=context)
   if c.get('username'):client.login(c['username'],c.get('password',''))
   if client.noop()[0]!='OK':raise CheckError('IMAP NOOP check failed.')
  finally:
   try:client.logout()
   except Exception:pass
 else:
  client=poplib.POP3_SSL(c['host'],c['port'],timeout=c['timeout'],context=context) if mode=='tls' else poplib.POP3(c['host'],c['port'],timeout=c['timeout'])
  try:
   if mode=='starttls':client.stls(context=context)
   if c.get('username'):client.user(c['username']);client.pass_(c.get('password',''))
   if not client.noop().startswith(b'+OK'):raise CheckError('POP3 NOOP check failed.')
  finally:
   try:client.quit()
   except Exception:pass
 return {}

def poll(c):
 start=time.monotonic();details={}
 try:
  kind=c['monitorType']
  if kind in ('http','keyword','json','docker'):details=http_check(c)
  elif kind=='websocket':details=websocket_check(c)
  elif kind=='tcp':
   with socket.create_connection((c['host'],c['port']),timeout=c['timeout']):pass
  elif kind=='tls':
   context=ssl.create_default_context(cadata=c.get('caPem') or None)
   with socket.create_connection((c['host'],c['port']),timeout=c['timeout']) as raw:
    with context.wrap_socket(raw,server_hostname=c['host']) as sock:
     cert=sock.getpeercert();expiry=ssl.cert_time_to_seconds(cert['notAfter']);days=(expiry-time.time())/86400
     details={'certificateDays':round(days,2),'certificateExpiry':expiry,'monitorWarning':days<=c['certWarnDays'],'monitorMessage':'TLS certificate expires within '+str(c['certWarnDays'])+' days.' if days<=c['certWarnDays'] else 'TLS certificate verified.'}
  elif kind=='ping':
   try:r=subprocess.run(['ping','-n','-c','1','-W',str(c['timeout']),'--',c['host']],capture_output=True,text=True,timeout=c['timeout']+1)
   except FileNotFoundError:raise CheckError('Install iputils-ping on the monitoring server.')
   if r.returncode:raise CheckError('No ICMP echo response.')
   match=re.search(r'time[=<]([0-9.]+)',r.stdout)
   if match:details['responseMs']=float(match.group(1))
  elif kind=='dns':
   try:import dns.resolver
   except ImportError:raise CheckError('Install python3-dnspython on the monitoring server.')
   resolver=dns.resolver.Resolver()
   if c.get('dnsServer'):resolver.nameservers=[c['dnsServer']]
   answers=resolver.resolve(c['host'],c.get('dnsType','A'),lifetime=c['timeout']);values=[str(a) for a in answers]
   if c.get('expectedValue') and c['expectedValue'].casefold() not in [v.casefold() for v in values]:raise CheckError('DNS answer did not match the expected value.')
   details['dnsAnswers']=values[:20]
  elif kind in ('redis','mqtt'):details=broker_check(c)
  elif kind in ('smtp','imap','pop3'):details=mail_check(c)
  elif kind=='ntp':
   with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
    sock.settimeout(c['timeout']);sock.connect((c['host'],c['port']));stamp=time.time()+2208988800;nonce=struct.pack('!II',int(stamp),int((stamp%1)*(2**32)));sock.send(bytes([0x23])+bytes(39)+nonce);reply=sock.recv(512)
    if len(reply)<48 or reply[0]&7!=4 or reply[0]>>6==3 or not 1<=reply[1]<=15 or reply[24:32]!=nonce:raise CheckError('No synchronized NTP server response.')
  elif kind=='steam':
   with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
    sock.settimeout(c['timeout']);sock.connect((c['host'],c['port']));query=b'\xff\xff\xff\xffTSource Engine Query\x00';sock.send(query);raw=sock.recv(4096)
    if raw[:5]==b'\xff\xff\xff\xffA' and len(raw)>=9:sock.send(query+raw[5:9]);raw=sock.recv(4096)
    if len(raw)<20 or raw[:5]!=b'\xff\xff\xff\xffI':raise CheckError('No supported Steam A2S_INFO response.')
  else:raise CheckError('Push monitors accept incoming heartbeats instead of active polling.')
  return {'source':'Service monitor','checkSuccess':True,'operationalOnline':True,'responseMs':round((time.monotonic()-start)*1000,2),**details}
 except Exception as error:
  # Do not echo URLs, headers, response bodies, or credentials from transport errors.
  message=str(error) if isinstance(error,CheckError) else 'Check failed: '+type(error).__name__+'. Check network, authentication, and protocol settings.'
  return {'source':'Service monitor','checkSuccess':False,'operationalOnline':False,'responseMs':None,'monitorMessage':message}
