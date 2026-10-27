import sys,json,unittest,subprocess,threading,socket,base64,hashlib
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from unittest.mock import patch,Mock,MagicMock
import types
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import service_checks as checks
class Fixture(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  code=302 if self.path=='/redirect' else 503 if self.path=='/bad' else 200
  self.send_response(code)
  if code==302:self.send_header('Location','http://127.0.0.1:1/never-follow')
  self.end_headers();self.wfile.write(b'{"status":{"ready":true},"State":{"Running":true}}')
class Checks(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.server=ThreadingHTTPServer(('127.0.0.1',0),Fixture);cls.url='http://127.0.0.1:'+str(cls.server.server_port);threading.Thread(target=cls.server.serve_forever,daemon=True).start()
 @classmethod
 def tearDownClass(cls):cls.server.shutdown();cls.server.server_close()
 def config(self,kind='http',**kw):return checks.validate({'kind':'service','monitorType':kind,'endpoint':self.url,'host':'localhost',**kw})
 def test_http_success_failure_and_status_allowlist(self):
  self.assertTrue(checks.poll(self.config())['checkSuccess']);self.assertFalse(checks.poll(self.config(endpoint=self.url+'/bad'))['checkSuccess']);self.assertTrue(checks.poll(self.config(endpoint=self.url+'/bad',expectedCodes='500-599'))['checkSuccess'])
 def test_redirect_not_followed(self):
  result=checks.poll(self.config(endpoint=self.url+'/redirect',expectedCodes='302'));self.assertTrue(result['checkSuccess']);self.assertEqual(result['httpStatus'],302)
 def test_keyword_and_inverse(self):
  self.assertTrue(checks.poll(self.config('keyword',keyword='ready'))['checkSuccess']);self.assertFalse(checks.poll(self.config('keyword',keyword='ready',invert=True))['checkSuccess'])
 def test_json_values_and_missing_path(self):
  self.assertTrue(checks.poll(self.config('json',jsonPath='status.ready',expectedValue='true'))['checkSuccess']);self.assertFalse(checks.poll(self.config('json',jsonPath='status.missing',expectedValue='true'))['checkSuccess'])
 def test_tcp_real_listener(self):self.assertTrue(checks.poll(self.config('tcp',host='127.0.0.1',port=self.server.server_port))['checkSuccess'])
 def test_sensitive_settings_and_errors_redacted(self):
  c=self.config(endpoint='https://example.com/check?token=private',headersJson='{"Authorization":"private-header"}',proxyUrl='http://user:secret@proxy.local:8080')
  data=json.dumps(checks.public(c));self.assertNotIn('private',data);self.assertNotIn('secret',data)
  with patch.object(checks,'http_check',side_effect=OSError('private-token')):self.assertNotIn('private-token',json.dumps(checks.poll(c)))
 def test_validation(self):
  for fields in [{'endpoint':'file:///etc/passwd'},{'endpoint':'http://user:pass@example.com'},{'interval':10},{'timeout':60},{'retries':-1},{'headersJson':'{"X-Test":"bad\\r\\nvalue"}'},{'expectedCodes':'299-200'},{'tags':['x'*41]},{'proxyUrl':'ftp://proxy.local'}]:
   with self.subTest(fields=fields),self.assertRaises(ValueError):self.config(**fields)
 def test_ping_no_shell_and_missing_binary(self):
  with patch.object(subprocess,'run',return_value=Mock(returncode=0,stdout='time=3.2 ms')) as run:
   result=checks.poll(self.config('ping'));self.assertTrue(result['checkSuccess']);self.assertNotIn('shell',run.call_args.kwargs)
  with patch.object(subprocess,'run',side_effect=FileNotFoundError()):self.assertFalse(checks.poll(self.config('ping'))['checkSuccess'])
 def test_tls_expiry_warning(self):
  tls=Mock();tls.__enter__=Mock(return_value=tls);tls.__exit__=Mock();tls.getpeercert.return_value={'notAfter':'Jan 01 00:00:00 2030 GMT'}
  raw=Mock();raw.__enter__=Mock(return_value=raw);raw.__exit__=Mock();context=Mock();context.wrap_socket.return_value=tls
  expiry=checks.ssl.cert_time_to_seconds('Jan 01 00:00:00 2030 GMT')
  with patch.object(checks.socket,'create_connection',return_value=raw),patch.object(checks.ssl,'create_default_context',return_value=context),patch.object(checks.time,'time',return_value=expiry-86400):
   result=checks.poll(self.config('tls'));self.assertTrue(result['checkSuccess']);self.assertTrue(result['monitorWarning']);self.assertEqual(result['certificateDays'],1)
 def test_websocket_validates_accept_digest(self):
  sock=Mock();nonce=base64.b64encode(b'x'*16).decode();digest=base64.b64encode(hashlib.sha1((nonce+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode();sock.recv.return_value=('HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: '+digest+'\r\n\r\n').encode()
  with patch.object(checks.socket,'create_connection',return_value=sock),patch.object(checks.secrets,'token_bytes',return_value=b'x'*16):self.assertTrue(checks.poll(self.config('websocket',endpoint='ws://localhost/socket'))['checkSuccess'])
  sock.recv.return_value=b'HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: wrong\r\n\r\n'
  with patch.object(checks.socket,'create_connection',return_value=sock):self.assertFalse(checks.poll(self.config('websocket',endpoint='ws://localhost/socket'))['checkSuccess'])

 def test_redis_auth_and_ping_no_data_writes(self):
  sock=MagicMock();sock.__enter__.return_value=sock;sock.recv.side_effect=[bytes([x]) for x in b'+OK\r\n+PONG\r\n']
  with patch.object(checks,'transport',return_value=sock):self.assertTrue(checks.poll(self.config('redis',username='monitor',password='secret'))['checkSuccess'])
  commands=b''.join(call.args[0] for call in sock.sendall.call_args_list);self.assertIn(b'AUTH',commands);self.assertIn(b'PING',commands);self.assertNotIn(b'SET',commands)
 def test_mqtt_connect_and_reject(self):
  for code,success in [(0,True),(5,False)]:
   sock=MagicMock();sock.__enter__.return_value=sock;sock.recv.return_value=b'\x20\x02\x00'+bytes([code])
   with patch.object(checks,'transport',return_value=sock):self.assertEqual(checks.poll(self.config('mqtt',username='monitor',password='secret'))['checkSuccess'],success)
 def test_ntp_origin_validation(self):
  sock=MagicMock();sock.__enter__.return_value=sock
  def response(size):return b'\x24\x02'+bytes(22)+sock.send.call_args.args[0][40:48]+bytes(16)
  sock.recv.side_effect=response
  with patch.object(checks.socket,'socket',return_value=sock):self.assertTrue(checks.poll(self.config('ntp'))['checkSuccess'])
  sock.recv.side_effect=None;sock.recv.return_value=b'\x24\x02'+bytes(46)
  with patch.object(checks.socket,'socket',return_value=sock):self.assertFalse(checks.poll(self.config('ntp'))['checkSuccess'])
 def test_mail_noop_never_sends_email(self):
  smtp=MagicMock();smtp.noop.return_value=(250,b'OK')
  with patch.object(checks.smtplib,'SMTP',return_value=smtp):self.assertTrue(checks.poll(self.config('smtp',username='monitor',password='secret'))['checkSuccess'])
  smtp.starttls.assert_called_once();smtp.sendmail.assert_not_called();smtp.send_message.assert_not_called()
  imap=MagicMock();imap.noop.return_value=('OK',[])
  with patch.object(checks.imaplib,'IMAP4_SSL',return_value=imap):self.assertTrue(checks.poll(self.config('imap'))['checkSuccess'])
  pop=MagicMock();pop.noop.return_value=b'+OK'
  with patch.object(checks.poplib,'POP3_SSL',return_value=pop):self.assertTrue(checks.poll(self.config('pop3'))['checkSuccess'])
 def test_dns_expected_answer(self):
  resolver=Mock();resolver.resolve.return_value=['192.0.2.1'];module=types.ModuleType('dns');child=types.ModuleType('dns.resolver');child.Resolver=lambda:resolver;module.resolver=child
  with patch.dict(sys.modules,{'dns':module,'dns.resolver':child}):
   self.assertTrue(checks.poll(self.config('dns',expectedValue='192.0.2.1'))['checkSuccess']);self.assertFalse(checks.poll(self.config('dns',expectedValue='192.0.2.2'))['checkSuccess'])
 def test_docker_running_and_unhealthy(self):
  for healthy in [True,False]:
   response=MagicMock();response.__enter__.return_value=response;response.status=200;response.read.return_value=json.dumps({'State':{'Running':True,'Health':{'Status':'healthy' if healthy else 'unhealthy'}}}).encode();opener=Mock();opener.open.return_value=response
   with patch.object(checks,'build_opener',return_value=opener):self.assertEqual(checks.poll(self.config('docker',endpoint='https://docker.local/containers/app/json'))['checkSuccess'],healthy)
