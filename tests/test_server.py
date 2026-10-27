import importlib.util,json,tempfile,threading,unittest
from pathlib import Path
from http.cookiejar import CookieJar
from http.server import ThreadingHTTPServer
from urllib.request import Request,build_opener,HTTPCookieProcessor
from urllib.error import HTTPError
spec=importlib.util.spec_from_file_location('server',Path(__file__).resolve().parents[1]/'server.py');app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)

class API(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();app.DATA=Path(cls.tmp.name);app.DB=app.DATA/'db.sqlite';app.AUTH=app.DATA/'auth.json';app.init()
  cls.server=ThreadingHTTPServer(('127.0.0.1',0),app.Handler);cls.base='http://127.0.0.1:'+str(cls.server.server_port)
  threading.Thread(target=cls.server.serve_forever,daemon=True).start()
 @classmethod
 def tearDownClass(cls):cls.server.shutdown();cls.server.server_close();cls.tmp.cleanup()
 def setUp(self):
  app.SESSIONS.clear();app.ATTEMPTS.clear()
  with app.connect() as c:
   for table in ['inventory','tokens','samples','incidents','audit']:c.execute('DELETE FROM '+table)
  app.init();app.AUTH.write_text(json.dumps({'username':'admin','salt':'01'*16,'hash':app.digest('test-password-123',bytes.fromhex('01'*16))}))
  self.client=build_opener(HTTPCookieProcessor(CookieJar()));self.request('/login','POST',{'username':'admin','password':'test-password-123'})
 def request(self,path,method='GET',body=None,headers=None,client=None):
  req=Request(self.base+path,method=method,data=json.dumps(body).encode() if body is not None else None,headers={'Content-Type':'application/json',**(headers or {})})
  try:r=(client or self.client).open(req)
  except HTTPError as e:r=e
  raw=r.read();return r.status,json.loads(raw) if raw and r.headers.get('Content-Type','').startswith('application/json') else raw,r
 def inventory(self):
  _,data,_=self.request('/api/state');data['companies']=['Example'];data['devices']=[{'id':1,'name':'Container','company':'Example','type':'Server','ip':'127.0.0.1','platform':'Ubuntu','port':22}];return self.request('/api/state','PUT',data)
 def test_auth_required(self):self.assertEqual(self.request('/api/state',client=build_opener())[0],401)
 def test_wrong_password(self):self.assertEqual(self.request('/login','POST',{'username':'admin','password':'bad'})[0],401)
 def test_empty_inventory(self):self.assertEqual(self.request('/api/state')[1]['devices'],[])
 def test_inventory_durable(self):
  self.assertEqual(self.inventory()[0],200);app.init();self.assertEqual(self.request('/api/state')[1]['devices'][0]['name'],'Container')
 def test_conflict(self):
  old=self.request('/api/state')[1];self.inventory();self.assertEqual(self.request('/api/state','PUT',old)[0],409)
 def test_invalid_company(self):
  data=self.request('/api/state')[1];data['companies']=['a','A'];self.assertEqual(self.request('/api/state','PUT',data)[0],400)
 def test_cross_origin(self):self.assertEqual(self.request('/api/state','PUT',{},headers={'Origin':'http://attacker.invalid'})[0],403)
 def test_agent_auth_and_measurements(self):
  self.inventory();token=self.request('/api/enroll','POST',{'id':1})[1]['token'];headers={'Authorization':'Bearer '+token}
  body={'cpu':12,'memory':35,'disk':44,'uptimeSeconds':400,'hostname':'test'}
  self.assertEqual(self.request('/api/agent/report','POST',body)[0],401)
  self.assertEqual(self.request('/api/agent/report','POST',body,headers)[0],200)
  device=self.request('/api/state')[1]['devices'][0];self.assertEqual(device['status'],'Online');self.assertEqual(device['cpu'],12)
  self.assertEqual(len(self.request('/api/history/1')[1]),1)
  body['cpu']=999;self.assertEqual(self.request('/api/agent/report','POST',body,headers)[0],400)
 def test_alert_and_recovery(self):
  self.inventory();app.record(1,{'cpu':95,'memory':10,'disk':10});app.incidents();self.assertEqual(len(self.request('/api/state')[1]['incidents']),1)
  app.record(1,{'cpu':10,'memory':10,'disk':10});app.incidents();self.assertEqual(self.request('/api/state')[1]['incidents'],[])
 def test_offline_alert(self):
  self.inventory();app.record(1,{'cpu':10})
  with app.connect() as c:c.execute('UPDATE samples SET time=time-200')
  app.incidents();self.assertEqual(self.request('/api/state')[1]['devices'][0]['status'],'Offline');self.assertEqual(len(self.request('/api/state')[1]['incidents']),1)
 def test_delete_revokes_agent(self):
  self.inventory();token=self.request('/api/enroll','POST',{'id':1})[1]['token'];data=self.request('/api/state')[1];data['devices']=[];self.request('/api/state','PUT',data)
  self.assertEqual(self.request('/api/agent/report','POST',{'hostname':'x'},headers={'Authorization':'Bearer '+token})[0],401)
 def test_password_change_and_logout(self):
  self.assertEqual(self.request('/api/password','POST',{'current':'test-password-123','password':'new-password-123'})[0],200)
  self.assertEqual(self.request('/logout','POST',{})[0],204)
  self.assertEqual(self.request('/api/state')[0],401)
  self.assertEqual(self.request('/login','POST',{'username':'admin','password':'new-password-123'})[0],200)
 def test_rate_limit(self):
  for i in range(10):self.assertEqual(self.request('/login','POST',{'username':'admin','password':'wrong'})[0],401)
  self.assertEqual(self.request('/login','POST',{'username':'admin','password':'wrong'})[0],429)
if __name__=='__main__':unittest.main()
