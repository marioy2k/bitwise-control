import importlib.util,json,tempfile,threading,unittest,sys
from pathlib import Path
from http.cookiejar import CookieJar
from http.server import ThreadingHTTPServer
from urllib.request import Request,build_opener,HTTPCookieProcessor
from urllib.error import HTTPError
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
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
   for table in ['inventory','tokens','samples','incidents','audit','jobs','connections','settings','outbox','users']:c.execute('DELETE FROM '+table)
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
 def test_api_integration_secret_redaction_and_poll(self):
  self.inventory();config={'kind':'mikrotik','url':'https://router','username':'monitor','password':'a-secret'}
  self.assertEqual(self.request('/api/integration','POST',{'id':1,'config':config})[0],200)
  state=self.request('/api/state')[1];self.assertNotIn('a-secret',json.dumps(state));self.assertNotIn('password',state['devices'][0]['integration'])
  with patch.object(app.adapters,'poll',return_value={'source':'MikroTik REST','cpu':10,'memory':20,'disk':30}):
   self.assertEqual(self.request('/api/poll','POST',{'id':1})[0],200)
  self.assertEqual(self.request('/api/state')[1]['devices'][0]['status'],'Online')
 def test_agent_jobs_scoped_to_token(self):
  self.inventory();token=self.request('/api/enroll','POST',{'id':1})[1]['token']
  job=self.request('/api/action','POST',{'id':1,'action':'upgrade_check'})[1]['job']
  self.assertEqual(self.request('/api/agent/jobs')[0],401)
  jobs=self.request('/api/agent/jobs',headers={'Authorization':'Bearer '+token})[1];self.assertEqual(jobs[0]['id'],job)
  self.assertEqual(self.request('/api/agent/result','POST',{'job':job,'status':'completed','result':'No updates'},headers={'Authorization':'Bearer '+token})[0],200)
  self.assertEqual(self.request('/api/jobs/1')[1][0]['status'],'completed')
 def test_api_controls_opt_in(self):
  self.inventory();self.request('/api/integration','POST',{'id':1,'config':{'kind':'mikrotik','url':'https://router','username':'a','password':'b'}})
  result=self.request('/api/action','POST',{'id':1,'action':'reboot'})[1];self.assertEqual(result['status'],'failed')
 def test_config_update_retains_secret(self):
  self.inventory();config={'kind':'mikrotik','url':'https://router','username':'a','password':'secret'};self.request('/api/integration','POST',{'id':1,'config':config});config['password']='';config['username']='b'
  self.assertEqual(self.request('/api/integration','POST',{'id':1,'config':config})[0],200)
  with app.connect() as c:stored=json.loads(c.execute('SELECT config FROM connections WHERE device=1').fetchone()['config'])
  self.assertEqual(stored['password'],'secret');self.assertEqual(stored['username'],'b')
 def account_client(self,role='viewer',companies=None,username='reader'):
  self.request('/api/users','POST',{'username':username,'password':'new-user-password','role':role,'companies':companies or [],'enabled':True})
  client=build_opener(HTTPCookieProcessor(CookieJar()));self.assertEqual(self.request('/login','POST',{'username':username,'password':'new-user-password'},client=client)[0],200);return client
 def test_viewer_company_isolation(self):
  self.inventory();data=self.request('/api/state')[1];data['companies'].append('Other');data['devices'].append({'id':2,'name':'Hidden','company':'Other','type':'Server','ip':'127.0.0.2','platform':'Linux','port':22});self.request('/api/state','PUT',data)
  client=self.account_client(companies=['Example']);visible=self.request('/api/state',client=client)[1]
  self.assertEqual(len(visible['devices']),1);self.assertEqual(visible['companies'],['Example']);self.assertEqual(self.request('/api/history/2',client=client)[0],403)
  self.assertEqual(self.request('/api/check','POST',{'id':1},client=client)[0],403);self.assertEqual(self.request('/api/backup',client=client)[0],403)
 def test_operator_cannot_overwrite_other_company(self):
  self.inventory();data=self.request('/api/state')[1];data['companies'].append('Other');data['devices'].append({'id':2,'name':'Hidden','company':'Other','type':'Server','ip':'127.0.0.2','platform':'Linux','port':22});self.request('/api/state','PUT',data)
  client=self.account_client('operator',['Example']);visible=self.request('/api/state',client=client)[1];visible['devices'][0]['name']='Edited';self.assertEqual(self.request('/api/state','PUT',visible,client=client)[0],200)
  full=self.request('/api/state')[1];self.assertEqual(len(full['devices']),2);self.assertTrue(any(d['name']=='Hidden' for d in full['devices']))
  self.assertEqual(self.request('/api/action','POST',{'id':2,'action':'reboot'},client=client)[0],403)
  self.assertEqual(self.request('/api/integration','POST',{'id':1,'config':None},client=client)[0],403)
 def test_disabling_user_revokes_session(self):
  client=self.account_client();self.request('/api/users','POST',{'username':'reader','role':'viewer','companies':[],'enabled':False});self.assertEqual(self.request('/api/state',client=client)[0],401)
 def test_user_changes_own_password(self):
  client=self.account_client();self.assertEqual(self.request('/api/password','POST',{'current':'new-user-password','password':'another-password'},client=client)[0],200)
  self.assertEqual(self.request('/login','POST',{'username':'reader','password':'another-password'},client=client)[0],200)
 def test_monitoring_rule_override(self):
  self.inventory();settings={'rules':{'cpu':50,'memory':90,'disk':90,'temperature':70,'offlineSeconds':180},'delivery':{'mode':'none'}}
  self.assertEqual(self.request('/api/monitoring','POST',settings)[0],200);app.record(1,{'cpu':60});app.incidents();self.assertEqual(len(self.request('/api/state')[1]['incidents']),1)
 def test_notification_queue_delivery_and_no_secrets_in_state(self):
  self.inventory();settings={'rules':{},'delivery':{'mode':'webhook','webhookUrl':'https://notify.invalid/private-secret','webhookToken':'bearer-secret'}}
  self.assertEqual(self.request('/api/monitoring','POST',settings)[0],200);app.record(1,{'cpu':95});app.incidents()
  with patch.object(app.notifications,'send') as send:app.deliver_notifications();self.assertEqual(send.call_count,1)
  state=self.request('/api/state')[1];self.assertEqual(state['notificationStatus'][0]['status'],'sent');self.assertNotIn('private-secret',json.dumps(state));self.assertNotIn('bearer-secret',json.dumps(state))
 def test_disabled_delivery_sends_nothing(self):
  self.inventory();app.record(1,{'cpu':95});app.incidents()
  with patch.object(app.notifications,'send') as send:app.deliver_notifications();send.assert_not_called()
 def test_maintenance_suppresses_incidents(self):
  self.inventory();data=self.request('/api/state')[1];data['devices'][0]['maintenanceUntil']=app.time.time()+3600;self.assertEqual(self.request('/api/state','PUT',data)[0],200)
  app.record(1,{'cpu':99});app.incidents();self.assertEqual(self.request('/api/state')[1]['incidents'],[])
  data=self.request('/api/state')[1];data['devices'][0]['maintenanceUntil']=0;self.request('/api/state','PUT',data);app.incidents();self.assertEqual(len(self.request('/api/state')[1]['incidents']),1)
 def printer_connection(self,threshold=20):
  config={'kind':'printer','host':'printer.local','username':'monitor','authPassword':'auth-secret','privPassword':'priv-secret','supplyThreshold':threshold}
  self.assertEqual(self.request('/api/integration','POST',{'id':1,'config':config})[0],200)
 def test_printer_alert_boundary_dedup_and_recovery(self):
  self.inventory();self.printer_connection()
  with app.connect() as c:c.execute("INSERT INTO settings VALUES('monitoring',?)",(json.dumps({'rules':dict(app.notifications.DEFAULT_RULES),'delivery':{'mode':'webhook'}}),))
  def sample(percent):
   app.record(1,{'supplies':[{'id':'1.1','name':'Black toner','class':3,'percent':percent},{'id':'1.2','name':'Waste','class':4,'percent':1}]});app.incidents()
  sample(20);state=app.view_state();self.assertEqual(state['devices'][0]['status'],'Warning');self.assertIn('Black toner (20% remaining)',state['incidents'][0]['message']);sample(19)
  with app.connect() as c:self.assertEqual(c.execute('SELECT count(*) FROM outbox').fetchone()[0],1)
  sample(21);self.assertEqual(app.view_state()['incidents'],[])
  with app.connect() as c:self.assertEqual(c.execute('SELECT count(*) FROM outbox').fetchone()[0],2)
 def test_printer_disabled_unknown_and_maintenance(self):
  self.inventory();self.printer_connection(0)
  app.record(1,{'supplies':[{'id':'1.1','name':'Black','class':3,'percent':0}]});app.incidents();self.assertEqual(app.view_state()['incidents'],[])
  self.printer_connection();app.record(1,{'supplies':[{'id':'1.1','name':'Black','class':3,'percent':None}]});app.incidents();self.assertEqual(app.view_state()['incidents'],[])
  data=self.request('/api/state')[1];data['devices'][0]['maintenanceUntil']=app.time.time()+3600;self.request('/api/state','PUT',data)
  app.record(1,{'supplies':[{'id':'1.1','name':'Black','class':3,'percent':0}]});app.incidents();self.assertEqual(app.view_state()['incidents'],[])
 def test_printer_poll_api_and_saved_threshold(self):
  self.inventory();self.printer_connection(15)
  with patch.object(app.adapters,'poll',return_value={'source':'Printer SNMPv3','supplies':[{'id':'1.1','name':'Cyan','class':3,'percent':10}]}):
   code,state,_=self.request('/api/poll','POST',{'id':1});self.assertEqual(code,200);self.assertEqual(state['devices'][0]['status'],'Warning');self.assertEqual(state['devices'][0]['integration']['supplyThreshold'],15)
  config={'kind':'printer','host':'printer.local','username':'monitor','supplyThreshold':30}
  self.assertEqual(self.request('/api/integration','POST',{'id':1,'config':config})[0],200)
  with app.connect() as c:self.assertEqual(json.loads(c.execute('SELECT config FROM connections').fetchone()[0])['authPassword'],'auth-secret')
 def test_dual_delivery_independent_retry_and_redaction(self):
  self.inventory();settings={'rules':{},'delivery':{'mode':'both','smtpHost':'smtp.example.com','sender':'alerts@example.com','recipient':'admin@example.com','smtpPassword':'smtp-secret','discordUrl':'https://discord.com/api/webhooks/123456/discord-secret'}}
  self.assertEqual(self.request('/api/monitoring','POST',settings)[0],200);app.record(1,{'cpu':95});app.incidents()
  def deliver(config,*args):
   if config['mode']=='email':raise OSError('SMTP unavailable')
  with patch.object(app.notifications,'send',side_effect=deliver) as send:app.deliver_notifications();self.assertEqual(send.call_count,2)
  with app.connect() as c:
   rows={r['channel']:dict(r) for r in c.execute('SELECT * FROM outbox')};self.assertEqual(rows['discord']['status'],'sent');self.assertEqual(rows['email']['status'],'pending');c.execute("UPDATE outbox SET next_attempt=0 WHERE channel='email'")
  with patch.object(app.notifications,'send') as send:app.deliver_notifications();self.assertEqual(send.call_count,1);self.assertEqual(send.call_args.args[0]['mode'],'email')
  state=json.dumps(self.request('/api/state')[1]);self.assertNotIn('smtp-secret',state);self.assertNotIn('discord-secret',state)
 def test_dual_delivery_destination_change_cancels_pending(self):
  self.inventory();settings={'rules':{},'delivery':{'mode':'both','smtpHost':'smtp.example.com','sender':'alerts@example.com','recipient':'admin@example.com','discordUrl':'https://discord.com/api/webhooks/123456/token'}}
  self.assertEqual(self.request('/api/monitoring','POST',settings)[0],200);app.record(1,{'cpu':95});app.incidents()
  self.request('/api/monitoring','POST',{'rules':{},'delivery':{'mode':'none'}})
  with patch.object(app.notifications,'send') as send:app.deliver_notifications();send.assert_not_called()
  with app.connect() as c:self.assertEqual(c.execute("SELECT count(*) FROM outbox WHERE status='cancelled'").fetchone()[0],2)
if __name__=='__main__':unittest.main()
