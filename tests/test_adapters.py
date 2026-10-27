import sys,unittest,subprocess
from pathlib import Path
from unittest.mock import patch,Mock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import adapters
class Adapters(unittest.TestCase):
 def test_proxmox_metrics(self):
  c={'kind':'proxmox','node':'pve','target':'lxc','vmid':100}
  with patch.object(adapters,'pve',return_value={'cpu':.12,'mem':512,'maxmem':1024,'disk':20,'maxdisk':100,'uptime':42,'status':'running'}) as request:
   data=adapters.pve_poll(c);self.assertEqual(data['cpu'],12);self.assertEqual(data['memory'],50);self.assertEqual(data['disk'],20);self.assertTrue(data['operationalOnline']);self.assertEqual(request.call_args.args[1],'/api2/json/nodes/pve/lxc/100/status/current')
 def test_proxmox_reboot_guest(self):
  with patch.object(adapters,'pve',return_value='UPID:task') as request:
   result=adapters.pve_action({'node':'pve','target':'lxc','vmid':100},'reboot',{});self.assertEqual(result,'UPID:task');self.assertEqual(request.call_args.args[1],'/api2/json/nodes/pve/lxc/100/status/reboot')
 def test_mikrotik_metrics(self):
  with patch.object(adapters,'mt',side_effect=[{'cpu-load':'15','total-memory':'1000','free-memory':'400','total-hdd-space':'100','free-hdd-space':'75','uptime':'1d2h3m4s','version':'7.1'},[]]):
   d=adapters.mt_poll({});self.assertEqual(d['cpu'],15);self.assertEqual(d['memory'],60);self.assertEqual(d['disk'],25);self.assertEqual(d['uptimeSeconds'],93784)
 def test_mikrotik_poe(self):
  with patch.object(adapters,'mt',return_value={}) as request:
   adapters.mt_action({},'poe',{'port':'*A','mode':'off'});self.assertEqual(request.call_args.args[1],'/interface/ethernet/poe/%2AA');self.assertEqual(request.call_args.args[3],{'poe-out':'off'})
 def test_unifi_metrics(self):
  with patch.object(adapters,'ui',side_effect=[{'name':'Switch','state':'ONLINE','interfaces':{'ports':[{'idx':1}]}},{'cpuUtilizationPct':11,'memoryUtilizationPct':22,'uptimeSec':300}]):
   d=adapters.ui_poll({'siteId':'site','deviceId':'device'});self.assertEqual(d['cpu'],11);self.assertTrue(d['operationalOnline']);self.assertEqual(d['ports'][0]['idx'],1)
 def test_unifi_power_cycle(self):
  with patch.object(adapters,'ui',return_value={}) as request:
   adapters.ui_action({'siteId':'site','deviceId':'device'},'poe_cycle',{'port':3});self.assertEqual(request.call_args.args[3],{'action':'POWER_CYCLE'})
 def test_snmp_metrics(self):
  with patch.object(adapters,'snmp',side_effect=['123400','"switch"','10\n30','1000','600']):
   d=adapters.snmp_poll({});self.assertEqual(d['uptimeSeconds'],1234);self.assertEqual(d['cpu'],20);self.assertEqual(d['memory'],40)
 def test_snmp_poe_oid(self):
  with patch.object(adapters,'snmp',return_value='1') as request:
   adapters.snmp_action({},'poe',{'group':1,'port':4,'mode':'off'});self.assertEqual(request.call_args.args[1],'.1.3.6.1.2.1.105.1.1.1.3.1.4');self.assertEqual(request.call_args.kwargs['value'],2)
 def test_snmp_secrets_not_process_arguments(self):
  c={'host':'127.0.0.1','username':'user','authPassword':'auth-secret','privPassword':'priv-secret'}
  with patch.object(subprocess,'run',return_value=Mock(returncode=0,stdout='1234')) as run:
   adapters.snmp(c,'.1.3.6.1.2.1.1.3.0');self.assertNotIn('auth-secret',' '.join(run.call_args.args[0]));self.assertNotIn('priv-secret',' '.join(run.call_args.args[0]))
 def test_tls_is_required(self):
  with self.assertRaises(ValueError):adapters.validate({'kind':'mikrotik','url':'http://router','username':'a','password':'b'})
 def test_credentials_are_redacted(self):
  c=adapters.public({'kind':'proxmox','tokenId':'x','tokenSecret':'secret','caPem':'ca'});self.assertNotIn('tokenSecret',c);self.assertTrue(c['credentialsConfigured'])
 def test_controls_are_opt_in(self):
  with self.assertRaises(adapters.AdapterError):adapters.action({'kind':'mikrotik'},'reboot',{})
 def test_invalid_poe_rejected(self):
  with self.assertRaises(adapters.AdapterError):adapters.mt_action({},'poe',{'port':'../system','mode':'on'})
 def test_nan_metrics_are_unknown(self):self.assertIsNone(adapters.bounded(float('nan')))
 def printer_table(self,rows):
  return '\n'.join('.1.3.6.1.2.1.43.11.1.1.'+str(col)+'.'+index+' '+str(value) for index,row in rows.items() for col,value in row.items())
 def test_printer_indexed_supplies_and_unknown_values(self):
  raw=self.printer_table({'1.2':{4:3,6:'"Black toner"',7:7,8:2000,9:200},'2.2':{4:3,6:'"Cyan ink"',7:19,8:-2,9:35},'1.9':{4:4,6:'"Waste"',7:19,9:5},'1.7':{4:3,6:'"Unknown"',7:19,9:-3}})
  with patch.object(adapters,'snmp',return_value=raw) as request:
   data=adapters.printer_poll({});request.assert_called_once_with({},'.1.3.6.1.2.1.43.11.1.1',walk=True,indexed=True)
  values={s['id']:s for s in data['supplies']};self.assertEqual(values['1.2']['percent'],10);self.assertEqual(values['2.2']['percent'],35);self.assertIsNone(values['1.7']['percent']);self.assertEqual(values['1.9']['class'],4)
 def test_printer_invalid_percentages_remain_unknown(self):
  for unit,capacity,level in [(7,0,1),(7,-2,50),(7,20,21),(19,100,101),(19,100,-1),(19,100,-2),(2,100,50)]:
   with self.subTest(unit=unit,capacity=capacity,level=level),patch.object(adapters,'snmp',return_value=self.printer_table({'1.1':{4:3,7:unit,8:capacity,9:level}})):
    self.assertIsNone(adapters.printer_poll({})['supplies'][0]['percent'])
 def test_printer_empty_or_unsupported_table(self):
  with patch.object(adapters,'snmp',return_value='No more variables left in this MIB View'):
   with self.assertRaises(adapters.AdapterError):adapters.printer_poll({})
 def test_printer_config_validation_and_readonly(self):
  c={'kind':'printer','host':'printer.local','username':'monitor','authPassword':'auth-secret','privPassword':'priv-secret','allowControl':True}
  validated=adapters.validate(c);self.assertEqual(validated['supplyThreshold'],20);self.assertFalse(validated['allowControl']);self.assertNotIn('authPassword',adapters.public(validated))
  for invalid in [-1,101,True,20.5,'20']:
   with self.subTest(threshold=invalid),self.assertRaises(ValueError):adapters.validate({**c,'supplyThreshold':invalid})
  with self.assertRaises(adapters.AdapterError):adapters.action({**c,'allowControl':True},'reboot',{})
 def test_snmp_indexed_walk_keeps_numeric_oids(self):
  with patch.object(subprocess,'run',return_value=Mock(returncode=0,stdout='')) as run:
   adapters.snmp({'host':'printer.local','username':'user','authPassword':'auth-secret','privPassword':'priv-secret'},'.1.3.6.1.2.1.43.11.1.1',walk=True,indexed=True)
   self.assertIn('-Onq',run.call_args.args[0]);self.assertEqual(run.call_args.args[0][0],'snmpwalk')
 def test_snmp_context_passed_to_command(self):
  config={'host':'printer.local','username':'user','authPassword':'auth-secret','privPassword':'priv-secret','contextName':'Jetdirect'}
  with patch.object(subprocess,'run',return_value=Mock(returncode=0,stdout='15')) as run:
   adapters.snmp(config,'.1.3.6.1.2.1.43.11.1.1',walk=True,indexed=True)
   args=run.call_args.args[0];self.assertEqual(args[1:3],['-n','Jetdirect']);self.assertNotIn('auth-secret',' '.join(args))
 def test_snmp_context_validation(self):
  config={'kind':'printer','host':'printer.local','username':'user','authPassword':'auth-secret','privPassword':'priv-secret'}
  self.assertEqual(adapters.validate({**config,'contextName':'Jetdirect'})['contextName'],'Jetdirect')
  for context in [None,42,'x'*256,'bad\ncontext']:
   with self.subTest(context=context),self.assertRaises(ValueError):adapters.validate({**config,'contextName':context})
if __name__=='__main__':unittest.main()
