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
if __name__=='__main__':unittest.main()
