import json,sys,unittest
from pathlib import Path
from unittest.mock import patch,MagicMock
import types
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import notifications

class Notifications(unittest.TestCase):
 def config(self):return {'mode':'both','smtpHost':'smtp.example.com','smtpPort':587,'smtpUser':'monitor','smtpPassword':'smtp-secret','sender':'alerts@example.com','recipient':'admin@example.com','discordUrl':'https://discord.com/api/webhooks/123456/discord-secret'}
 def test_both_validation_redaction_and_secret_preservation(self):
  previous=notifications.validate({'delivery':self.config()},{});public=notifications.public(previous)
  self.assertNotIn('smtp-secret',json.dumps(public));self.assertNotIn('discord-secret',json.dumps(public));self.assertEqual(notifications.channels(previous['delivery']),['email','discord'])
  config=self.config();config['smtpPassword']='';config['discordUrl']=''
  self.assertEqual(notifications.validate({'delivery':config},previous)['delivery'],previous['delivery'])
 def test_discord_url_validation(self):
  for url in ['https://evil.invalid/api/webhooks/1/token','https://discord.com.evil.invalid/api/webhooks/1/token','http://discord.com/api/webhooks/1/token','https://discord.com/api/webhooks/1/token?wait=false','https://discord.com/api/webhooks/1/token/messages/1','https://discord.com:444/api/webhooks/1/token']:
   with self.subTest(url=url),self.assertRaises(ValueError):notifications.validate({'delivery':{'mode':'discord','discordUrl':url}}, {})
 def test_both_requires_email_and_discord(self):
  for missing in ['smtpHost','sender','recipient','discordUrl']:
   config=self.config();del config[missing]
   with self.subTest(missing=missing),self.assertRaises(ValueError):notifications.validate({'delivery':config},{})
 def test_discord_payload_limits_mentions_and_waits_for_acceptance(self):
  opener=MagicMock();opener.open.return_value.__enter__.return_value.status=200
  with patch.object(notifications,'build_opener',return_value=opener):notifications.send({**self.config(),'mode':'discord'},'Alert @everyone','x'*3000)
  req=opener.open.call_args.args[0];body=json.loads(req.data);self.assertEqual(len(body['content']),2000);self.assertEqual(body['allowed_mentions'],{'parse':[]});self.assertTrue(req.full_url.endswith('?wait=true'))
 def test_apprise_destinations_are_independent_and_hidden(self):
  notifier=MagicMock();notifier.add.return_value=True;notifier.notify.return_value=True;module=types.SimpleNamespace(Apprise=MagicMock(return_value=notifier))
  with patch.dict(sys.modules,{'apprise':module}):
   settings=notifications.validate({'delivery':{'mode':'apprise','appriseUrls':'tgram://token/chat\nslack://token/path'}},{})
   self.assertEqual(notifications.channels(settings['delivery']),['apprise:0','apprise:1']);self.assertNotIn('tgram://',json.dumps(notifications.public(settings)))
   notifier.reset_mock();notifications.send({**settings['delivery'],'mode':'apprise:1'},'Subject','Message');notifier.add.assert_called_once_with('slack://token/path');notifier.notify.assert_called_once()
 def test_apprise_invalid_url_rejected(self):
  notifier=MagicMock();notifier.add.return_value=False
  with patch.dict(sys.modules,{'apprise':types.SimpleNamespace(Apprise=lambda:notifier)}),self.assertRaises(ValueError):notifications.validate({'delivery':{'mode':'apprise','appriseUrls':'invalid://secret'}},{})
 def test_smtp_starttls_and_ssl(self):
  for port in [587,465]:
   smtp=MagicMock()
   with patch.object(notifications.smtplib,'SMTP',return_value=smtp) as plain,patch.object(notifications.smtplib,'SMTP_SSL',return_value=smtp) as tls:
    notifications.send({**self.config(),'mode':'email','smtpPort':port},'Alert','Low toner')
   self.assertEqual(smtp.send_message.call_count,1)
   if port==587:plain.assert_called_once();smtp.starttls.assert_called_once();tls.assert_not_called()
   else:tls.assert_called_once();plain.assert_not_called();smtp.starttls.assert_not_called()
