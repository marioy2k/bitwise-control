"""Opt-in notification delivery; secrets never appear in public settings."""
import json,smtplib,ssl,re,logging
from email.message import EmailMessage
from urllib.parse import urlsplit
from urllib.request import Request,build_opener,HTTPSHandler
from adapters import NoRedirect
DEFAULT_RULES={'cpu':90,'memory':90,'disk':90,'temperature':70,'offlineSeconds':180}
SECRETS={'smtpPassword','webhookUrl','webhookToken','discordUrl','appriseUrls'}

def validate(body,previous):
 out={'rules':{},'delivery':{}}
 rules=body.get('rules',{})
 for key,default in DEFAULT_RULES.items():
  value=rules.get(key,default)
  if type(value)!=int or not 0<=value<=(3600 if key=='offlineSeconds' else 200):raise ValueError('Invalid monitoring rule: '+key)
  if key=='offlineSeconds' and value<60:raise ValueError('Missing-report timeout must be at least 60 seconds.')
  out['rules'][key]=value
 delivery=body.get('delivery',{});mode=delivery.get('mode','none')
 if mode not in ('none','email','webhook','discord','both','apprise'):raise ValueError('Choose disabled, email, Discord, both, or webhook notifications.')
 for key in ['mode','smtpHost','smtpPort','smtpUser','smtpPassword','sender','recipient','webhookUrl','webhookToken','discordUrl','appriseUrls']:
  value=delivery.get(key)
  if key in SECRETS and not value:value=previous.get('delivery',{}).get(key,'')
  if value is not None:
   if key!='smtpPort' and (not isinstance(value,str) or len(value)>4096 or ('\n' in value and key!='appriseUrls') or '\r' in value):raise ValueError('Invalid notification setting: '+key)
   out['delivery'][key]=value
 for key in ('reminderMinutes','summaryMinutes'):
  value=delivery.get(key,previous.get('delivery',{}).get(key,0))
  if type(value)!=int or value not in (0,5,10):raise ValueError('Choose disabled, 5 minutes, or 10 minutes for '+key)
  out['delivery'][key]=value
 out['delivery']['mode']=mode
 if mode in ('email','both'):
  d=out['delivery'];port=d.get('smtpPort',587)
  if type(port)!=int or not 1<=port<=65535:raise ValueError('Invalid SMTP port.')
  d['smtpPort']=port
  for key in ['smtpHost','sender','recipient']:
   if not d.get(key):raise ValueError('Required email setting: '+key)
  for key in ['sender','recipient']:
   if '@' not in d[key] or any(ch in d[key] for ch in '<>,; '):raise ValueError('Enter a single valid '+key+' email address.')
 if mode=='webhook':
  u=urlsplit(out['delivery'].get('webhookUrl',''))
  if u.scheme!='https' or not u.hostname or u.username or u.password:raise ValueError('Use an HTTPS webhook URL without embedded credentials.')
 if mode in ('discord','both'):
  u=urlsplit(out['delivery'].get('discordUrl',''))
  if u.scheme!='https' or u.hostname!='discord.com' or u.port not in (None,443) or u.username or u.password or u.query or u.fragment or not re.fullmatch(r'/api(?:/v[0-9]+)?/webhooks/[0-9]+/[A-Za-z0-9_.-]+',u.path):raise ValueError('Enter a Discord webhook URL from your channel integration settings.')
 if mode=='apprise':
  urls=[url.strip() for url in out['delivery'].get('appriseUrls','').splitlines() if url.strip()]
  if not 1<=len(urls)<=20:raise ValueError('Enter 1–20 Apprise service URLs, one per line.')
  try:
   import apprise
  except ImportError:raise ValueError('Install the apprise package on the monitoring server.')
  logging.getLogger('apprise').disabled=True
  for url in urls:
   notifier=apprise.Apprise()
   if not notifier.add(url):raise ValueError('An Apprise URL is invalid or unsupported by the installed library.')
  out['delivery']['appriseUrls']='\n'.join(urls)
 return out

def public(settings):
 delivery=settings.get('delivery',{})
 return {'rules':settings.get('rules',DEFAULT_RULES),'delivery':{**{k:v for k,v in delivery.items() if k not in SECRETS},'credentialsConfigured':any(delivery.get(k) for k in SECRETS)}}

def channels(config):
 mode=config.get('mode','none')
 if mode=='apprise':return ['apprise:'+str(i) for i,url in enumerate(config.get('appriseUrls','').splitlines()) if url.strip()]
 return ['email','discord'] if mode=='both' else ([] if mode=='none' else [mode])

def send(config,subject,message):
 mode=config.get('mode','none')
 if mode=='both':raise ValueError('Queue email and Discord independently.')
 if mode=='none':return
 if mode=='email':
  msg=EmailMessage();msg['From']=config['sender'];msg['To']=config['recipient'];msg['Subject']=subject;msg.set_content(message)
  context=ssl.create_default_context();port=config.get('smtpPort',587)
  client=smtplib.SMTP_SSL(config['smtpHost'],port,timeout=15,context=context) if port==465 else smtplib.SMTP(config['smtpHost'],port,timeout=15)
  with client:
   if port!=465:client.starttls(context=context)
   if config.get('smtpUser'):client.login(config['smtpUser'],config.get('smtpPassword',''))
   client.send_message(msg)
 if mode=='webhook':
  # Generic JSON with common text/content fields for webhook receivers.
  body={'subject':subject,'message':message,'text':subject+'\n'+message,'content':subject+'\n'+message}
  headers={'Content-Type':'application/json'}
  if config.get('webhookToken'):headers['Authorization']='Bearer '+config['webhookToken']
  request=Request(config['webhookUrl'],data=json.dumps(body).encode(),headers=headers)
  with build_opener(NoRedirect(),HTTPSHandler(context=ssl.create_default_context())).open(request,timeout=15) as response:
   if not 200<=response.status<300:raise ValueError('Webhook rejected the notification.')

 if mode=='discord':
  # Explicit content limit and disabled mentions for names supplied by inventory.
  body={'content':(subject+'\n'+message)[:2000],'allowed_mentions':{'parse':[]}}
  request=Request(config['discordUrl']+'?wait=true',data=json.dumps(body).encode(),headers={'Content-Type':'application/json','User-Agent':'BitwiseControl/1.0'})
  with build_opener(NoRedirect(),HTTPSHandler(context=ssl.create_default_context())).open(request,timeout=15) as response:
   if not 200<=response.status<300:raise ValueError('Discord rejected the notification.')

 if mode.startswith('apprise:'):
  import apprise
  logging.getLogger('apprise').disabled=True
  urls=[url for url in config.get('appriseUrls','').splitlines() if url.strip()];index=int(mode.split(':',1)[1]);notifier=apprise.Apprise()
  if not 0<=index<len(urls) or not notifier.add(urls[index]):raise ValueError('Notification provider configuration is unavailable.')
  if not notifier.notify(title=subject,body=message):raise ValueError('Notification provider rejected the message.')
