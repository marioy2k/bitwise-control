"""Opt-in notification delivery; secrets never appear in public settings."""
import json,smtplib,ssl
from email.message import EmailMessage
from urllib.parse import urlsplit
from urllib.request import Request,build_opener,HTTPSHandler
from adapters import NoRedirect
DEFAULT_RULES={'cpu':90,'memory':90,'disk':90,'temperature':70,'offlineSeconds':180}
SECRETS={'smtpPassword','webhookUrl','webhookToken'}

def validate(body,previous):
 out={'rules':{},'delivery':{}}
 rules=body.get('rules',{})
 for key,default in DEFAULT_RULES.items():
  value=rules.get(key,default)
  if type(value)!=int or not 0<=value<=(3600 if key=='offlineSeconds' else 200):raise ValueError('Invalid monitoring rule: '+key)
  if key=='offlineSeconds' and value<60:raise ValueError('Missing-report timeout must be at least 60 seconds.')
  out['rules'][key]=value
 delivery=body.get('delivery',{});mode=delivery.get('mode','none')
 if mode not in ('none','email','webhook'):raise ValueError('Choose disabled, email, or webhook notifications.')
 for key in ['mode','smtpHost','smtpPort','smtpUser','smtpPassword','sender','recipient','webhookUrl','webhookToken']:
  value=delivery.get(key)
  if key in SECRETS and not value:value=previous.get('delivery',{}).get(key,'')
  if value is not None:
   if key!='smtpPort' and (not isinstance(value,str) or len(value)>4096 or '\n' in value or '\r' in value):raise ValueError('Invalid notification setting: '+key)
   out['delivery'][key]=value
 out['delivery']['mode']=mode
 if mode=='email':
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
 return out

def public(settings):
 delivery=settings.get('delivery',{})
 return {'rules':settings.get('rules',DEFAULT_RULES),'delivery':{**{k:v for k,v in delivery.items() if k not in SECRETS},'credentialsConfigured':any(delivery.get(k) for k in SECRETS)}}

def send(config,subject,message):
 mode=config.get('mode','none')
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
