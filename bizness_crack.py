#!/usr/bin/env python3

import sys
import base64
import hashlib


def generateHash(hash_type, salt, value):
    hash_object = hashlib.new(hash_type)
    hash_object.update(salt.encode())
    hash_object.update(value.encode())
    hashed_bytes = hash_object.digest()
    hash = f"${hash_type}${salt}${base64.urlsafe_b64encode(hashed_bytes).decode()}"

    return hash


hash_type = "SHA1"  # SHA doesn't exist, but SHA1 does
salt = "d"
# the original hash found on the box isn't divisible by 4
# so we're manually adding an '=' at the end
needle = "$SHA1$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I="

if len(sys.argv) < 2:
    print("[!] Usage: ./bizness_crack.py <path_to_rockyou.txt>", end="\n\n")
    exit(0)

with open(sys.argv[1], "r", encoding="latin-1") as pwd_list:
    print("[!] Cracking...")
    for pwd in pwd_list:
        password = pwd.strip()
        hash = generateHash(hash_type, salt, password)

        if hash == needle:
            print("[+] Found password: ", password)
            exit(0)
