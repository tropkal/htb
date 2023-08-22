import websocket
import sys
import json

ws_host = "ws://ws.qreader.htb:5789"
input = sys.argv[1]
#payload = '{"version":' + '"' + input + '"'  + '}'
payload = '{"version":"%s"}' % input

ws = websocket.create_connection(ws_host + "/version")
payload = payload.replace("'", '"')
ws.send(payload)

while True:
    print(ws.recv())
