#!/usr/bin/env python3

from pwn import *

#exe = ELF("./know_your_mem")

#context.binary = exe


def conn():
        return remote("54.187.236.100", 4669)


def main():
    r = conn()

    # good luck pwning :)

    with open("shellcode.bin.pkt", "rb") as f:
        data = f.read()

    r.send(data)


    r.interactive()


if __name__ == "__main__":
    main()
