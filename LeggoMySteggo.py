from pwn import *

hostname = "leggo.satellitesabove.me"
port = 5300
ticket = b"ticket{foxtrot327531bravo3:GCDGecW5cGnkx0pSqZ_uOF_xEBAVHkqQaItCa7rRzn-ThP6CrrEiWw_2woF83WIy_Q}"
    
io = remote(hostname, port)
io.recvuntil(b"Ticket please")
io.sendline(ticket)
io.recvuntil(b"CMD>")
io.sendline(b"PLAYBACK_FILE")
#output = io.recvlineS()
#print(output)
#io.sendline(b"DEST_FILENAME")
#output = io.recvlineS()
#print(output)
#x = "2aa0736e657a05244e0f8a1c10c4492dde39907c032dba9f3527b49873f1d534"
x = (io.readlineS()).strip("\n")
print(x)
x2 = int(x.strip("?"), 16)
x3 = x2 >> 1
print(hex(x3))
io.interactive()