from pwn import *

hostname = "black_hole.satellitesabove.me"
port = 5300
ticket = b"ticket{foxtrot327531bravo3:GCDGecW5cGnkx0pSqZ_uOF_xEBAVHkqQaItCa7rRzn-ThP6CrrEiWw_2woF83WIy_Q}"
    
io = remote(hostname, port)
io.recvuntil(b"Ticket please")
io.sendline(ticket)
#io.recvuntil(b"CMD>")
#io.sendline(b"TAKE_IMG")
#output = io.recvlineS()
#print(output)
#io.sendline(b"DEST_FILENAME")
#output = io.recvlineS()
#print(output)
io.interactive()