from pwn import *

hostname = "HostnameGoesHere"
port = 1234
ticket = b"ticket{ThisIsNSLsTicketForConnectingToChallenges}"
    
io = remote(hostname, port)
io.recvuntil(b"Ticket please")
io.sendline(ticket)
io.interactive()