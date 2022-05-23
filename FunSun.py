from skyfield.api import EarthSatellite, load as load2, Topos
from pandas import value_counts
from pwn import *
from datetime import *
from Utilities import *

hostname = "sunfun.satellitesabove.me"
port = 5300
ticket = b"ticket{whiskey282757juliet3:GNAXVgxmXWtXp746aE8ID1UukVlTG7JGgsmQadm7qJUNelwqe1wYPAHZ14rwv6SaMg}"
    
io = remote(hostname, port)
io.recvuntil(b"Ticket please")
#io.sendline(ticket)

tle = """SunFunSat
    1 70003F 22700A   22140.00000000  .00000000  00000-0  00000-0 0  100
    2 70003  70.9464 334.7550 0003504  0.0012  16.1023 13.17057395  100
    """

time = datetime(2020, 3, 26, 21, 52, 55, tzinfo=timezone.utc)
ts = load2.timescale()
t = ts.from_datetime(time)

name, first_line, second_line = validateTLE(tle)
testSat = EarthSatellite(first_line, second_line, name, ts)
#print(name)
#print(first_line)
#print(second_line)

io.interactive()