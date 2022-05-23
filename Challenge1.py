from pwn import *
import numpy as np
from astropy.time import Time
from astropy import units as u
from poliastro.twobody import Orbit, angles
from poliastro.bodies import Earth

hostname = "matters_of_state.satellitesabove.me"
port = 5300
ticket = b"ticket{victor234519juliet3:GPaKWC8OIYDU7cP1AT-rDrc02fMDUPsWTqzun-bIQ02UxQawSREtsUiLD4M5VZ-wsw}"
    
io = remote(hostname, port)
io.recvuntil(b"Ticket please")
io.sendline(ticket)
#io.interactive()
io.recvuntil(b"semi-major axis: ")
a = float((io.recvlineS().split()[0]))*u.km
io.recvuntil(b"eccentricity: ")
e = float((io.recvlineS().split()[0]))*u.one
io.recvuntil(b"inclination: ")
i = float((io.recvlineS().split()[0]))*u.deg
io.recvuntil(b"RAAN: ")
RAAN = float((io.recvlineS().split()[0]))*u.deg
io.recvuntil(b"Mean anomaly: ")
M = float((io.recvlineS().split()[0]))*u.deg
io.recvuntil(b"Argument of periapsis: ")
argPe = float((io.recvlineS().split()[0]))*u.deg
t = Time("2022-01-01T00:00:00.000")

if e < 1: 
    M = (M + np.pi * u.rad) % (2 * np.pi * u.rad) - np.pi * u.rad 
    nu = angles.E_to_nu(angles.M_to_E(M, e), e) 
elif e == 1: 
    nu = angles.D_to_nu(angles.M_to_D(M)) 
else: 
    nu = angles.F_to_nu(angles.M_to_F(M, e), e) 

orb=Orbit.from_classical(attractor=Earth, a=a, ecc=e, inc=i, raan=RAAN, argp=argPe, nu=nu, epoch=t)
print(orb.r)
print(orb.v)

pos = b"-13816.24676361,16031.813156,39975.93312529"
vel = b"-3.02029731,-1.49328041,-0.15100103"

print(a)
print(e)
print(i)
print(RAAN)
print(M)
print(argPe)
io.recvuntil(b"Position: X,Y,Z")
io.sendline(pos)
io.recvuntil()

io.interactive()