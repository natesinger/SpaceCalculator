from orbital import earth, KeplerianElements, utilities
from datetime import datetime, timezone
from pytwobodyorbit import lambert
from astropy.time import Time
from pymap3d import aer2eci
from math import degrees
from pwn import remote


earthGM = 3.986004418e14         # m**3/s**-2


def read_radar_data(file):
    pulses = []
    with open(file) as f:
        line = f.readline()
        count = 0
        while line:
            if count > 0:                                                   # Skip the column headers
                pulse = line.strip().split()
                t = datetime.strptime(pulse[0], '%Y-%m-%d-%H:%M:%S.%f-%Z')
                t = t.replace(tzinfo=timezone.utc)
                pulse[0] = t
                pulse[1]= float(pulse[1])
                pulse[2]= float(pulse[2])
                pulse[3]= float(pulse[3])
                pulses.append(pulse)
            line = f.readline()
            count += 1
    return pulses


pulses = read_radar_data("radar_data.txt")                                               # Parse the pulse data
lat, long, alt = 8.7256, 167.715, 35                                                          # Given radar location

# PyMap3d here
startTime, az, el, distance = pulses[0][0], pulses[0][1], pulses[0][2], pulses[0][3]*1000     # Unwrapping the data from just the first pulse
startX, startY, startZ = aer2eci(az, el, distance, lat, long, alt, startTime, deg=True)
startPos = [startX, startY, startZ]

finalTime, az, el, distance = pulses[-1][0], pulses[-1][1], pulses[-1][2], pulses[-1][3]*1000 # Unwrapping the data from just the last pulse
finalX, finalY, finalZ = aer2eci(az, el, distance, lat, long, alt, finalTime, deg=True)
finalPos = [finalX, finalY, finalZ]

# PyTwoBodyOrbit here
timeDifference = finalTime-startTime                                                          # Total time between first and last pulses
startVel, finalVel = lambert(startPos, finalPos, timeDifference.seconds, mu=earthGM)          # Solve for the velocity at the first and last pulses

# OrbitalPy and AstroPy here
pos = utilities.Position(x=finalPos[0], y=finalPos[1], z=finalPos[2])                                         # Just converting to OrbitalPy Class
vel = utilities.Velocity(x=finalVel[0], y=finalVel[1], z=finalVel[2])                                         # Just converting to OrbitalPy Class
orbit = KeplerianElements.from_state_vector(pos, vel, earth, Time(finalTime, format='datetime', scale='utc')) # Solving for Keplerian Elements

# Converting into the requested units of measurement
elements = [
    orbit.a / 1000,         # semi-major axis (m -> km) 
    orbit.e,                # eccentricity (dimensionless)
    degrees(orbit.i),       # inclination (radians -> degrees)
    degrees(orbit.raan),    # RAAN (radians -> degrees)
    degrees(orbit.arg_pe),  # argument of perigee (radians -> degrees)
    degrees(orbit.f),       # true anomaly (radians -> degrees)
]

print(elements)

# Connect and submit answers.
#io = remote('moon-virus.satellitesabove.me', 5021)                                    
#io.recv()
#io.sendline(str(elements[0]).encode("utf-8"))
#io.sendline(str(elements[1]).encode("utf-8"))
#io.sendline(str(elements[2]).encode("utf-8"))
#io.sendline(str(elements[3]).encode("utf-8"))
#io.sendline(str(elements[4]).encode("utf-8"))
#io.sendline(str(elements[5]).encode("utf-8"))
#io.interactive()