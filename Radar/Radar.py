from numpy import linalg, array, cross, dot, arccos, pi
from datetime import datetime, timezone
from skyfield import api, units
from pwn import *

earthGM = 3.986004418e5                                                     # Km**3/s**2

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

def PosTimeToKepler(posTime):
    assert isinstance(posTime[6], datetime), "posTime[6] is not a valid datetime object"
    t0 = posTime[6]
    
    r_ = array(posTime[0:3])
    v_ = array(posTime[3:6])

    r = linalg.norm(r_)
    
    h_ = cross(r_,v_)
    h = linalg.norm(h_)
    e_ = cross(v_,h_)/earthGM - r_/r
    e = linalg.norm(e_)

    p = h*h/earthGM

    a = p /(1-e*e)
    a = linalg.norm(a)

    i = arccos(h_[2]/h)

    omega=0
    n_ = [-h_[1],h_[0],0]
    n = linalg.norm(n_)
    if n_[1] >= 0:
        omega = arccos(n_[0]/n)
    if n_[1] < 0:
        omega = 2*pi - arccos(n_[0]/n)

    ω = arccos(dot(n_,e_) / (n*e))
    if e_[2] < 0:
        ω = 2*pi - ω
        
    
    υ = arccos(dot(e_,r_)/(e*r))
    if dot(r_,v_) < 0:
        υ = 2*pi - υ

    # [a(km) e i(rad) Ω(rad) ω(rad) υ(rad)]
    elements = [a, e, i, omega, ω, υ, t0]
    return elements


def KalmanFilter(radarLocation,pulses):

    ts = api.load.timescale()
    t = ts.now()

    # Create an array of measured ICRF positions, z
    i = 0
    z = []
    while i < len(pulses):
        t  = ts.from_datetime(pulses[i][0])
        az = pulses[i][1]
        el = pulses[i][2]
        r  = pulses[i][3] # km

        # Convert AER to ICRF
        relPos = radarLocation.at(t).from_altaz(az_degrees=az, alt_degrees=el, distance=units.Distance(km=r))
        pos = radarLocation.at(t).position.km + relPos.position.km
        
        # Store ICRF positions into the measurement, z, array including time stamps
        z.append([pos[0], pos[1], pos[2], pulses[i][0]])
        i = i+1


    # Kalman Filter
    gain = 0.5 # Gain for x
    i = 0   
    x0 = array([0,0,0,0,0,0])
    x1 = array([0,0,0,0,0,0])
    x0Dot = array([0,0,0,0,0,0])
    orbit = []
    
    while i < len(z):
        # Initial state estimate
        if i == 0:
            dt = (z[1][3] - z[0][3]).total_seconds()
            r0 = array(z[0][0:3])
            r = linalg.norm(r0)
            r1 = array(z[1][0:3])
            v = (r1 - r0)/dt

            x0 = array([
                z[i][0],
                z[i][1],
                z[i][2],
                v[0],
                v[1],
                v[2]
            ])

            x0Dot = array([
                x0[3],
                x0[4],
                x0[5],
                -earthGM*x0[0]/(r*r*r),
                -earthGM*x0[1]/(r*r*r),
                -earthGM*x0[2]/(r*r*r)
            ])

            orbit = PosTimeToKepler([x0[0],x0[1],x0[2],x0[3],x0[4],x0[5],z[i][3]])
            orbit[2] = orbit[2]*180/pi #i
            orbit[3] = orbit[3]*180/pi #RAAN
            orbit[4] = orbit[4]*180/pi #aop
            orbit[5] = orbit[5]*180/pi #true anomaly

        # Kalman filtered states
        else:
            # Predict next state with dynamics
            dt = (z[i][3] - z[i-1][3]).total_seconds()
            x0 = array([
                x0[0]+x0Dot[0]*dt,
                x0[1]+x0Dot[1]*dt,
                x0[2]+x0Dot[2]*dt,
                x0[3]+x0Dot[3]*dt,
                x0[4]+x0Dot[4]*dt,
                x0[5]+x0Dot[5]*dt
            ])
            r = linalg.norm(array(x0[0:3]))
            x0Dot = array([
                x0[3],
                x0[4],
                x0[5],
                -earthGM*x0[0]/(r*r*r),
                -earthGM*x0[1]/(r*r*r),
                -earthGM*x0[2]/(r*r*r)
            ])
            
            # Kalman gain
            gain = 1/(i+1)
            #α = 0.5

            # Estimate next state with Kalman filter
            r0 = array(z[i-1][0:3])
            r = linalg.norm(r0)
            r1 = array(z[i][0:3])
            v = (r1 - r0)/dt

            x1 = array([
                x0[0]+gain*(z[i][0]-x0[0]),
                x0[1]+gain*(z[i][1]-x0[1]),
                x0[2]+gain*(z[i][2]-x0[2]),
                x0[3]+gain*(v[0]-x0[3]),
                x0[4]+gain*(v[1]-x0[4]),
                x0[5]+gain*(v[2]-x0[5])
            ])

            orbit = PosTimeToKepler([x1[0],x1[1],x1[2],x1[3],x1[4],x1[5],z[i][3]])
            orbit[2] = orbit[2]*180/pi #i
            orbit[3] = orbit[3]*180/pi #RAAN
            orbit[4] = orbit[4]*180/pi #aop
            orbit[5] = orbit[5]*180/pi #true anomaly

            # Set state for next iteration
            x0 = x1

        i = i+1

    return orbit

time = datetime(2021, 6, 27, 0, 9, 52, 0, tzinfo=timezone.utc)
radarLocation = api.wgs84.latlon(8.7256, 167.715, 35)
pulses = read_radar_data("radar_data.txt")
orbit = KalmanFilter(radarLocation, pulses)

print(orbit)

#io = remote('moon-virus.satellitesabove.me', 5021)                                    
#io.recv()
#io.sendline(str(orbit[0]).encode("utf-8"))
#io.sendline(str(orbit[1]).encode("utf-8"))
#io.sendline(str(orbit[2]).encode("utf-8"))
#io.sendline(str(orbit[3]).encode("utf-8"))
#io.sendline(str(orbit[4]).encode("utf-8"))
#io.sendline(str(orbit[5]).encode("utf-8"))
#io.interactive()