from poliastro.twobody import Orbit, angles
from astropy import units as u
import numpy as np

e = 0.8898246770000006*u.one
M = 0.1621535087*u.deg

if e < 1: 
    M = (M + np.pi * u.rad) % (2 * np.pi * u.rad) - np.pi * u.rad 
    nu = angles.E_to_nu(angles.M_to_E(M, e), e) 
elif e == 1: 
    nu = angles.D_to_nu(angles.M_to_D(M)) 
else: 
    nu = angles.F_to_nu(angles.M_to_F(M, e), e) 

print(nu)