from sgp4.api import SGP4_ERRORS
from math import fmod, atan2
from Constants import *
import numpy as np

class ConvergenceError(Exception):
    pass

def eccentric_anomaly_from_mean(e, M, tolerance=1e-14):
    """Convert mean anomaly to eccentric anomaly.
    Implemented from [A Practical Method for Solving the Kepler Equation][1]
    by Marc A. Murison from the U.S. Naval Observatory
    [1]: http://murison.alpheratz.net/dynamics/twobody/KeplerIterations_summary.pdf
    """
    MAX_ITERATIONS = 100
    Mnorm = fmod(M, 2 * np.pi)
    E0 = M + (-1 / 2 * e ** 3 + e + (e ** 2 + 3 / 2 * np.cos(M) * e ** 3) * np.cos(M)) * np.sin(M)
    dE = tolerance + 1
    count = 0
    while dE > tolerance:
        t1 = np.cos(E0)
        t2 = -1 + e * t1
        t3 = np.sin(E0)
        t4 = e * t3
        t5 = -E0 + t4 + Mnorm
        t6 = t5 / (1 / 2 * t5 * t4 / t2 + t2)
        E = E0 - t5 / ((1 / 2 * t3 - 1 / 6 * t1 * t6) * e * t6 + t2)
        dE = abs(E - E0)
        E0 = E
        count += 1
        if count == MAX_ITERATIONS:
            raise ConvergenceError('Did not converge after {n} iterations. (e={e!r}, M={M!r})'.format(n=MAX_ITERATIONS, e=e, M=M))
    return E

def true_anomaly_from_eccentric(e, E):
    """Convert eccentric anomaly to true anomaly."""
    return 2 * atan2(np.sqrt(1 + e) * np.sin(E / 2), np.sqrt(1 - e) * np.cos(E / 2))

def true_anomaly_from_mean_anomaly(e, M, tolerance=1e-14):
    """Convert mean anomaly to true anomaly."""
    E = eccentric_anomaly_from_mean(e, M, tolerance)
    return true_anomaly_from_eccentric(e, E)

def semi_major_axis_from_mean_motion(mean_motion, k): 
    """Calculate semi-major axis from mean motion."""
    return (k / (mean_motion * np.pi / 43200) ** 2) ** (1/3) / 1000

#def position_and_velocity_TEME_km(self, t):
#        """Return the raw true equator mean equinox (TEME) vectors from SGP4.
#        Returns a tuple of NumPy arrays ``([x y z], [xdot ydot zdot])``
#        expressed in kilometers and kilometers per second.  Note that we
#        assume the TLE epoch to be a UTC date, per AIAA 2006-6753.
#        """
#        sat = self.model
#        jd = t.whole
#        fraction = t.tai_fraction - t._leap_seconds() / DAY_S
#
#        if getattr(jd, 'shape', None):
#            e, r, v = sat.sgp4_array(jd, fraction)
#            messages = [SGP4_ERRORS[error] if error else None for error in e]
#            return r.T, v.T, messages
#        else:
#            error, position, velocity = sat.sgp4(jd, fraction)
#            message = SGP4_ERRORS[error] if error else None
#            return np.array(position), np.array(velocity), message

def geocentric_coords_from_something():
    """Calculate the Geocentric Celestial Reference System (GCRS) coordinates from SOMETHING"""