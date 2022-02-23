from Orbit import *

# All units are in kilometers, seconds, or degrees unless otherwise stated.

class Satellite:
    """Default Constructor"""
    def __init__(self, orbit=None, attitude=None, propulsion=None, name=None, mass=0.0): # Default values so we can create a satellite in an orbit where we don't care about attitude or propulsion
        self.Orbit = orbit
        self.Attitude = attitude
        self.Propulsion = propulsion
        self.name = name
        self.mass = mass

    @classmethod
    def fromTLE(cls, tle, time=None):
        """Construct a Satellite from a TLE"""
        orbit = Orbit.fromTLE(tle, time)
        name = tle.strip().splitlines()[0]
        satellite = cls(orbit=orbit, name=name)
        return satellite

    def calcGravitationalConstant(self, mass):
        # Math to calculate the gravitational constant for a given body
        gravitationalConstant = 0.0
        return gravitationalConstant

    def manuever(self, newOrbit):
        # Calculate deltaV, burnStart, and burnTime to reach newOrbit from current self.orbit, self.attitude, and self.propulsion
        deltaV = 0.0
        burnStart = None
        burnEnd = None
        man = Manuever(deltaV, burnStart, burnEnd)
        return man

class Attitude:
    """Default Constructor"""
    def __init__(self, quaternion=[0.0, 0.0, 0.0, 0.0]):                                                      # Default values so we can create a satellite in an orbit where we don't care about attitude
        self.quaternion = quaternion

class Manuever:                                                                                               # We can maybe do without this class, but it might be useful?
    """Default Constructor"""
    def __init__(self, deltaV, burnStart=None, burnEnd=None):
        self.deltaV = deltaV
        self.burnStart = burnStart
        self.burnEnd = burnEnd