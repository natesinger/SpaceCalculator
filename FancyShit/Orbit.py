from sgp4.api import Satrec
from SpaceMath import *
from Bodies import *
from Utilities import *

# All units are in kilometers, seconds, or degrees unless otherwise stated.

class Orbit:
    """Default Constructor"""
    def __init__(self):
        self.model = Satrec()

    @property
    def semi_major_axis(self):
        return self.model.a
    
    @semi_major_axis.setter
    def semi_major_axis(self, new_val):
        self.model.a = new_val

    @property
    def true_anomaly(self):
        if self._true_anomaly is None:
            self._true_anomaly = true_anomaly_from_mean_anomaly(self.eccentricity, self.mean_motion)
        return self._true_anomaly

    @true_anomaly.setter
    def true_anomaly(self, new_val):
        self._true_anomaly=new_val

    @property
    def geocentricCoords(self, time=None):
        if time is None:
            time=self.time
        if time==self.time:
            if self.geocentricCoords is None:
                self.geocentricCoords = [0,0,0]                            #TODO: Math
            return self.geocentricCoords
        else:
            geocentricCoordsAtTime = [0,0,0]  
            return geocentricCoordsAtTime
        

    @property
    def positionVector(self, time):
        if time == self.time:
            if self._positionVector is None:
                self._positionVector = None                              #TODO: Math
            return self._positionVector
        else:
            positionVectorAtTime = None                                  #TODO: Math
            return positionVectorAtTime

    @property
    def velocityVector(self, time):
        if time == self.time:
            if self._velocityVector is None:
                self._velocityVector = None                              #TODO: Math
            return self._velocityVector
        else:
            velocityVectorAtTime = None                                  #TODO: Math
            return velocityVectorAtTime

    @classmethod
    def fromTLE(cls, tle, time=None):
        """Construct an Orbit from a TLE"""
        name, first_line, second_line = validateTLE(tle)
        satrec = Satrec.twoline2rv(first_line, second_line)

        two_digit_year = satrec.epochyr
        if two_digit_year < 57:
            year = two_digit_year + 2000
        else:
            year = two_digit_year + 1900

        self = cls.__new__(cls)
        self.name = None if name is None else name
        self.model = satrec
        self.epoch = time.utc(year, 1, satrec.epochdays)
        self.target = -100000 - satrec.satnum

        return self 

    @classmethod
    def fromPosAndVelVectors(cls, positionVector, velocityVector, body, t=None):
        # Math to convert stuff 
        semi_major_axis = 0
        eccentricity = 0
        inclination = 0
        longitude_of_ascending_node = 0
        true_anomaly = 0
        body = 0
        time = t
        newOrbit = cls(semi_major_axis, eccentricity, inclination, longitude_of_ascending_node, true_anomaly, body, time)
        return newOrbit

    @classmethod
    def fromPosVectors(cls, positionVectorAtT1, positionVectorAtT2, body, t1=None, t2=None):
        # Math to convert stuff using Lambert's Equations
        semi_major_axis = 0
        eccentricity = 0
        inclination = 0
        longitude_of_ascending_node = 0
        true_anomaly = 0
        body = 0
        time = t2
        newOrbit = cls(Orbit, semi_major_axis, eccentricity, inclination, longitude_of_ascending_node, true_anomaly, body, time)
        return newOrbit

    def calcPositionVector(self):
        # Math to calculate position vector from Kepler elements
        position = [0.0, 0.0, 0.0]
        return position

    def calcVelocityVector(self):
        # Math to calculate velocity vector from Kepler elements
        velocity = [0.0, 0.0, 0.0]
        return velocity
