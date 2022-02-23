from datetime import datetime
from SpaceMath import *
from Bodies import *
from Utilities import *

# All units are in kilometers, seconds, or degrees unless otherwise stated.

class Orbit:
    """Default Constructor"""
    def __init__(self, inclination, longitude_of_ascending_node, eccentricity, semi_major_axis=None, true_anomaly=None, mean_anomaly=None, mean_motion=None, body=Earth, time=datetime.now()):
        self.inclination = inclination
        self.longitude_of_ascending_node = longitude_of_ascending_node
        self.eccentricity = eccentricity
        self.semi_major_axis = semi_major_axis
        self.true_anomaly = true_anomaly
        self.mean_anomaly = mean_anomaly
        self.mean_motion = mean_motion
        self.body=body
        self.time=time

    @property
    def semi_major_axis(self):
        if self._semi_major_axis is None:
            self._semi_major_axis = semi_major_axis_from_mean_motion(self.mean_motion, self.body.k)
        return self._semi_major_axis
    
    @semi_major_axis.setter
    def semi_major_axis(self, new_val):
        self._semi_major_axis=new_val

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
        _, second_line, third_line = validateTLE(tle)

        inclination = float(third_line[8:16])
        longitude_of_ascending_node = float(third_line[17:25])
        eccentricity = float(third_line[26:33])
        argument_of_perigee = float(third_line[34:42])             
        mean_anomaly = float(third_line[43:51]) 
        mean_motion = float(third_line[52:63])   
        revs_at_epoch = third_line[63:68]              
        
        orbit = Orbit(inclination=inclination, longitude_of_ascending_node=longitude_of_ascending_node, eccentricity=eccentricity, mean_anomaly=mean_anomaly, mean_motion=mean_motion, time=time)
        return orbit    

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
