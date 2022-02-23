from Satellite import *
from datetime import datetime

def test_ILikeToWatch():
    tle = """REDACT
    1 13337U 98067A   20087.38052801 -.00000452  00000-0  00000+0 0  9995
    2 13337  51.6460  33.2488 0005270  61.9928  83.3154 15.48919755219337
    """
    time = datetime(2020, 3, 26, 21, 52, 55)
    testSat = Satellite.fromTLE(tle, time)
    lat, long, elev = testSat.Orbit.geocentricCoords


    #print(testSat.__dict__["Orbit"].__dict__)
    #print(testSat.Orbit.semi_major_axis)
    #print(testSat.Orbit.semi_major_axis)
    print(testSat.Orbit.geocentricCoords)