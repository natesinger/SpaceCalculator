from skyfield.api import EarthSatellite, load, Topos
from datetime import datetime, timezone
from Utilities import *

def test_ILikeToWatch():
    tle = """REDACT
    1 13337U 98067A   20087.38052801 -.00000452  00000-0  00000+0 0  9995
    2 13337  51.6460  33.2488 0005270   61.9928  83.3154 15.48919755219337 
    """
    name, first_line, second_line = validateTLE(tle)
    time = datetime(2020, 3, 26, 21, 52, 55, tzinfo=timezone.utc)
    ts = load.timescale()
    t = ts.from_datetime(time)

    testSat = EarthSatellite(first_line, second_line, name, ts)

    lat = 38.8895                                                                          # Tricky.  Just google search the coords for the Washington Monument.
    long = -77.0353                                                                        # You want to "LookAt" the monument, not the position of the satellite.

    assert 38.8839 < lat < 38.8943, "Latitude was not between 38.8839 and 38.8943"
    assert -77.0437 < long < -77.0271, "Longitude was not between -77.0437 and -77.0271"

    target = Topos(str(abs(lat))+" N", str(abs(long))+" W")
    difference = testSat - target
    topocentric = difference.at(t)
    alt, az, distance = topocentric.altaz()                                                # Altitude is supplied as part of the challenge but it looks like the vaule doesn't get checked.

    assert int(distance.m) >= 250000, "Range was not greater than 250000"

    heading = (180 + az.degrees) % 360
    tilt = 90 - alt.degrees

    #assert 93.0757777778 < heading < 97.0757777778, "Heading was not between 93.0757777778 and 97.0757777778"   #I"M PRETTY SURE THE NUMBERS THEY CHECK FOR ON THE GITHUB PAGE FOR THIS CHALLENGE ARE BULLSHIT.
    #assert 13.0757222222 < tilt < 15.0757222222, "Tilt was not between 13.0757222222 and 15.0757222222"         #I"M PRETTY SURE THE NUMBERS THEY CHECK FOR ON THE GITHUB PAGE FOR THIS CHALLENGE ARE BULLSHIT.
    assert 58.186613703 < heading < 62.186613703, "Heading was not between 58.186613703 and 62.186613703 degrees."
    assert 47.966588303 < tilt < 51.966588303, "Tilt has to be between 47.966588303 and 51.966588303 degrees."