# Quals Challenge: I Like to Watch
This expects challengers to use Google Earth (Pro) to connect to a webserver to point at a specific view of a landmark. It seems Google earth bounds the view angle to a different range of angles than expected in some cases, curl can be used to work around that which is how the solver approaches it. 

## Input
(1) two-line element (TLE) of satellite in orbit (2) the long and lat and altitude of an object on earths surface 

## Output
determine the correct (lat, long, range, azimuth, altitude) to point the satellite at a specific lat/long/alt on the surface of earth


# Quals Challenge: Attitude Adjustment
This challenge provides the user a list of boresight reference 3d vectors and the corresponding catalog reference vectors, this is essentially a matrix alg challenge. The goal of the challenge is provide the attitude of the boresight from this pairing of vectors.

## Input
Set of boresight reference 3d vectors as a tuple of floats, as starting position, another group of 3d vectors as end position

## output
Quaternion/attitude change to aim starting point at ending point
