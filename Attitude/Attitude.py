from scipy.spatial.transform import Rotation
from scipy import signal, misc
import numpy as np
from pwn import *
import rmsd

def compute_matrix(catalog, stars):
    v_ref, v_obs = [], []
    for idx, x, y, z in stars:
        v_ref.append([catalog[idx][0], catalog[idx][1], catalog[idx][2]])
        v_obs.append([x, y, z])

    A = np.array(v_ref)
    B = np.array(v_obs)

    A -= rmsd.centroid(A)
    B -= rmsd.centroid(B)

    R = rmsd.kabsch(A, B)

    sol_dcm = Rotation.from_dcm(R)
    sol = sol_dcm.as_quat()

    return ','.join(str(x) for x in sol)


if __name__ == "__main__":

    # Build list of stars
    catalog = []
    with open("Attitude/test.txt", "r+") as testFile:
        for line in testFile.readlines():
            line = line.strip()
            if len(line):
                catalog.append(list(map(float, line.split(','))))

    io = remote("attitude.satellitesabove.me", 5021)
    io.recvline()   # Skip the header
    io.recvline()   # Skip the header
    
    stars = []
    while True:
        try:
            line = io.recvlineS(keepends=False)
            if "0." in line:    # Just to catch all valid lines, sloppy
                id = int(line.split(' : ')[0].strip())
                r = line.split(' : ')[1].split(',\t')
                x = float(r[0])
                y = float(r[1])
                z = float(r[2])
                stars.append([id, x, y, z])
        except Exception as e:
            print(e)
            break

    sol = compute_matrix(catalog, stars)

    
