from pwn import *

hostname = "sunfun.satellitesabove.me"
port = 5300
ticket = b"ticket{whiskey282757juliet3:GNAXVgxmXWtXp746aE8ID1UukVlTG7JGgsmQadm7qJUNelwqe1wYPAHZ14rwv6SaMg}"

degreesOff=180.0
bestDegreesOff = 180.0

#for qX in range(-120, 180):
qX=-120
for qY in range(650, 651):
    for qZ in range(-1000, -999):
        for qW in range(680, 1500):

            io = remote(hostname, port)
            io.recvuntil(b"Ticket please")
            io.sendline(ticket)

            io.recvuntil(b"Qx = ")
            io.sendline(str(qX))

            io.recvuntil(b"Qy = ")
            io.sendline(str(qY))

            io.recvuntil(b"Qz = ")
            io.sendline(str(qZ))

            io.recvuntil(b"Qw = ")
            io.sendline(str(qW))

            io.recvuntil(b"Quaternion normalized to: ")

            quatS = io.recvlineS()
            quatS = quatS.strip("")
            quatS = quatS.strip("[")
            quatS = quatS.strip("]")
            quat = quatS.split()
            if len(quat) > 4:
                del quat[4]
            quat[3] = quat[3].strip("]")
            print(quat)
            quat = list(map(float, quat))
            #print(quat)

            line = io.recvlineS().strip("\n")
            line = line.split()
            newDegreesOff = float(line[5])
            #print(newDegreesOff)

            if newDegreesOff < degreesOff:
                degreesOff = newDegreesOff
            
            with open("output.txt", "a+") as writeFile:
                writeFile.write(f"qX: {qX}\t qY: {qY}\t qZ: {qZ}\t qW: {qW}\n")
                writeFile.write(f"Normalized Quaternion = {quat}\n")
                writeFile.write(f"Current DeggresOff: {newDegreesOff}\t Best: {degreesOff}\n\n")

            io.close()
    