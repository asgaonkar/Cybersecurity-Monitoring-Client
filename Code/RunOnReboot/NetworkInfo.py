#! /usr/bin/env python

import Interfaces
import MAC

def getMAC():
    MAC_Address = {}
    interfaces = Interfaces.getInterfaces()
    for interface in interfaces:
        MAC_Address[interface] = MAC.getMAC(interfaces[interface])
    return MAC_Address

if __name__=='__main__':
    import sys
    MACInfo = getMAC()
    if MACInfo:
        print(MACInfo)
        sys.exit(0)
    else:
        sys.exit(1)
