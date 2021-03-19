#! /usr/bin/env python

import os
def getInterfaces():
  # Get name of the interfaces
  interfaces = {}
  try:
    for root,dirs,files in os.walk('/sys/class/net'):
      for dir in dirs:
        if dir[0:3]=='eth':
            interfaces['Ethernet'] = dir
        elif dir[0:4]=='wlan':
            interfaces['Wireless'] = dir
    return interfaces
  except OSError as err:
    print("OS error: {0}".format(err))
    return False

if __name__=='__main__':
    import sys
    interfaces = getInterfaces()
    if interfaces:
        print(interfaces)
        sys.exit(0)
    else:
        sys.exit(1)
        
    