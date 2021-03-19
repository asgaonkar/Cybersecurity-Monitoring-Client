#! /usr/bin/env python

import os

def getOSInfo(filename='/etc/os-release'):
   
   osInfo = {}
   
   try:
       f = open(filename, 'rb')
   except OSError as err:
       print("OS error: {0}".format(err))
       return False
   
   with f:
       for line in f:
            line = line.rstrip('\n').split('=')
            if line:
                label = line[0].strip()
                value = line[1].strip()
                osInfo[label] = value
       
       osInfo["Name"] = os.uname()[0]
       osInfo["Hostname"] = os.uname()[1]
       osInfo["OS Release"] = os.uname()[2]
       osInfo["OS Version"] = os.uname()[3]
       osInfo["Architecture"] = os.uname()[4]
       
       return(osInfo)

if __name__ == "__main__":        
    import sys
    osInfo = getOSInfo()
    if osInfo:        
        print(osInfo)        
        sys.exit(0)
    else:
        print('Error')
        sys.exit(1)    
