#! /usr/bin/env python

import json

def getManufaturerInfo(revision, filename='/home/pi/GSA/RunOnReboot/ModelToManufacturer.json'):
   
   try:
       f = open(filename, 'rb')
   except OSError as err:
       print("OS error: {0}".format(err))
       return False
   
   with f:
       return(json.load(f)[revision])

if __name__ == "__main__":
    import sys
    revision = sys.argv[1]
    manufature_details = getManufaturerInfo(revision)
    if manufature_details:        
        print(manufature_details)
        sys.exit(0)
    else:
        print('Error')
        sys.exit(1)
    
    