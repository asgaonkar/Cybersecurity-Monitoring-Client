#! /usr/bin/env python

from collections import defaultdict

def getCPUInfo():
    cpuinfo = defaultdict(list)
    fname = '/proc/cpuinfo'
    try:
        f = open(fname, 'rb')
    except OSError as err:
        print("OS error: {0}".format(err))
        return False
    
    
    with f:
        for line in f:
            line = line.rstrip('\n')
            if line:
                label = line.split(':')[0].strip()
                value = line.split(':')[1].strip()
                if label in cpuinfo:
                    cpuinfo[label].append(value)
                else:
                    cpuinfo[label] = [value]
    return cpuinfo    

if __name__=='__main__':
    import sys
    cpuInfo = getCPUInfo()
    if cpuInfo:
        print(cpuInfo)
        sys.exit(0)
    else:
        sys.exit(1)
    