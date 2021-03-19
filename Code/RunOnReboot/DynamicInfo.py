#! /usr/bin/env python

import IPLayerAddressing

INTERFACE = "wlan0"

def dynamicInfo():

    dynamicInformation = {}

    dynamicInformation['IP_Addressing'] = IPLayerAddressing.getIPLayerAddressingParameters(INTERFACE)

    return dynamicInformation

if __name__=='__main__':
    print(dynamicInfo())
    
