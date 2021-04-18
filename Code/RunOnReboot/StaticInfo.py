#! /usr/bin/env python

import ManufatcurerInfo
import CPUInfo
import NetworkInfo
import OSInfo

def getStaticInfo():

    staticInformation = {}
    try:
        cpuInfo = CPUInfo.getCPUInfo()
        osInfo = OSInfo.getOSInfo()
        staticInformation["MAC Address"] = NetworkInfo.getMAC()
        staticInformation["Hostname"] = osInfo["Hostname"]
        staticInformation["Serial Number"] = cpuInfo['Serial'][0]
        staticInformation["Hardware"] = cpuInfo['Hardware'][0]
        staticInformation["Manufacturer"] = ManufatcurerInfo.getManufaturerInfo(cpuInfo["Revision"][0])
        staticInformation["OS"] = {}
        staticInformation["OS"]["Name"] = osInfo["NAME"]
        staticInformation["OS"]["Type"] = osInfo["ID_LIKE"]
        staticInformation["OS"]["Version Number"] = osInfo["VERSION_ID"]
        staticInformation["OS"]["Architecture"] = osInfo["Architecture"]
        staticInformation["OS"]["Version"] = osInfo["OS Version"]
        staticInformation["OS"]["Release"] = osInfo["OS Release"]
    except KeyboardInterrupt as e:
        return staticInformation        
    return staticInformation

if __name__=='__main__':
    print(getStaticInfo())
    
