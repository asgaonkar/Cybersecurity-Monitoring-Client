from requirementSniffThread import requirementSniffThread
import IPLayerAddressing
import threading
from scapy.all import *
import sys
import cryptography
import ManufatcurerInfo
import CPUInfo
import NetworkInfo
import OSInfo

# While running on Kali, make INTERFACE as eth0
# While running on Pi, make INTERFACE as wlan0
INTERFACE = "eth0"

def getDynamicInfo():

    dynamicInformation = {}

    dynamicInformation['IP_Addressing'] = IPLayerAddressing.getIPLayerAddressingParameters(INTERFACE)    
    
    # Create a thread for each sniff function call     
    # ICMPThread = requirementSniffThread("ICMP-Thread","icmp","icmp",INTERFACE)     
    # TCPThread = requirementSniffThread("TCP-Thread","tcp","tcp",INTERFACE) 
    # TLSThread = requirementSniffThread("TLS-Thread","tls","tcp",INTERFACE)    
    # DNSThread = requirementSniffThread("DNS-Thread","dns","dns",INTERFACE)
    ScapyThread = requirementSniffThread("Scapy-Thread","Combined","",INTERFACE)
    sniffThreads = [ScapyThread]

    # Start new Threads
    for thread in sniffThreads:
        thread.start()

    try:
        while True:            
            pass
    except KeyboardInterrupt as e:
        print("Exiting Main Thread")
        for thread in sniffThreads:
            thread.terminate()
    finally:
        for thread in sniffThreads:
            thread.terminate()

    # Wait for actual termination (if needed)  
    for thread in sniffThreads:
        if thread.is_alive():
            thread.join()



    return dynamicInformation

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
        sys.exit()        
    finally:      
        return staticInformation
    return staticInformation

if __name__=='__main__':
    # Start StaticClient
    # Start DynamicClient
    staticInformation = getStaticInfo()
    print("Static Information: ", staticInformation)
    dynamicInformation =  getDynamicInfo()
    print("Dynamic Information (Static Part): ", dynamicInformation)
    
