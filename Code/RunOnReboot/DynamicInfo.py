#! /usr/bin/env python

from requirementSniffThread import requirementSniffThread
import IPLayerAddressing
import threading
from scapy.all import *
import sys
# import crypt
import cryptography


# While running on Kali, make INTERFACE as eth0
# While running on Pi, make INTERFACE as wlan0
INTERFACE = "eth0"

def dynamicInfo():

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

if __name__=='__main__':
    print(dynamicInfo())
    
