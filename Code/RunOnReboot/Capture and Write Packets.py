#!/usr/bin/python

import threading
import time
from scapy.all import *


exitFlag = 0

class myThread (threading.Thread):
   
   def __init__(self, name, protocol, count):
       threading.Thread.__init__(self)
       self.protocol = protocol
       self.count = count
       self.name = name

   def run(self):
       print("Starting " + self.name)
       sniff(count=self.count, filter='{}'.format(self.protocol), prn=write_to_file)
       print("Exiting " + self.name)       

def write_to_file(pkt):
    wrpcap('filtered.pcap', pkt, append=True)


   

# Create new threads
thread1 = myThread("Thread-1", "arp", 20)
thread2 = myThread("Thread-2", "icmp", 20)

# Start new Threads
thread1.start()
time.sleep(1)
thread2.start()

print("Exiting Main Thread")

