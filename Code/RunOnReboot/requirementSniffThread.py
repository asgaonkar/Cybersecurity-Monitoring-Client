import threading
from scapy.all import *
import cryptography
import logData
import time
import os
from shutil import copyfile
load_layer('tls')
from collections import defaultdict

# -------------------------------------------------------------------------------------------------------

INTERVAL = 0.5

# Thread Class

class requirementSniffThread(threading.Thread):

   def __init__(self, name, protocol, protocolfilter, interface):       
      threading.Thread.__init__(self)
      self._running = True
      self.interface = interface
      self.protocol = protocol      
      self.filter = protocolfilter
      self.name = name      
      self.lastTime = 0      
      self.tcpFilename = 'TCP_Packets.pcap'
      self.tlsFilename = 'TLS_Packets.pcap'
      self.icmpFilename = 'ICMP_Packets.pcap'
      self.dnsFilename = 'DNS_Packets.pcap'           
      self.dnsFileAppend = True
      self.tcpFileAppend = True
      self.icmpFileAppend = True
      self.tlsFileAppend = True      
      self.combinedFilename = 'Combined_Packets.pcap'

    
   def run(self):
       print("Starting " + self.name)          
       sniff(iface=self.interface, filter='{}'.format(self.filter), prn=self.packetHandler, stop_filter=self.checkTermination)
      #  prn=self.functionMapping[self.protocol]
       print("Exiting " + self.name)       
   
   def writeFile(self, filename, packet, protocolAppend):               
      wrpcap(filename, packet, append=protocolAppend)
      if protocolAppend==False:
         protocolAppend = True                   


   def packetHandler(self,packet):
      # self.writeFile(self.combinedFilename, packet, True)      
      if packet.haslayer(TLS) or packet.haslayer(Raw):      
         self.sslPacketpanalyzer(packet)
         self.tcpPacketpanalyzer(packet)
      elif packet.haslayer(TCP):
         self.tcpPacketpanalyzer(packet)
      elif packet.haslayer(ICMP):
         self.icmpPacketpanalyzer(packet)  
      elif packet.haslayer(DNS):
         self.dnsPacketpanalyzer(packet)
      else:         
         self.otherPacketanalyzer(packet)   

   def otherPacketanalyzer(self, packet):
      pass

   def terminate(self): 
      self._running = False                

   def checkTermination(self, packet):
      return not self._running

   def dnsCatchFile(self, filename):
      dnsPackets = rdpcap(filename)
      for packet in dnsPackets:
         print(packet.summary())                  
         DNS_Data = {'QD':defaultdict(list), 'AN':defaultdict(list), 'NS':defaultdict(list)}
         if packet.haslayer(DNS):                        
            for x in packet[DNS].qdcount:
               DNS_Data['QD']['qName'].append(packet[DNS].qd[x].qname)
               DNS_Data['QD']['qType'].append(packet[DNS].qd[x].qtype)
            for x in packet[DNS].ancount:
               DNS_Data['AN']['rrName'].append(packet[DNS].an[x].rrname)
               DNS_Data['AN']['rData'].append(packet[DNS].an[x].rdata)
               DNS_Data['AN']['ttl'].append(packet[DNS].an[x].ttl)
               DNS_Data['AN']['type'].append(packet[DNS].an[x].type)
            for x in packet[DNS].nscount:
               DNS_Data['NS']['rrName'].append(packet[DNS].ns[x].rrname)
               DNS_Data['NS']['rName'].append(packet[DNS].ns[x].rname)
               DNS_Data['NS']['type'].append(packet[DNS].ns[x].type)
               DNS_Data['NS']['mName'].append(packet[DNS].ns[x].mname)
               DNS_Data['NS']['serial'].append(packet[DNS].ns[x].serial)
               DNS_Data['NS']['retry'].append(packet[DNS].ns[x].retry)
               DNS_Data['NS']['expire'].append(packet[DNS].ns[x].expire)
         print(DNS_Data)               
      try:
         os.remove(filename)
      except OSError as e:
         print("Error: %s : %s" % (filename, e.strerror))

   def catchFile(self, filename, protocol):      
      if protocol=='dns':
         self.dnsCatchFile(filename)
      elif protocol=='tcp':
         pass
      elif protocol=='icmp':
         pass
      elif protocol=='tls':
         pass
      else:
         pass

   def dnsPacketpanalyzer(self, packet):
      self.writeFile(self.dnsFilename, packet, self.dnsFileAppend)
      print("DNS")
      currentTime = int(time.time())
      if currentTime>self.lastTime + INTERVAL*60:         
         self.lastTime = currentTime               
         copyfile(self.dnsFilename, self.dnsFilename+'.bak')
         self.dnsFileAppend = False
         t = threading.Thread(target=self.catchFile, args=(self.dnsFilename+'.bak','dns',))
         t.daemon = True
         t.start()
      

   def tcpPacketpanalyzer(self, packet):          
      self.writeFile(self.tcpFilename, packet, self.tcpFileAppend)         
      print("TCP")
      currentTime = int(time.time())
      if currentTime>self.lastTime + INTERVAL*60:
         self.lastTime = currentTime
         copyfile(self.tcpFilename, self.tcpFilename+'.bak')
         self.tcpFileAppend = False
         t = threading.Thread(target=self.catchFile, args=(self.tcpFilename+'.bak','tcp',))
         t.daemon = True
         t.start()
      
      IPVersion = IP if IP in packet else IPv6
      ip_src=packet[IPVersion].src
      ip_dst=packet[IPVersion].dst
      try:
         tcp_sport=packet[TCP].sport
         tcp_dport=packet[TCP].dport                                          
         print("TCP Transaction: {}(:{}) -> {}(:{})".format(ip_src,tcp_sport,ip_dst,tcp_dport))               
      except:
         print("TCP Transaction: {} -> {})".format(ip_src,ip_dst))               

   def icmpPacketpanalyzer(self, packet):      
      try:        
         print("ICMP")         
         self.writeFile(self.icmpFilename,packet,self.icmpFileAppend)   
         currentTime = int(time.time())
         if currentTime>self.lastTime + INTERVAL*60:
            self.lastTime = currentTime
            copyfile(self.icmpFilename, self.icmpFilename+'.bak')
            self.icmpFileAppend = False
            t = threading.Thread(target=self.catchFile, args=(self.icmpFilename+'.bak','icmp',))
            t.daemon = True
            t.start()
         ICMP_info = packet[ICMP]
         ICMP_type = packet[ICMP].type
         ICMP_code = packet[ICMP].code
         ICMP_bytes = bytes(ICMP_info)
         IPVersion = IP if IP in packet else IPv6        
         ip_src=packet[IPVersion].src
         ip_dst=packet[IPVersion].dst        
         print("--------------------------")
         # print("Counter: ",counter)        
         print("ICMP Transaction: {} -> {}".format(ip_src,ip_dst))
         print("ICMP Type: ",ICMP_type)
         print("ICMP Code: ",ICMP_code)                
         print("\n")
      except:
         # unattended.append(counter)
         pass
      # counter+=1
   
   def sslPacketpanalyzer(self, packet):            
      if TLS in packet or Raw in packet:           
         try:
            TLS_info = ''
            if TLS in packet:
               # print(packet[TLS])
               TLS_info = packet[TLS]
            elif TCP in packet and Raw in packet:
               # print(TLS(packet.load))
               TLS_info = TLS(packet.load)                
            if TLS_info:
               self.writeFile(self.tlsFilename, packet, self.tlsFileAppend)
               print("TLS/SSL")
               currentTime = int(time.time())
               if currentTime>self.lastTime + INTERVAL*60:
                  self.lastTime = currentTime
                  copyfile(self.tlsFilename, self.tlsFilename+'.bak')
                  self.icmpFileAppend = False
                  t = threading.Thread(target=self.catchFile, args=(self.tlsFilename+'.bak','tls',))
                  t.daemon = True
                  t.start()
               # print(counter)
               # print(TLS_info.msg)                                          
               if TLSClientHello in TLS_info.msg[0]:                     
                  IPVersion = IP if IP in packet else IPv6
                  ip_src=packet[IPVersion].src
                  ip_dst=packet[IPVersion].dst
                  tcp_sport=packet[TCP].sport
                  tcp_dport=packet[TCP].dport                                          
                  print("TLS Server Address IP: {} Port: {}".format(ip_dst, tcp_dport))
               if TLSClientKeyExchange in TLS_info.msg[0]:
                  pubKey = TLS_info.msg[0][TLSClientKeyExchange].exchkeys.load
                  print("Public Key: ",pubKey)
               if Raw in TLS_info and TLSServerHelloDone in TLS_info:
                  certificate = TLS(TLS_info[Raw])           
                  print("Certificate: {}".format(bytes(certificate).encode('hex')))
               if TLSServerHello in TLS_info:
                  agreedCipher = TLS_info[TLSServerHello].cipher
                  print("TLS Agreed Cipher: {}".format(agreedCipher))                
               TLS_bytes = bytes(TLS_info)                
               protocolRecord = int(TLS_bytes[0].encode('hex'),16)                                                
               if protocolRecord == 22:
                  version =  int(TLS_bytes[1:2].encode('hex'),16),int(TLS_bytes[2:3].encode('hex'),16)
                  message_len = int(TLS_bytes[3:5].encode('hex'),16)
                  handshake_type = TLS_bytes[5].encode('hex')
                  handshake_length = int(TLS_bytes[6:9].encode('hex'),16)
                  print("Version = {}\nLength = {}\nHandshake Type = {}\nHandshake Length = {}".format(version, message_len, handshake_type, handshake_length))                          
               print("------------------------------\n")    
         except:
               # unattended.append(counter)
               pass               
   #  counter+=1  
 

# -------------------------------------------------------------------------------------------------------
   