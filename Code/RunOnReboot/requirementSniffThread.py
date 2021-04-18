import threading
from scapy.all import *
import cryptography
import logData
import time
import os
import IPLayerAddressing
from shutil import copyfile
load_layer('tls')
from collections import defaultdict
import json
import sys
import cryptography
import ManufatcurerInfo
import CPUInfo
import NetworkInfo
import OSInfo
import logData
import cookieHistory
import browserHistory
from os import path

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
      self.fileNames = {'TCP': self.tcpFilename, 'TLS': self.tlsFilename, 'ICMP': self.icmpFilename, 'DNS': self.dnsFilename}
      self.dnsFileAppend = True
      self.tcpFileAppend = True
      self.icmpFileAppend = True
      self.tlsFileAppend = True      
      self.fileAppends = {'DNS':self.dnsFileAppend, 'TCP': self.tcpFileAppend, 'ICMP': self.icmpFileAppend, 'TLS':self.tlsFileAppend}
      self.digitalTwin = {}
      self.tcpData = {'TCP':[]}
      self.dnsData = {'DNS':[]}
      self.icmpData = {'ICMP':[]}
      self.tlsData = {'TLS':[]}      
      self.fileFlag = False
      self.transactionCount = 0
      # self.combinedFilename = 'Combined_Packets.pcap'
    
   def run(self):
       print("Starting " + self.name)          
       sniff(iface=self.interface, filter='{}'.format(self.filter), prn=self.packetHandler, stop_filter=self.checkTermination)
      #  prn=self.functionMapping[self.protocol]
       print("Exiting " + self.name)       
   
   def writeFile(self, filename, packet, protocol):               
      wrpcap(filename, packet, append=self.fileAppends[protocol])
      if self.fileAppends[protocol]==False:
         self.fileAppends[protocol] = True                   

   def packetHandler(self,packet):
      currentTime = int(time.time())
      if currentTime>self.lastTime + INTERVAL*60:
         self.lastTime = currentTime
         for protocol in self.fileNames:            
            if path.exists(self.fileNames[protocol]):
               copyfile(self.fileNames[protocol], self.fileNames[protocol]+'.bak')
               self.fileAppends[protocol] = False         
         # self.tcpFileAppend = False
         t = threading.Thread(target=self.catchFile)
         t.daemon = True
         t.start()                               
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
      backFile = filename + '.bak'      
      if path.exists(backFile):
         dnsPackets = rdpcap(backFile)
      else:
         self.dnsData['DNS'] = []
         return
      completeData = []
      for packet in dnsPackets:   
         data = {}
         data['timestamp'] = str(packet.time)                   
         DNS_Data = {'QD':defaultdict(list), 'AN':defaultdict(list), 'NS':defaultdict(list)}
         if packet.haslayer(DNS):                        
            for x in range(packet[DNS].qdcount):
               DNS_Data['QD']['qName'].append(packet[DNS].qd[x].qname)
               DNS_Data['QD']['qType'].append(packet[DNS].qd[x].qtype)
            for x in range(packet[DNS].ancount):
               DNS_Data['AN']['rrName'].append(packet[DNS].an[x].rrname)
               DNS_Data['AN']['rData'].append(packet[DNS].an[x].rdata)
               DNS_Data['AN']['ttl'].append(packet[DNS].an[x].ttl)
               DNS_Data['AN']['type'].append(packet[DNS].an[x].type)
            for x in range(packet[DNS].nscount):
               DNS_Data['NS']['rrName'].append(packet[DNS].ns[x].rrname)
               DNS_Data['NS']['rName'].append(packet[DNS].ns[x].rname)
               DNS_Data['NS']['type'].append(packet[DNS].ns[x].type)
               DNS_Data['NS']['mName'].append(packet[DNS].ns[x].mname)
               DNS_Data['NS']['serial'].append(packet[DNS].ns[x].serial)
               DNS_Data['NS']['retry'].append(packet[DNS].ns[x].retry)
               DNS_Data['NS']['expire'].append(packet[DNS].ns[x].expire)         
         data['data'] = DNS_Data                            
         completeData.append(data)
      self.dnsData['DNS'] = completeData
      try:
         os.remove(backFile)
      except OSError as e:
         print("Error: %s : %s" % (backFile, e.strerror))

   def tcpCatchFile(self, filename):
      backFile = filename + '.bak'
      if path.exists(backFile):
         tcpPackets = rdpcap(backFile)  
      else:
         self.tcpData['TCP'] = []
         return
      completeData = []    
      for packet in tcpPackets:       
         data = {}
         data['timestamp'] = str(packet.time)                     
         TCP_Data = {}
         IPVersion = IP if IP in packet else IPv6
         ip_src=packet[IPVersion].src
         ip_dst=packet[IPVersion].dst
         try:
            tcp_sport=packet[TCP].sport
            tcp_dport=packet[TCP].dport                                          
            TCP_Data['Source Port'] = tcp_sport
            TCP_Data['Destination Port'] = tcp_dport
            # print("TCP Transaction: {}(:{}) -> {}(:{})".format(ip_src,tcp_sport,ip_dst,tcp_dport))                           
         except:
            # print("TCP Transaction: {} -> {})".format(ip_src,ip_dst))               
            TCP_Data['Source IP'] = ip_src
            TCP_Data['Destination IP'] =  ip_dst    
         data['data'] = TCP_Data
         completeData.append(data)
      self.tcpData['TCP'] = completeData
      try:
         os.remove(backFile)
      except OSError as e:
         print("Error: %s : %s" % (backFile, e.strerror))

   def icmpCatchFile(self, filename):
      backFile = filename + '.bak'
      if path.exists(backFile):
         icmpPackets = rdpcap(backFile)  
      else:            
         self.icmpData['ICMP'] = []
         return
      completeData = []    
      for packet in icmpPackets:
         data = {}
         data['timestamp'] = str(packet.time)
         ICMP_Data = {}      
         try:
            IPVersion = IP if IP in packet else IPv6        
            ip_src=packet[IPVersion].src
            ip_dst=packet[IPVersion].dst        
            ICMP_Data['Source IP'] = ip_src
            ICMP_Data['Destination IP'] = ip_dst
            
            ICMP_info = packet[ICMP]
            ICMP_type = packet[ICMP].type
            ICMP_code = packet[ICMP].code
            ICMP_bytes = bytes(ICMP_info)
            
            ICMP_Data['Type'] = ICMP_type
            ICMP_Data['Code'] = ICMP_code
            # print("--------------------------")
            # print("Counter: ",counter)        
            # print("ICMP Transaction: {} -> {}".format(ip_src,ip_dst))
            # print("ICMP Type: ",ICMP_type)
            # print("ICMP Code: ",ICMP_code)                
            # print("\n")                  
         except:
            pass
         finally:
            data['data'] = ICMP_Data
            completeData.append(data)
      self.icmpData['ICMP'] = completeData
      try:
         os.remove(backFile)
      except OSError as e:
         print("Error: %s : %s" % (backFile, e.strerror))

   def tlsCatchFile(self, filename):
      backFile = filename + '.bak'
      if path.exists(backFile):
         tlsPackets = rdpcap(backFile)      
      else:
         self.tlsData['TLS'] = []
         return
      completeData = []
      for packet in tlsPackets:
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
                  TLS_Data = {}
                  data = {}
                  try:                  
                     if TLSClientHello in TLS_info.msg[0]:                     
                        IPVersion = IP if IP in packet else IPv6
                        ip_src=packet[IPVersion].src
                        ip_dst=packet[IPVersion].dst
                        tcp_sport=packet[TCP].sport
                        tcp_dport=packet[TCP].dport                                          
                        # print("TLS Server Address IP: {} Port: {}".format(ip_dst, tcp_dport))
                        TLS_Data['Source IP'] = ip_src
                        TLS_Data['Destination IP'] = ip_dst
                        TLS_Data['Source Port'] = tcp_sport
                        TLS_Data['Destination Port'] = tcp_dport
                  except:
                     pass
                  try:                     
                     if TLSClientKeyExchange in TLS_info.msg[0]:
                        pubKey = TLS_info.msg[0][TLSClientKeyExchange].exchkeys.load
                        TLS_Data['Public Key'] = bytes(pubKey).encode('hex')
                        # print("Public Key: ",pubKey)
                  except:
                     pass
                  try:
                     if Raw in TLS_info and TLSServerHelloDone in TLS_info:
                        certificate = TLS(TLS_info[Raw])           
                        # print("Certificate: {}".format(bytes(certificate).encode('hex')))
                        # TLS_Data['Certificate'] = certificate
                        TLS_Data['Certificate (HEX)'] = bytes(certificate).encode('hex')
                  except:
                     pass
                  try:
                     if TLSServerHello in TLS_info:
                        agreedCipher = TLS_info[TLSServerHello].cipher
                        TLS_Data['Agreed Cipher'] = agreedCipher
                        # print("TLS Agreed Cipher: {}".format(agreedCipher))                
                  except:
                     pass
                  TLS_bytes = bytes(TLS_info)                
                  protocolRecord = int(TLS_bytes[0].encode('hex'),16)                                                
                  if protocolRecord == 22:
                     version =  int(TLS_bytes[1:2].encode('hex'),16),int(TLS_bytes[2:3].encode('hex'),16)
                     message_len = int(TLS_bytes[3:5].encode('hex'),16)
                     handshake_type = int(TLS_bytes[5].encode('hex'))
                     handshake_length = int(TLS_bytes[6:9].encode('hex'),16)
                     # print("Version = {}\nLength = {}\nHandshake Type = {}\nHandshake Length = {}".format(version, message_len, handshake_type, handshake_length))                          
                     TLS_Data['Version'] = version
                     TLS_Data['Length'] = message_len
                     TLS_Data['Handshake Type'] = handshake_type
                     TLS_Data['Handshake Length'] = handshake_length
                  # print("------------------------------\n")                  
                  if TLS_Data:
                     print('--------------------------------------------------------------')
                     data['timestamp'] = str(packet.time)
                     data['data'] = TLS_Data               
                     completeData.append(data)                  
                     print("JSON: ",json.dumps(TLS_Data, ensure_ascii=False))
                     print('--------------------------------------------------------------')
            except Exception as e:
               print("Error: ",e)               
      self.tlsData['TLS'] = completeData
      try:
         os.remove(backFile)
      except OSError as e:
         print("Error: %s : %s" % (backFile, e.strerror))
   
   def getStaticInfo(self):
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
         print("Show Error: ",e)
         sys.exit()        
      finally:      
         return staticInformation
      return staticInformation

   def catchFile(self):            
      self.dnsCatchFile(self.fileNames['DNS'])
      self.tcpCatchFile(self.fileNames['TCP'])
      self.icmpCatchFile(self.fileNames['ICMP'])
      self.tlsCatchFile(self.fileNames['TLS'])
      self.digitalTwin['Static'] = self.getStaticInfo()
      self.digitalTwin['Dynamic'] =  {}      
      self.digitalTwin['Dynamic']['IP Addressing'] = IPLayerAddressing.getIPLayerAddressingParameters(self.interface)    
      self.digitalTwin['Dynamic']['TCP'] = self.tcpData
      self.digitalTwin['Dynamic']['DNS'] = self.dnsData
      self.digitalTwin['Dynamic']['ICMP'] = self.icmpData
      self.digitalTwin['Dynamic']['TLS'] = self.tlsData
      self.digitalTwin['Dynamic']['Cookies'] = cookieHistory.getCookieHistory(INTERVAL)
      self.digitalTwin['Dynamic']['Browser History'] = browserHistory.getBrowserHistory(INTERVAL)
      self.transactionCount+=1
      # print('--------------------------------------------------------------')
      # print('Transaction Count: ',self.transactionCount)
      # print('DigitalTwin: ',self.digitalTwin)
      # print('--------------------------------------------------------------')
      writeLog = logData.writeData(self.digitalTwin, self.transactionCount)
      
      
      
   def dnsPacketpanalyzer(self, packet):
      self.writeFile(self.dnsFilename, packet, 'DNS')
      print("DNS")
      # currentTime = int(time.time())
      # if currentTime>self.lastTime + INTERVAL*60:         
      #    self.lastTime = currentTime               
      #    copyfile(self.dnsFilename, self.dnsFilename+'.bak')
      #    self.dnsFileAppend = False
      #    t = threading.Thread(target=self.catchFile, args=(self.dnsFilename+'.bak','dns','',))
      #    t.daemon = True
      #    t.start()
      
   def tcpPacketpanalyzer(self, packet):          
      self.writeFile(self.tcpFilename, packet, 'TCP')         
      print("TCP")
      # currentTime = int(time.time())
      # if currentTime>self.lastTime + INTERVAL*60:
      #    self.lastTime = currentTime
      #    copyfile(self.tcpFilename, self.tcpFilename+'.bak')
      #    self.tcpFileAppend = False
      #    t = threading.Thread(target=self.catchFile, args=(self.tcpFilename+'.bak','tcp','',))
      #    t.daemon = True
      #    t.start()                         

   def icmpPacketpanalyzer(self, packet):      
      try:        
         print("ICMP")         
         self.writeFile(self.icmpFilename,packet,'ICMP')   
         # currentTime = int(time.time())
         # if currentTime>self.lastTime + INTERVAL*60:
         #    self.lastTime = currentTime
         #    copyfile(self.icmpFilename, self.icmpFilename+'.bak')
         #    self.icmpFileAppend = False
         #    t = threading.Thread(target=self.catchFile, args=(self.icmpFilename+'.bak','icmp','',))
         #    t.daemon = True
         #    t.start()         
      except:         
         pass   
   
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
               self.writeFile(self.tlsFilename, packet, 'TLS')
               print("TLS/SSL")
               # currentTime = int(time.time())
               # if currentTime>self.lastTime + INTERVAL*60:
               #    self.lastTime = currentTime
               #    copyfile(self.tlsFilename, self.tlsFilename+'.bak')
               #    self.tlsFileAppend = False
               #    t = threading.Thread(target=self.catchFile, args=(self.tlsFilename+'.bak','tls',TLS_info))
               #    t.daemon = True
               #    t.start()               
               # print(TLS_info.msg)                                                         
         except:               
               pass                  
 
# -------------------------------------------------------------------------------------------------------
   