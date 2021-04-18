import netifaces
import socket
import threading

# Assuming the device is connected to just one type of interface with just one instance of the interface
# One type of interface -> Either eth0 (Ethernet) or wlan0 (Wi-Fi)
# One connection -> No multiple instances of the interface

# Using default gateway of the device

GATEWAY = 'default'

# -------------------------------------------------------------------------------------------------------

def get_unix_dns_ips():
    dns_ips = {}

    with open('/etc/resolv.conf') as filePointer:
        for line in filePointer:
            columns = line.split()            
            if columns[0]=="nameserver":
                dns_ip = columns[1]
                try:
                    # Legal DNS IP Address
                    dns_ips[columns[1]] = {'Binary_Format': socket.inet_aton(dns_ip)}                    
                    reverse_lookup = socket.gethostbyaddr(dns_ip)
                    dns_ips[dns_ip]['Name'] = reverse_lookup[0]
                    dns_ips[dns_ip]['Alias List'] = reverse_lookup[1]
                except socket.error:
                    # Illegal DNS IP Address
                    continue                
    
    return dns_ips

def getIPLayerAddressingParameters(INTERFACE):
        
    ifaddresses = netifaces.ifaddresses(INTERFACE)[netifaces.AF_INET][0]
    gateways = netifaces.gateways()[GATEWAY][netifaces.AF_INET]

    IP_Info = {}

    IP_Info['DeviceIP'] = ifaddresses['addr']
    IP_Info['BroadcastIP'] = ifaddresses['broadcast']
    IP_Info['Netmask'] = ifaddresses['netmask']
    IP_Info['GatewayIP'] = gateways[0]
    IP_Info['DNS_Info'] = get_unix_dns_ips()

    return IP_Info
    
if __name__=="__main__":
    # While running on Kali, make INTERFACE as eth0
    # While running on Pi, make INTERFACE as wlan0
    INTERFACE = "eth0"
    print(getIPLayerAddressingParameters(INTERFACE))
    