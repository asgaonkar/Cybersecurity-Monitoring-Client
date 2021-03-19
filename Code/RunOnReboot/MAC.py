def getMAC(interface):
    
  # Return the MAC address of the specified interface
  try:
    mac_address = open('/sys/class/net/%s/address'%interface).read()[:17]
    return mac_address
  except OSError as err:
    print("OS error: {0}".format(err))        
    return False

if __name__=='__main__':
    import sys
    mac_address = getMAC(sys.argv[1])
    if mac_address:
        print(mac_address)
        sys.exit(0)
    else:
        sys.exit(1)
