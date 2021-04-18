def getARPCache():
    arpCache = []
    key = ["IP Address", "HW Type", "Flags", "HW Address", "Mask", "Device"]
    with open('/proc/net/arp') as filePointer:
        for index, line in enumerate(filePointer):            
            if index>0:
                row = {}
                columns = line.split()            
                for i in range(len(columns)):
                    row[key[i]] = columns[i]
                arpCache.append(row)                                    
    return arpCache

def getARPTable():
    arpTable = []
    return arpTable

def getARPContent():
    arpCache = getARPCache()
    arpTable = getARPTable()

    return {"arpCache": arpCache, "arpTable": arpTable}

if __name__=="__main__":
    print(getARPContent())