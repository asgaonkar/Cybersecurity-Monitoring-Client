import time
import json
import requests
import sys

def needNewToken():

    # Interval in seconds    
    interval = 30

    currentTime = time.time()

    try:
        tokenTimeFile = open("tokenTime.txt", "r")
    except:
        tokenTimeFile = open("tokenTime.txt", "w")
        tokenTimeFile.write(str(currentTime))
        tokenTimeFile.close()
                
    # print("Current Time: ",currentTime)
    tokenTimeFile = open("tokenTime.txt", "r")
    readTime = tokenTimeFile.readline()
    tokenTimeFile.close()    
    previousTime = float(readTime)      
    # print("Previous Time: ",previousTime)      

    # print("Need: ",currentTime<previousTime+interval)    

    if currentTime<previousTime+interval:        
        return False
    
    tokenTimeFile = open("tokenTime.txt", "w")
    tokenTimeFile.write(str(currentTime))
    tokenTimeFile.close()

    return True

def createNewToken():
    url = "34.94.115.157:4000"    
    channelName = "common"
    smartContractName = "dtc"
    postURL = 'http://{}/users/register'.format(url)

    headers = {
        'Content-Type':'application/json',        
    }

    body = {
        "username": "user1",
        "orgName": "clientMachine",
        "role": "client",
        "attrs": [
            {
                "name":"name",
                "value":"nameTrial",
                "ecert": True
            }, 
            {
                "name":"description",
                "value":"descriptionTrial",
                "ecert": True
            }
        ],
        "secret": "384e193ec04a6731d58b8591242b7dcf"
    }

    response = requests.post(postURL, data=json.dumps(body), headers=headers)
    token = response.json()['token']
    tokenFile = open('token.txt', 'w')
    tokenFile.write(token)
    tokenFile.close()
    return token

def getToken():

    if not needNewToken():
        try:            
            tokenFile = open('token.txt', 'r')            
        except:
            return createNewToken()
        return tokenFile.readline()
    else:
        return createNewToken()    

def writeData(digitalTwinInfo):        

    url = "34.94.115.157:4000"    
    channelName = "common"
    smartContractName = "dtc"
    
    authToken = getToken()

    # print("AuthToken: ",authToken)

    timestamp = int(time.time()*1000.0)

    headers = {
    'Content-Type':'application/json',
    'Accept':'application/json',
    'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MTM5MDI5NjEsInVzZXJuYW1lIjoidXNlcjIiLCJvcmdOYW1lIjoiY2xpZW50TWFjaGluZSIsImlhdCI6MTYxMzg2Njk2MX0.6KGmGWtxNSlMkfR7wGIB5etd2lwSSiyfmtkAiiN-PFI'  
    }

    headers['Authorization'] = 'Bearer ' + authToken

    body = {
    'peers': ['peer2.machine1.clientMachine.chainrider.io'],
    'fcn': 'insertAsset',
    'args': [str(timestamp), json.dumps(digitalTwinInfo)],
    }

    # postURL = "http://{}/channels/{}/chaincodes/{}".format(url, channelName, smartContractName)
    # response = requests.post(postURL, data=json.dumps(body), headers=headers)
    # print("Timestamp: ",timestamp)
    # print("Response: ",response)

'''
digitalTwinInfo =   {
                        "name": "Automation Trial",
                        "machine": "laptopWindows",
                        "city": "Tempe"
                    }
'''

digitalTwinInfo =   {"name": "Automation Trial", "machine": "laptopWindows", "city": "Tempe" }

if __name__=="__main__":
    writeData(digitalTwinInfo)