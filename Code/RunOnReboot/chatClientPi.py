#!/usr/bin/python
# chat_client.py

import sys, socket, select
import StaticInfo
 
HOST = ''
PORT = ''

def chat_client(s):
     
    print('Connected to remote host. You can start sending messages')
    sys.stdout.write('[Me]: '); sys.stdout.flush()
    initialStaticInfo = str(staticInfo) + "\n"
    print(initialStaticInfo)
    s.send(initialStaticInfo)
    sys.stdout.write('[Me]: '); sys.stdout.flush()
     
    while 1:
        socket_list = [sys.stdin, s]
         
        # Get the list sockets which are readable
        read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [])
         
        for sock in read_sockets:            
            if sock == s:
                # incoming message from remote server, s
                data = sock.recv(4096)
                if not data :
                    print('\nDisconnected from chat server')
                    sys.exit()
                else :
                    #print data
                    sys.stdout.write(data)
                    sys.stdout.write('[Me]: '); sys.stdout.flush()                                        
            
            else :
                # user entered a message                
                msg = sys.stdin.readline()
                s.send(msg)
                sys.stdout.write('[Me]: '); sys.stdout.flush() 

def checkUsage():
    if(len(sys.argv) < 3) :
        print('Usage : python chat_client.py hostname port')
        sys.exit()

def defineSocketVariables():
    global HOST
    global PORT

    HOST = sys.argv[1]
    PORT = int(sys.argv[2])

def createSocket():    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    return s

def connectToHost(s):
    host = HOST
    port = PORT

    # connect to remote host
    try :
        s.connect((host, port))
    except :
        print('Unable to connect')
        sys.exit()
    return s


if __name__ == "__main__":

    checkUsage()
    defineSocketVariables()
    clientSocket = createSocket()
    staticInfo = StaticInfo.getStaticInfo()    
    clientSocket = connectToHost(clientSocket)

    try:
        # DO THINGS
        chat_client(clientSocket)
    except KeyboardInterrupt:
        # quit
        sys.stdout.write("\n!!! KeyboardInterrup: Exiting the room !!!\n"); sys.stdout.flush()     
        sys.exit()    
