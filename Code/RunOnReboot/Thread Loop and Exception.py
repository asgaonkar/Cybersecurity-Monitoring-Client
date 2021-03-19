import sys
import threading
import queue
import time


class CountdownTask: 
      
    def __init__(self): 
        self._running = True
      
    def terminate(self): 
        self._running = False
        
    def run(self, timeDealy):         
        while self._running and timeDealy > 0: 
            print('T-minus', timeDealy) 
            timeDealy -= 1
            time.sleep(timeDealy) 
    
  
c = CountdownTask() 
t = threading.Thread(target = c.run, args =(100, )) 
t.start() 

# Signal termination 
# c.terminate()  


try:
    while True:
        pass
except KeyboardInterrupt as e:
    c.terminate()

# Wait for actual termination (if needed)  
t.join() 