import csv
import os
import sqlite3
import sys
from datetime import datetime, timedelta
import time

# INTERVAL should be specified in minutes
INTERVAL = 0.5
columnNames = []
# Only checks for mozilla firefox
def getBrowserPaths(username):
    browser_path_dict = {}
    browserPath = os.path.join('/',username,'.mozilla','firefox')    
    if os.path.exists(browserPath):	
        firefox_dir_list = os.listdir(browserPath)		
        for f in firefox_dir_list:			
            # print(f.find('.default'))
            if f.find('.default') > 0:
                browserPath = os.path.join(browserPath, f, 'cookies.sqlite')                
		# check whether the firefox database exists
        if os.path.exists(browserPath):
                browser_path_dict['firefox'] = browserPath    
    return browser_path_dict

def getCookieHistory(Interval = INTERVAL):    
    # browserhistory is a dictionary that stores the query results based on the name of browsers.
    cookieHistory = {}
    global columnNames
    # call get_database_paths() to get database paths.
    paths2databases = getBrowserPaths(os.getlogin())        
    currentTime = int(time.time())
    lastTime = int(currentTime - Interval*60)*1000000    
    print("Last Time: ",lastTime)    
    for browser, path in paths2databases.items():
        try:
            conn = sqlite3.connect(path)
            cursor = conn.cursor()
            _SQL = ''
            # SQL command for browsers' database table
            # Currently focusing only on firefox
            if browser == 'chrome':
                _SQL = """SELECT url, title, datetime((last_visit_time/1000000)-11644473600, 'unixepoch', 'localtime') 
                                    AS last_visit_time FROM urls ORDER BY last_visit_time DESC"""
            elif browser == 'firefox':
                _SQL = """SELECT * FROM moz_cookies where creationTime>={} or lastAccessed>={} order by creationTime DESC""".format(lastTime, lastTime)
            elif browser == 'safari':
                _SQL = """SELECT url, title, datetime(visit_time + 978307200, 'unixepoch', 'localtime') 
                                    FROM history_visits INNER JOIN history_items ON history_items.id = history_visits.history_item ORDER BY visit_time DESC"""
            else:
                pass
            # query_result will store the result of query
            query_result = []
            try:                               
                cursor.execute(_SQL)
                columnNames = list(map(lambda x: x[0], cursor.description))
                print("************************************************")
                print("Column Names: ",columnNames)
                print("************************************************")
                query_result = cursor.fetchall()
            except sqlite3.OperationalError:
                print('* Notification * ')
                print('Please Completely Close ' + browser.upper() + ' Window')
            except Exception as err:
                print(err)
            # close cursor and connector
            cursor.close()
            conn.close()
            # put the query result based on the name of browsers.
            cookieHistory[browser] = query_result
        except sqlite3.OperationalError:
            print('* ' + browser.upper() + ' Database Permission Denied.')


    cookies = {}
    cookies['Data'] = []
    for index, history in enumerate(cookieHistory['firefox']):        
        dataEntry = {}
        # print(index+1, ': ', history)        
        for i in range(len(columnNames)):
            if type(history[i])==int:
                dataEntry[columnNames[i]] = history[i]
            else:
                dataEntry[columnNames[i]] = history[i].encode('ascii')
        cookies['Data'].append(dataEntry)
    # print("------------------------------------------------")    
    return cookies
    
if __name__=="__main__":
    print(getCookieHistory(INTERVAL))