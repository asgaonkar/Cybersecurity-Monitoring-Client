import csv
import os
import sqlite3
import sys
from datetime import datetime, timedelta
import time

# INTERVAL should be specified in minutes
INTERVAL = 12000

# Only checks for mozilla firefox
def getBrowserPaths(username):
    browser_path_dict = {}
    browserPath = os.path.join('/',username,'.mozilla','firefox')    
    if os.path.exists(browserPath):	
        firefox_dir_list = os.listdir(browserPath)		
        for f in firefox_dir_list:			
            # print(f.find('.default'))
            if f.find('.default') > 0:
                browserPath = os.path.join(browserPath, f, 'places.sqlite')                
		# check whether the firefox database exists
        if os.path.exists(browserPath):
                browser_path_dict['firefox'] = browserPath
    return browser_path_dict

def getBrowserHistory():
    """Get the user's browsers history by using sqlite3 module to connect to the dabases.
       It returns a dictionary: its key is a name of browser in str and its value is a list of
       tuples, each tuple contains four elements, including url, title, and visited_time. 

       Example
       -------
       >>> import browserhistory as bh
       >>> dict_obj = bh.get_browserhistory()
       >>> dict_obj.keys()
       >>> dict_keys(['safari', 'chrome', 'firefox'])
       >>> dict_obj['safari'][0]
       >>> ('https://mail.google.com', 'Mail', '2018-08-14 08:27:26')
    """
    # browserhistory is a dictionary that stores the query results based on the name of browsers.
    browserhistory = {}

    # call get_database_paths() to get database paths.
    paths2databases = getBrowserPaths(os.getlogin())        
    currentTime = int(time.time())
    lastTime = currentTime - INTERVAL*60        
    for browser, path in paths2databases.items():
        try:
            conn = sqlite3.connect(path)
            cursor = conn.cursor()
            _SQL = ''
            # SQL command for browsers' database table
            if browser == 'chrome':
                _SQL = """SELECT url, title, datetime((last_visit_time/1000000)-11644473600, 'unixepoch', 'localtime') 
                                    AS last_visit_time FROM urls ORDER BY last_visit_time DESC"""
            elif browser == 'firefox':
                _SQL = """SELECT url, title, datetime((visit_date/1000000), 'unixepoch', 'localtime') AS visited_date
                                    FROM moz_places INNER JOIN moz_historyvisits on moz_historyvisits.place_id = moz_places.id where visit_date>{} ORDER BY visited_date DESC LIMIT 5""".format(lastTime*1000000)                                            
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
            browserhistory[browser] = query_result
        except sqlite3.OperationalError:
            print('* ' + browser.upper() + ' Database Permission Denied.')

    return browserhistory

for index, history in enumerate(getBrowserHistory()['firefox']):
    print(index+1, ': ', history)
    print("------------------------------------------------")
