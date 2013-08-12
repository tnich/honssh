# Copyright (c) 2013 Thomas Nicholson <tnnich@googlemail.com>
# See the COPYRIGHT file for more information
# Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.

import sys
import datetime

def log(logfile, message):
    f = file(logfile, 'a')
    f.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " - " + message + "\n")
    f.close()
    
def logna(logfile, message):
    f = file(logfile, 'a')
    f.write(message)
    f.close()
    
def otherLog(logfile, ip, username, password):
    f = file(logfile, 'a')
    f.write("%s,%s,%s,%s\n" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),ip,username,password))
    f.close()
