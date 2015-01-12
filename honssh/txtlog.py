# Copyright (c) 2013 Thomas Nicholson <tnnich@googlemail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The names of the author(s) may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

import sys
import datetime
import os 

def log(logfile, message):
    setPermissions = False
    
    if(os.path.isfile(logfile) == False):
        setPermissions = True
    
    f = file(logfile, 'a')
    f.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " - " + message + "\n")
    f.close()
 
    if(setPermissions):
        os.chmod(logfile, 0644)
    
 
def authLog(logfile, ip, username, password, success):
    
    setPermissions = False
    
    if(os.path.isfile(logfile) == False):
        setPermissions = True
    
    f = file(logfile, 'a')
    
    if username == '' or password == '':
        f.write("%s,%s\n" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),ip))
    else:
        auth = "0"
        if success:
            auth = "1"
        f.write("%s,%s,%s,%s,%s\n" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),ip,username,password,auth))
    f.close()
    
    if(setPermissions):
        os.chmod(logfile, 0644)
        
def downloadLog(dt, logfile, ip, link, outFile, theSize, theMD5):
    setPermissions = False
    
    if(os.path.isfile(logfile) == False):
        setPermissions = True
      
    f = file(logfile, 'a')
    f.write("%s,%s,%s,%s,%s,%s\n" % (dt, ip, link, theSize, theMD5, outFile))
    f.close()
    
    if(setPermissions):
        os.chmod(logfile, 0644)
        
def spoofLog(logfile, username, password, ip):
   
    setPermissions = False
    found = False
        
    if os.path.isfile(logfile):
        f = file(logfile, 'r')
        lines = f.readlines()
        f.close()
        for i in range(len(lines)):
            lines[i] = lines[i].strip().split(' - ')
            if lines[i][0] == username and lines[i][1] == password:
                found = True
                if ip not in lines[i][2:]:
                    lines[i].append(ip)
        f = file(logfile, 'w')
        for line in lines:
            f.write(' - '.join(line) + '\n')
        if not found:
            f.write("%s - %s - %s\n" % (username,password,ip))
        f.close()
    else:
        f = file(logfile, 'a')
        f.write("%s - %s - %s\n" % (username,password,ip))
        f.close()
        setPermissions = True
    
    if(setPermissions):
        os.chmod(logfile, 0644)