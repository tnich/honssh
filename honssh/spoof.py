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

from honssh import log
import ConfigParser
import os
import re
import random

def get_connection_details(cfg, conn_details):
    if cfg.get('spoof', 'enabled') == 'true':
        user = get_users(cfg, conn_details['username'])
        rand = 0
        if user != None:
            if user[1] == conn_details['password']:
                rand = 1
            else:
                if user[2] == 'fixed':
                    passwords = re.sub(r'\s', '', user[3]).split(',')
                    if conn_details['password'] in passwords:
                        rand = 1
                elif user[2] == 'random':
                    if int(user[3]) > 0:
                        randomFactor = (100 / int(user[3])) + 1
                        rand = random.randrange(1, randomFactor)
        
                found = False
                logfile = cfg.get('folders', 'log_path') + "/spoof.log"
                if os.path.isfile(logfile):
                    f = file(logfile, 'r')
                    creds = f.read().splitlines()
                    f.close()
                    for cred in creds:
                        cred = cred.strip().split(' - ')
                        if cred[0] == conn_details['username'] and cred[1] == conn_details['password']:
                            rand = 1
                            #self.out.writePossibleLink(cred[2:])
                            break

        if rand == 1:
            #self.out.addConnectionString("[SSH  ] Spoofing Login - Changing %s to %s" % (conn_details['password'], user[1]))
            #self.out.writeSpoofPass(conn_details['username'], conn_details['password']) 
            write_spoof_log(cfg, conn_details)
            return True, conn_details['username'], user[1]
    
    return False, '', ''

def get_users(cfg, username):
    usersCfg = ConfigParser.ConfigParser()
    if os.path.exists(cfg.get('spoof','users_conf')):
        usersCfg.read(cfg.get('spoof','users_conf'))
        users = usersCfg.sections()
        for user in users:
            if user == username:
                if usersCfg.has_option(user, 'fake_passwords'):
                    return [user, usersCfg.get(user, 'real_password'), 'fixed', usersCfg.get(user, 'fake_passwords')]
                if usersCfg.has_option(user, 'random_chance'):
                    return [user, usersCfg.get(user, 'real_password'), 'random', usersCfg.get(user, 'random_chance')]
    else:
        log.msg(log.LRED, '[SPOOF]', 'ERROR: users_conf does not exist')
    return None

def write_spoof_log(cfg, conn_details):
    logfile = cfg.get('folders', 'log_path') + '/spoof.log'
    username = conn_details['username']
    password = conn_details['password']
    ip = conn_details['peer_ip']
    
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