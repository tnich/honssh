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

from twisted.python import log
from kippo.core.config import config
import subprocess

class Networking():
    cfg = config()
    theIP = None
    theFakeIP = None
    
    def setupNetworking(self, theIP):
        if self.cfg.get('advNet', 'enabled') == 'true':
            self.theIP = theIP
            self.theFakeIP = self.getFakeIP(self.theIP)
            
            sp = self.runCommand('ip link add name honssh type dummy')
            result = sp.communicate()
            if sp.returncode != 0:
                if 'File exists' in result[0]:
                    log.msg("[ADV-NET] - HonSSH Interface already exists, not re-adding")
                    return self.addFakeIP()
                else:
                    log.msg('[ADV-NET] - Error creating HonSSH Interface - Using client_addr: ' + result[0])
                    return self.cfg.get('honeypot', 'client_addr')
            else:    
                sp = self.runCommand('ip link set honssh up')
                result = sp.communicate()
                if sp.returncode != 0:
                    log.msg('[ADV-NET] - Error setting HonSSH Interface UP - Using client_addr: ' + result[0])
                    return self.cfg.get('honeypot', 'client_addr')
                else:
                    log.msg("[ADV-NET] - HonSSH Interface created")
                    return self.addFakeIP()
        else:
            log.msg("[ADV-NET] - Advanced Networking disabled - Using client_addr")
            return self.cfg.get('honeypot', 'client_addr')

    def addFakeIP(self):
        sp = self.runCommand('ip addr add ' + self.theFakeIP + '/32 dev honssh')
        result = sp.communicate()
        if sp.returncode != 0:
            if 'File exists' in result[0]:
                log.msg("[ADV-NET] - Fake IP Address already exists, not re-adding")
                return self.theFakeIP
            else:
                log.msg('[ADV-NET] - Error adding IP address to HonSSH Interface - Using client_addr: ' + result[0])
                return self.cfg.get('honeypot', 'client_addr')
        else:
            sp = self.runCommand('iptables -t nat -A POSTROUTING -s ' + self.theFakeIP + '/32 -d ' + self.cfg.get('honeypot', 'honey_addr') + '/32 -p tcp --dport 22 -j SNAT --to ' + self.theIP)
            result = sp.communicate()
            if sp.returncode != 0:
                log.msg('[ADV-NET] - Error creating POSTROUTING Rule - Using client_addr: ' + result[0])
                return self.cfg.get('honeypot', 'client_addr')
            else:
                sp = self.runCommand('iptables -t nat -A PREROUTING -s ' + self.cfg.get('honeypot', 'honey_addr') + '/32 -d ' + self.theIP +'/32 -p tcp --sport 22 -j DNAT --to ' + self.theFakeIP)
                result = sp.communicate()
                if sp.returncode != 0:
                    log.msg('[ADV-NET] - Error creating PREROUTING Rule - Using client_addr: ' + result[0])
                    return self.cfg.get('honeypot', 'client_addr')
                else:
                    log.msg("[ADV-NET] - HonSSH FakeIP and iptables rules added")
                    return self.theFakeIP
        
    def removeFakeIP(self):
        sp = self.runCommand('ip addr del ' + self.theFakeIP + '/32 dev honssh')
        result = sp.communicate()
        if sp.returncode != 0:
            log.msg('[ADV-NET] - Error removing IP address to HonSSH Interface: ' + result[0])
 
        sp = self.runCommand('iptables -t nat -D POSTROUTING -s ' + self.theFakeIP + '/32 -d ' + self.cfg.get('honeypot', 'honey_addr') + '/32 -p tcp --dport 22 -j SNAT --to ' + self.theIP)
        result = sp.communicate()
        if sp.returncode != 0:
            log.msg('[ADV-NET] - Error removing POSTROUTING Rule: ' + result[0])
 
        sp = self.runCommand('iptables -t nat -D PREROUTING -s ' + self.cfg.get('honeypot', 'honey_addr') + '/32 -d ' + self.theIP +'/32 -p tcp --sport 22 -j DNAT --to ' + self.theFakeIP)
        result = sp.communicate()
        if sp.returncode != 0:
            log.msg('[ADV-NET] - Error removing PREROUTING Rule: ' + result[0])
        
    def removeNetworking(self, sessions):
        if self.cfg.get('advNet', 'enabled') == 'true':
            if len(sessions) == 0:
                self.removeFakeIP()
                sp = self.runCommand('ip link del dev honssh')
                result = sp.communicate()
                if sp.returncode != 0:
                    log.msg("[ADV-NET] - Error removing HonSSH Interface: " + result[0])
            else:
                found = False
                for s in sessions:
                    session = sessions[s]
                    if session.endIP == self.theIP:
                        found = True
                        break
                if not found:    
                    self.removeFakeIP()
    
    def getFakeIP(self, theIP):
        ipBits = theIP.split('.')
        for i in range(0, len(ipBits)):
            ipBits[i] = str(int(ipBits[i]) + 1)
            if ipBits[i] >= '255':
                ipBits[i] = '1'
        return '.'.join(ipBits)
    
    def runCommand(self, cmd):
        return subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
