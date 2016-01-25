# Copyright (c) 2016 Thomas Nicholson <tnnich@googlemail.com>
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
from honssh.config import config
import subprocess

class Networking():
    cfg = config()
    peer_ip = None
    fake_ip = None
    
    def setupNetworking(self, peer_ip, honey_ip, honey_port):
        if self.cfg.get('advNet', 'enabled') == 'true':
            self.peer_ip = peer_ip
            self.honey_port = str(honey_port)
            self.honey_ip = honey_ip

            self.fake_ip = self.getFakeIP(self.peer_ip)
            
            sp = self.runCommand('ip link add name honssh type dummy')
            result = sp.communicate()
            if sp.returncode != 0:
                if 'File exists' in result[0]:
                    log.msg(log.LPURPLE, '[ADV-NET]', 'HonSSH Interface already exists, not re-adding')
                    return self.addFakeIP()
                else:
                    log.msg(log.LRED, '[ADV-NET]', 'Error creating HonSSH Interface - Using client_addr: ' + result[0])
                    return self.cfg.get('honeypot', 'client_addr')
            else:    
                sp = self.runCommand('ip link set honssh up')
                result = sp.communicate()
                if sp.returncode != 0:
                    log.msg(log.LRED, '[ADV-NET]', 'Error setting HonSSH Interface UP - Using client_addr: ' + result[0])
                    return self.cfg.get('honeypot', 'client_addr')
                else:
                    log.msg(log.LGREEN, '[ADV-NET]', 'HonSSH Interface created')
                    return self.addFakeIP()
        else:
            log.msg(log.LPURPLE, '[ADV-NET]', 'Advanced Networking disabled - Using client_addr')
            return self.cfg.get('honeypot', 'client_addr')

    def addFakeIP(self):
        sp = self.runCommand('ip addr add ' + self.fake_ip + '/32 dev honssh')
        result = sp.communicate()
        if sp.returncode != 0:
            if 'File exists' in result[0]:
                log.msg(log.LPURPLE, '[ADV-NET]', 'Fake IP Address already exists, not re-adding')
                return self.fake_ip
            else:
                log.msg(log.LRED, '[ADV-NET]', 'Error adding IP address to HonSSH Interface - Using client_addr: ' + result[0])
                return self.cfg.get('honeypot', 'client_addr')
        else:
            sp = self.runCommand('iptables -t nat -A POSTROUTING -s ' + self.fake_ip + '/32 -d ' + self.honey_ip + '/32 -p tcp --dport ' + self.honey_port + ' -j SNAT --to ' + self.peer_ip)
            result = sp.communicate()
            if sp.returncode != 0:
                log.msg(log.LRED, '[ADV-NET]', 'Error creating POSTROUTING Rule - Using client_addr: ' + result[0])
                return self.cfg.get('honeypot', 'client_addr')
            else:
                sp = self.runCommand('iptables -t nat -A PREROUTING -s ' + self.honey_ip + '/32 -d ' + self.peer_ip +'/32 -p tcp --sport ' + self.honey_port + ' -j DNAT --to ' + self.fake_ip)
                result = sp.communicate()
                if sp.returncode != 0:
                    log.msg(log.LRED, '[ADV-NET]', 'Error creating PREROUTING Rule - Using client_addr: ' + result[0])
                    return self.cfg.get('honeypot', 'client_addr')
                else:
                    log.msg(log.LGREEN, '[ADV-NET]', 'HonSSH FakeIP and iptables rules added')
                    return self.fake_ip
        
    def removeFakeIP(self):
        sp = self.runCommand('ip addr del ' + self.fake_ip + '/32 dev honssh')
        result = sp.communicate()
        if sp.returncode != 0:
            log.msg(log.LRED, '[ADV-NET]', 'Error removing IP address to HonSSH Interface: ' + result[0])
 
        sp = self.runCommand('iptables -t nat -D POSTROUTING -s ' + self.fake_ip + '/32 -d ' + self.honey_ip + '/32 -p tcp --dport ' + self.honey_port + ' -j SNAT --to ' + self.peer_ip)
        result = sp.communicate()
        if sp.returncode != 0:
            log.msg(log.LRED, '[ADV-NET]', 'Error removing POSTROUTING Rule: ' + result[0])
 
        sp = self.runCommand('iptables -t nat -D PREROUTING -s ' + self.honey_ip + '/32 -d ' + self.peer_ip +'/32 -p tcp --sport ' + self.honey_port + ' -j DNAT --to ' + self.fake_ip)
        result = sp.communicate()
        if sp.returncode != 0:
            log.msg(log.LRED, '[ADV-NET]', 'Error removing PREROUTING Rule: ' + result[0])
        
    def removeNetworking(self, connections):
        if self.cfg.get('advNet', 'enabled') == 'true':
            if len(connections) == 0:
                self.removeFakeIP()
                sp = self.runCommand('ip link del dev honssh')
                result = sp.communicate()
                if sp.returncode != 0:
                    log.msg(log.LRED, '[ADV-NET]', 'Error removing HonSSH Interface: ' + result[0])
            else:
                found = False
                for sensor in connections:
                    for session in sensor['sessions']:
                        if session['peer_ip'] == self.peer_ip:
                            found = True
                            break
                if not found:    
                    self.removeFakeIP()
    
    def getFakeIP(self, peer_ip):
        ipBits = peer_ip.split('.')
        for i in range(0, len(ipBits)):
            ipBits[i] = int(ipBits[i]) + 1
            if ipBits[i] >= 255:
                ipBits[i] = 1
            ipBits[i] = str(ipBits[i])
        return '.'.join(ipBits)
    
    def runCommand(self, cmd):
        return subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
