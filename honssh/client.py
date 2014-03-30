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

from twisted.conch.ssh import transport, service
from twisted.python import log
from twisted.internet import protocol, defer
from honssh import txtlog, extras
from kippo.core import ttylog
from kippo.core.config import config
import datetime, time, os, re, io, struct

class HonsshClientTransport(transport.SSHClientTransport):
    firstTry = False
    failedString = ''
    def connectionMade(self):
        log.msg('New client connection')
        self.factory.server.client = self
        transport.SSHClientTransport.connectionMade(self)
        self.txtlog_file = self.factory.server.txtlog_file
        self.ttylog_file = self.factory.server.ttylog_file
        self.cfg = self.factory.server.cfg
        
    def verifyHostKey(self, pubKey, fingerprint):
        return defer.succeed(True)
    
    def connectionSecure(self):
        log.msg('Client Connection Secured')
        
    def connectionLost(self, reason):
        transport.SSHClientTransport.connectionLost(self, reason)
        log.msg("Lost connection with the honeypot: %s" % self.cfg.get('honeypot', 'honey_addr'))

    def dispatchMessage(self, messageNum, payload):
        if transport.SSHClientTransport.isEncrypted(self, "both"):
            
            if messageNum == 94 or messageNum == 95:
                data = payload[8:]
                if messageNum == 95:
                    data = payload[12:]
                    
                if self.factory.server.isPty:
                    if(self.factory.server.tabPress):
                        if not '\x0d' in data and not '\x07' in data:
                            self.factory.server.command = self.factory.server.command + repr(data)[1:-1]
                    if(self.factory.server.upArrow):
                        self.factory.server.command = repr(data)[1:-1]
                    if "passwd: password updated successfully" in repr(data) and self.cfg.get('honeypot', 'spoof_login') == 'true' :
                        self.factory.server.passDetected = False
                        self.cfg.set('honeypot', 'spoof_pass', self.factory.server.newPass)
                        f = open('honssh.cfg', 'w')
                        self.cfg.write(f)
                        f.close()  
                    ttylog.ttylog_write(self.ttylog_file, len(data), ttylog.TYPE_OUTPUT, time.time(), data)
                    for i in self.factory.server.interactors:
                        i.sessionWrite(data)
                else:
                    if self.factory.server.size > 0 and data != '\x00' and data != '\x0a':
                        txtlog.log(self.txtlog_file, "RAW SERVER-CLIENT: %s" % (repr(data)))
                        
                    match = re.match('C\d{4} (\d*) (.*)', data)
                    if match:
                        txtlog.log(self.txtlog_file, "Downloading File via SCP: %s" % str(match.group(2)))
                    
            elif messageNum == 51:
                if self.firstTry:
                    self.failedString = self.failedString +  datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " - Failed login - Username:%s Password:%s\n" % (self.factory.server.currUsername, self.factory.server.currPassword)
                else:
                    self.firstTry = True
                if 'publickey' in  repr(payload):
                    log.msg("Detected Public Key authentication - disabling")   
                    b = 'password'.encode('utf-8')
                    payload = struct.pack('>L',len(b))
                    payload = payload + b + '\x00'   
            elif messageNum == 52:
                extras.successLogin(self.factory.server.endIP)
                if not os.path.exists(os.path.join('sessions/' + self.factory.server.endIP)):
                    os.makedirs(os.path.join('sessions/' + self.factory.server.endIP))
                    os.chmod(os.path.join('sessions/' + self.factory.server.endIP),0755)
                txtlog.log(self.txtlog_file, self.factory.server.connectionString)
                txtlog.logna(self.txtlog_file, self.failedString)
                self.failedString = ''
                txtlog.log(self.txtlog_file, "Successful login - Username:%s Password:%s" % (self.factory.server.currUsername, self.factory.server.currPassword))
            elif messageNum == 97:
                log.msg("Disconnect received from the honeypot: %s" % self.cfg.get('honeypot', 'honey_addr'))
            else:     
                if self.cfg.get('extras', 'adv_logging') == 'false':
                    if messageNum not in [1,2,5,6,20,21,90,80,91,93] and messageNum not in range(30,49) and messageNum not in range(96,100):
                        self.factory.server.makeSessionFolder()
                        txtlog.log(self.txtlog_file, "Unknown SSH Packet detected - Please raise a HonSSH issue on google code with the details: CLIENT %s - %s" % (str(messageNum), repr(payload)))      
                    
            if self.cfg.get('extras', 'adv_logging') == 'true':
                self.factory.server.makeSessionFolder()
                txtlog.log(self.txtlog_file[:self.txtlog_file.rfind('.')] + "-adv.log" , "CLIENT: MessageNum: " + str(messageNum) + " Encrypted " + repr(payload))
                log.msg("CLIENT: MessageNum: " + str(messageNum) + " Encrypted " + repr(payload))
            
            #log.msg("CLIENT: MessageNum: " + str(messageNum) + " Encrypted " + repr(payload))    
            self.factory.server.sendPacket(messageNum, payload)
        else:
            transport.SSHClientTransport.dispatchMessage(self, messageNum, payload)

class HonsshClientFactory(protocol.ClientFactory):
    protocol = HonsshClientTransport   
    
class HonsshSlimClientTransport(transport.SSHClientTransport):
    def dataReceived(self, data):
        self.buf = self.buf + data
        if not self.gotVersion:
            if self.buf.find('\n', self.buf.find('SSH-')) == -1:
                return
            lines = self.buf.split('\n')
            for p in lines:
                if p.startswith('SSH-'):
                    self.gotVersion = True
                    self.otherVersionString = p.strip()
                    self.factory.server.otherVersionString = self.otherVersionString
                    log.msg(self.factory.server.otherVersionString)
                    self.loseConnection()
            
class HonsshSlimClientFactory(protocol.ClientFactory):
    protocol = HonsshSlimClientTransport  
