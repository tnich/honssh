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
from twisted.conch.ssh import factory, transport, service
from twisted.conch.ssh.transport import SSHCiphers
from twisted.python import log
from twisted.internet import reactor
from honssh import client, txtlog, extras
from kippo.core import ttylog
from kippo.core.config import config
import datetime, time, os, struct, re, subprocess

class HonsshServerTransport(transport.SSHServerTransport):
    command = ''
    currUsername = ''
    currPassword = ''
    endIP = ''
    txtlog_file = ''
    ttylog_file = ''
    connectionString = ''
    tabPress = False
    isPty = False
    size = 0
    name = ''
    passwdDetected = False
    newPass = ''
    cfg = config()
    
    def connectionMade(self):
        self.interactors = []
        clientFactory = client.HonsshClientFactory()
        clientFactory.server = self

        self.factory.sessions[self.transport.sessionno] = self
             
        reactor.connectTCP(self.cfg.get('honeypot', 'honey_addr'), 22, clientFactory, bindAddress=(self.cfg.get('honeypot', 'client_addr'),self.transport.getPeer().port))
        
        self.endIP = self.transport.getPeer().host
        self.logLocation = self.cfg.get('honeypot', 'session_path') + "/" + self.endIP + "/" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.txtlog_file = self.logLocation + ".log"
        self.connectionString = "Incoming connection from: %s:%s" % (self.endIP,self.transport.getPeer().port)
        
        self.ttylog_file = self.logLocation + ".tty"
        
        transport.SSHServerTransport.connectionMade(self)
        
    def connectionLost(self, reason):       
        for i in self.interactors:
            i.sessionClosed()
        if self.transport.sessionno in self.factory.sessions:
            del self.factory.sessions[self.transport.sessionno]
        transport.SSHServerTransport.connectionLost(self, reason)
        
    def ssh_KEXINIT(self, packet):
        self.connectionString = self.connectionString + " - " + self.otherVersionString
        return transport.SSHServerTransport.ssh_KEXINIT(self, packet)
    
    def dispatchMessage(self, messageNum, payload):
        if transport.SSHServerTransport.isEncrypted(self, "both"):
            self.tabPress = False

            if messageNum == 50: 
                p = 0
                num = int(payload[p:p+4].encode('hex'), 16)
                p = p+4
                self.currUsername = payload[p:p+num]
                p = p+num
                num = int(payload[p:p+4].encode('hex'), 16)
                p = p+4
                service = payload[p:p+num]
                p = p+num
                num = int(payload[p:p+4].encode('hex'), 16)
                p = p+4
                auth = payload[p:p+num]
                p = p+num+1
                if auth == 'password':
                    pos = p
                    num = int(payload[p:p+4].encode('hex'), 16)
                    p = p+4
                    self.currPassword = payload[p:p+num]
                    txtlog.otherLog(self.cfg.get('honeypot', 'log_path') + "/" + datetime.datetime.now().strftime("%Y-%m-%d"), self.endIP, self.currUsername, self.currPassword)
                    extras.attemptedLogin(self.currUsername, self.currPassword)
                    if(self.cfg.get('honeypot', 'spoof_login') == 'true'):
                        self.client.failedString = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " - Spoofing Login - Changing %s to %s\n" % (self.currPassword, self.cfg.get('honeypot', 'spoof_pass'))
                        payload = payload[0:pos]
                        b = self.cfg.get('honeypot', 'spoof_pass').encode('utf-8')
                        payload = payload + struct.pack('>L',len(b))
                        payload = payload + b
            elif messageNum == 98:
                num = int(payload[7:8].encode('hex'), 16)
                data = payload[8:8+num]
                if data == 'pty-req':
                    self.isPty = True
                    ttylog.ttylog_open(self.ttylog_file, time.time())
            elif messageNum == 94:
                data = payload[8:]
                if self.isPty:
                    if data == '\x0d' or data == '\x03':  #if enter or ctrl+c
                        if data == '\x03':
                            self.command = self.command + "^C"
                        if self.cfg.get('honeypot', 'spoof_login') == 'true' and self.command == 'passwd':
                            self.passwdDetected = True
                        if self.passwdDetected == True:
                            self.newPass = self.command
                        log.msg("Entered command: %s" % (self.command))
                        txtlog.log(self.txtlog_file, "Entered command: %s" % (self.command))
                        if self.cfg.get('extras', 'file_download') == 'true':
                            file = re.match("wget(.+)((http|ftp|https):\/\/[\w\-_]+(\.[\w\-_]+)+([\w\-\.,@?^=%&amp:/~\+#]*[\w\-\@?^=%&amp/~\+#])?)", self.command)
                            if file:

                                if not os.path.exists('downloads'):
                                    os.makedirs('downloads')
                                    os.chmod('downloads',0755)                   

                                txtlog.log(self.txtlog_file, "wget Download Detected - Downloading File Using: %s" % str(file.group(0)))
                                wgetCommand = "wget -P downloads " + str(file.group(1)) + " " + str(file.group(2))
                                subprocess.Popen(wgetCommand, shell=True)

                        self.command = ""
                    elif data == '\x7f':    #if backspace
                        self.command = self.command[:-1]
                    elif data == '\x09':    #if tab
                        self.tabPress = True
                    else:
                        s = repr(data)
                        self.command = self.command + s[1:-1]
                else:
                    if self.size > 0:
                        if self.cfg.get('extras', 'file_download') == 'true':
                            f = open(self.logLocation + '-' + self.name + '.safe', 'ab')
                            f.write(data)
                            f.close()
                        self.size = self.size - len(data)
                    elif data != '\x00' and data != '\x0a':
                        txtlog.log(self.txtlog_file, "RAW CLIENT-SERVER: %s" % (repr(data)))
                    
                    match = re.match('C\d{4} (\d*) (.*)', data)
                    if match:
                        txtlog.log(self.txtlog_file, "Uploading File via SCP: %s" % str(match.group(2)))
                        self.size = int(match.group(1))
                        self.name = str(match.group(2))
                    
            #else:    
            #    log.msg("SERVER: MessageNum: " + str(messageNum) + " Encrypted " + repr(payload))
            self.client.sendPacket(messageNum, payload)
        else:
            transport.SSHServerTransport.dispatchMessage(self, messageNum, payload)
    
    def addInteractor(self, interactor):
        self.interactors.append(interactor)

    def delInteractor(self, interactor):
        self.interactors.remove(interactor)


class HonsshServerFactory(factory.SSHFactory):
    cfg = config()      
    otherVersionString=''
    sessions = {}
    def __init__(self):
        clientFactory = client.HonsshSlimClientFactory()
        clientFactory.server = self
        reactor.connectTCP(self.cfg.get('honeypot', 'honey_addr'), 22, clientFactory)
    
    def buildProtocol(self, addr):
        t = HonsshServerTransport()
        
        t.ourVersionString = self.otherVersionString
        t.factory = self
        t.supportedPublicKeys = self.privateKeys.keys()
        if not self.primes:
            log.msg('disabling diffie-hellman-group-exchange because we cannot find moduli file')
            ske = t.supportedKeyExchanges[:]
            ske.remove('diffie-hellman-group-exchange-sha1')
            t.supportedKeyExchanges = ske
        return t
