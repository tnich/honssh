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
from honssh import client, output
from kippo.core.config import config
import datetime, time, os, struct, re, subprocess, random

class HonsshServerTransport(transport.SSHServerTransport):
    command = ''
    currUsername = ''
    currPassword = ''

    tabPress = False
    upArrow = False
    isPty = False
    pointer = 0
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
        
        self.out = output.Output()
        self.endIP = self.transport.getPeer().host
        self.out.connectionMade(self.endIP, self.transport.getPeer().port)

        transport.SSHServerTransport.connectionMade(self)
        
    def connectionLost(self, reason):
        try:
            self.client.loseConnection()       
        except:
            pass
        for i in self.interactors:
            i.sessionClosed()
        if self.transport.sessionno in self.factory.sessions:
            del self.factory.sessions[self.transport.sessionno]
        transport.SSHServerTransport.connectionLost(self, reason)
               
        self.out.connectionLost(self.isPty)
        
    def ssh_KEXINIT(self, packet):
        self.out.setVersion(self.otherVersionString)
        return transport.SSHServerTransport.ssh_KEXINIT(self, packet)

            
    def processCommand(self, theCommand):
        self.out.commandEntered(theCommand)
        if self.cfg.get('download', 'enabled') == 'true':
            match = re.finditer("wget ([^;&|]+)", theCommand)
               
            user = ''
            password = ''                
            for m in match:
                argMatch = re.search("-user=(.*?) ", m.group(0))
                if argMatch:
                    user = m.group(0)
                argMatch = re.search("-password=(.*?) ", m.group(0))
                if argMatch:
                    password = m.group(0)               
                
                self.out.fileDownload(m.group(0), m.group(0).split(' ')[-1], user, password)
                
    
    def dispatchMessage(self, messageNum, payload):
        if transport.SSHServerTransport.isEncrypted(self, "both"):
            self.sendOn = True
            self.tabPress = False
            self.upArrow = False

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
                    if(self.cfg.get('spoof', 'enabled') == 'true'):
                        rand = random.randrange(1, int(self.cfg.get('spoof', 'chance')))
                        if rand == 1:
                            self.client.failedString = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " - Spoofing Login - Changing %s to %s\n" % (self.currPassword, self.cfg.get('spoof', 'pass'))
                            payload = payload[0:pos]
                            b = self.cfg.get('spoof', 'pass').encode('utf-8')
                            payload = payload + struct.pack('>L',len(b))
                            payload = payload + b
            elif messageNum == 98:
                num = int(payload[7:8].encode('hex'), 16)
                data = payload[8:8+num]
                if data == 'pty-req':
                    self.isPty = True
                    self.out.openTTY()
                elif data == 'exec':
                    if 'scp' not in payload[17:]:
                        self.out.openTTY()
                        self.processCommand(repr(payload[17:])[1:-1])
                        data = "INPUT: " + payload[17:] + "\n\n\n"
                        self.out.input(data)
                elif data == 'subsystem' and 'sftp' in repr(payload):
                    log.msg("Detected SFTP - Disabling")
                    self.sendOn = False
                    self.sendPacket(100, '\x00\x00\x00\x00') #Might be OpenSSH specific replies - fingerprinting issue?
                    #TODO: Code proper handling of SFTP - capture commands and uploads etc.
                else:
                    if data != 'shell' and data != 'env' and 'putty' not in data:
                        self.out.errLog("New message 98 type detected - Please raise a HonSSH issue on google code with the details: %s" % data)
                        log.msg("SERVER: MessageNum: " + str(messageNum) + " Encrypted " + repr(payload))
            elif messageNum == 90:
                if 'direct-tcpip' in repr(payload) or 'forwarded-tcpip' in repr(payload):
                    log.msg("Detected Port Forwarding - disabling")
                    num = int(payload[0:4].encode('hex'), 16)
                    channel = int(payload[4+num:4+num+4].encode('hex'), 16)
                    self.sendOn = False
                    p = struct.pack('>L',channel)
                    self.sendPacket(92, p + '\x00\x00\x00\x01\x00\x00\x00\x0bopen failed\x00\x00\x00\x00')  #Might be OpenSSH specific replies - fingerprinting issue?
            elif messageNum == 80:
                if 'tcpip-forward' in repr(payload):
                    log.msg("Detected Remote Forwarding - disabling")
                    self.sendOn = False
                    self.sendPacket(4,'\x00\x00\x00\x00$Server has disabled port forwarding.\x00\x00\x00\x00')  #Might be OpenSSH specific replies - fingerprinting issue?
            elif messageNum == 97:
                log.msg("Disconnect received from the attacker: %s" % self.endIP)
            elif messageNum == 94 or messageNum == 95:
                data = payload[8:]
                if messageNum == 95:
                    data = payload[12:]
                    
                if self.isPty:
                    if data == '\x0d' or data == '\x03' or data == '\x18' or data == '\x1a':  #if enter or ctrl+c or ctrl+x or ctrl+z
                        if data == '\x03':
                            self.command = self.command + "^C"
                        if data == '\x18':
                            self.command = self.command + "^X"
                        if data == '\x1a':
                            self.command = self.command + "^Z"
                        if self.cfg.get('spoof', 'enabled') == 'true' and self.command == 'passwd':
                            self.passwdDetected = True
                        if self.passwdDetected == True:
                            self.newPass = self.command
                        log.msg("Entered command: %s" % (self.command))
                        self.processCommand(self.command)
                        self.command = ""
                        self.pointer = 0
                    elif data == '\x7f':    #if backspace
                        self.command = self.command[:self.pointer-1] + self.command[self.pointer:]
                        self.pointer = self.pointer - 1
                    elif data == '\x09':    #if tab
                        self.tabPress = True
                    elif data == '\x1b\x5b\x41' or data == '\x1b\x5b\x42':    #up arrow or down arrow...
                        self.upArrow = True
                    elif data == '\x1b\x5b\x43': #right
                        if self.pointer != len(self.command):
                            self.pointer = self.pointer + 1
                    elif data == '\x1b\x5b\x44': #left
                        if self.pointer >= 0:
                            log.msg(self.pointer)
                            self.pointer = self.pointer - 1
                    else:
                        s = repr(data)
                        self.command = self.command[:self.pointer] + s[1:-1] + self.command[self.pointer:]
                        self.pointer = self.pointer + len(s[1:-1])
                else:
                    if self.size > 0:
                        if self.cfg.get('download', 'enabled') == 'true':
                            self.out.makeDownloadsFolder()
                            outfile = self.cfg.get('folders','session_path') + '/' + self.endIP + '/downloads/' + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + "-" + self.name
                            f = open(outfile, 'ab')
                            f.write(data)
                            f.close()
                            self.out.fileDownloaded((True, '', outfile, None))
                        self.size = self.size - len(data)
                    elif data != '\x00' and data != '\x0a':
                        self.out.genericLog("RAW CLIENT-SERVER: %s" % repr(data))

                    match = re.match('C\d{4} (\d*) (.*)', data)
                    if match:
                        self.out.genericLog("Uploading File via SCP: %s" % match.group(2))
                        self.size = int(match.group(1))
                        self.name = str(match.group(2))
                    
            else:
                if self.cfg.get('packets', 'enabled') == 'false':
                    if messageNum not in [1,2,5,6,20,21,80,91,93] and messageNum not in range(30,49) and messageNum not in range(96,100):
                        self.out.errLog("Unknown SSH Packet detected - Please raise a HonSSH issue on google code with the details: SERVER %s - %s" % (str(messageNum), repr(payload)))
                        log.msg("SERVER: MessageNum: " + str(messageNum) + " Encrypted " + repr(payload))
                    
            if self.cfg.get('packets', 'enabled') == 'true':
                self.out.advancedLog("SERVER: MessageNum: " + str(messageNum) + " Encrypted " + repr(payload))
            
            #log.msg("SERVER: MessageNum: " + str(messageNum) + " Encrypted " + repr(payload))

            if self.sendOn:
                self.client.sendPacket(messageNum, payload)
        else:
            transport.SSHServerTransport.dispatchMessage(self, messageNum, payload)
    
    def addInteractor(self, interactor):
        self.interactors.append(interactor)

    def delInteractor(self, interactor):
        self.interactors.remove(interactor)
        
    def sendPacket(self, messageNum, payload):
        #log.msg("SERVER: MessageNum: " + str(messageNum) + " Encrypted " + repr(payload))
        transport.SSHServerTransport.sendPacket(self, messageNum, payload)



class HonsshServerFactory(factory.SSHFactory):
    cfg = config()      
    otherVersionString = ''
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
