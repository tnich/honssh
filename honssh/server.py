# Copyright (c) 2013 Thomas Nicholson <tnnich@googlemail.com>
# See the COPYRIGHT file for more information
# Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.

from twisted.conch.ssh import factory, transport, service
from twisted.conch.ssh.transport import SSHCiphers
from twisted.python import log
from twisted.internet import reactor
from honssh import client, txtlog, extras
from kippo.core import ttylog
from kippo.core.config import config
import datetime, time, os, struct

class HonsshServerTransport(transport.SSHServerTransport):
    command = ''
    currUsername = ''
    currPassword = ''
    endIP = ''
    txtlog_file = ''
    ttylog_file = ''
    connectionString = ''
    tabPress = False
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
            elif messageNum == 94:
                data = payload[8:]
                if data == '\x0D':
                    log.msg(self.command)
                    txtlog.log(self.txtlog_file, "Entered command: %s" % (self.command))
                    self.command = ""
                elif data == '\x7f':
                    self.command = self.command[:-1]
                elif data == '\x09':
                    self.tabPress = True
                else:
                    s = repr(data)
                    self.command = self.command + s[1:2]
            else:    
                log.msg("INPUT: MessageNum: " + str(messageNum) + " Encrypted " + repr(payload))

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
