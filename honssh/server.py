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
from honssh import client, output, networking, honsshServer
from honssh.protocols import sftp, ssh
from kippo.core.config import config
from kippo.dblog import mysql
from hpfeeds import hpfeeds
import datetime, time, os, struct, re, subprocess, random

class HonsshServerTransport(honsshServer.HonsshServer):
    cfg = config()
   
    def connectionMade(self):
        self.interactors = []
        clientFactory = client.HonsshClientFactory()
        clientFactory.server = self

        self.factory.sessions[self.transport.sessionno] = self
        
        self.out = output.Output(self.factory.hpLog, self.factory.dbLog)
        self.net = networking.Networking()
        
        self.endIP = self.transport.getPeer().host   

        self.bindIP = self.net.setupNetworking(self.endIP)
        
        reactor.connectTCP(self.cfg.get('honeypot', 'honey_addr'), 22, clientFactory, bindAddress=(self.bindIP, self.transport.getPeer().port))
        
        self.out.connectionMade(self.endIP, self.transport.getPeer().port)

        self.sshParse = ssh.SSH(self, self.out)

        honsshServer.HonsshServer.connectionMade(self)
        
    def connectionLost(self, reason):
        try:
            self.client.loseConnection()       
        except:
            pass
        for i in self.interactors:
            i.sessionClosed()
        if self.transport.sessionno in self.factory.sessions:
            del self.factory.sessions[self.transport.sessionno]
        honsshServer.HonsshServer.connectionLost(self, reason)
               
        self.out.connectionLost()
        self.net.removeNetworking(self.factory.sessions)
        
    def ssh_KEXINIT(self, packet):
        self.out.setVersion(self.otherVersionString)
        return honsshServer.HonsshServer.ssh_KEXINIT(self, packet)
       
    def dispatchMessage(self, messageNum, payload):
        if honsshServer.HonsshServer.isEncrypted(self, "both"):
            self.sshParse.parsePacket("[SERVER]", messageNum, payload)
        else:
            honsshServer.HonsshServer.dispatchMessage(self, messageNum, payload)
    
    def addInteractor(self, interactor):
        self.interactors.append(interactor)

    def delInteractor(self, interactor):
        self.interactors.remove(interactor)
        
    def sendPacket(self, messageNum, payload):
        honsshServer.HonsshServer.sendPacket(self, messageNum, payload)
        
class HonsshServerFactory(factory.SSHFactory):
    cfg = config()
    otherVersionString = ''
    sessions = {}
    hpLog = None
    dbLog = None
    
    def __init__(self):
        clientFactory = client.HonsshSlimClientFactory()
        clientFactory.server = self
        reactor.connectTCP(self.cfg.get('honeypot', 'honey_addr'), 22, clientFactory)
        
        if self.cfg.get('hpfeeds', 'enabled') == 'true':
            hp = hpfeeds.HPLogger()
            self.hpLog = hp.start(self.cfg)
            
        if self.cfg.get('database_mysql', 'enabled') == 'true':
            db = mysql.DBLogger()
            self.dbLog = db.start(self.cfg)
    
    def buildProtocol(self, addr):
        t = HonsshServerTransport()
               
        t.ourVersionString = self.otherVersionString
        t.factory = self
        t.factory.hpLog = self.hpLog
        t.supportedPublicKeys = self.privateKeys.keys()
        if not self.primes:
            log.msg('[SERVER] - disabling diffie-hellman-group-exchange because we cannot find moduli file')
            ske = t.supportedKeyExchanges[:]
            ske.remove('diffie-hellman-group-exchange-sha1')
            t.supportedKeyExchanges = ske
        return t
