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
from twisted.internet import reactor, defer, threads
from honssh import client, output, networking, honsshServer, connections
from honssh.protocols import sftp, ssh
from kippo.core.config import config
from kippo.dblog import mysql
from hpfeeds import hpfeeds
import datetime, time, os, struct, re, subprocess, random

class HonsshServerTransport(honsshServer.HonsshServer):
    cfg = config()
       
    def connectionMade(self):
        self.timeoutCount = 0
        self.interactors = []
        self.wasConnected = False
        self.networkingSetup = False
      
        self.out = output.Output(self.factory)
        self.net = networking.Networking()

        self.disconnected = False
        self.clientConnected = False
        self.finishedSending = False
        self.delayedPackets = []
        
        self.endIP = self.transport.getPeer().host   
        self.localIP = self.transport.getHost().host
        
        preAuthDefer = threads.deferToThread(self.preAuth)
        preAuthDefer.addCallback(self.preAuthConn)
        
        honsshServer.HonsshServer.connectionMade(self)
        
    def connectionLost(self, reason):
        self.disconnected = True
        try:
            self.client.loseConnection()       
        except:
            pass
        honsshServer.HonsshServer.connectionLost(self, reason)
        
        if self.wasConnected:       
            self.out.connectionLost()
        if self.networkingSetup:
            self.net.removeNetworking(self.factory.connections.connections)
        
    def ssh_KEXINIT(self, packet):
        return honsshServer.HonsshServer.ssh_KEXINIT(self, packet)
       
    def dispatchMessage(self, messageNum, payload):
        if honsshServer.HonsshServer.isEncrypted(self, "both"):
            if not self.clientConnected:
                log.msg("[SERVER] CONNECTION TO HONEYPOT NOT READY, BUFFERING PACKET")
                self.delayedPackets.append([messageNum, payload])
            else:
                if not self.finishedSending:
                    self.delayedPackets.append([messageNum, payload])
                else:
                    self.sshParse.parsePacket("[SERVER]", messageNum, payload)
        else:                    
            honsshServer.HonsshServer.dispatchMessage(self, messageNum, payload)
        
    def sendPacket(self, messageNum, payload):
        honsshServer.HonsshServer.sendPacket(self, messageNum, payload)
        
    def preAuth(self):
        if self.cfg.has_option('app_hooks', 'pre_auth_script'):
            if self.cfg.get('app_hooks', 'pre_auth_script') != '':
                log.msg('[SERVER] Calling pre_auth_script')
                preAuthCommand = self.cfg.get('app_hooks', 'pre_auth_script') + ' ' + self.endIP + ' ' + self.localIP
                sp = subprocess.Popen(preAuthCommand, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                result = sp.communicate()
                if sp.returncode == 0:
                    binder = result[0].split(',')
                    self.sensorName = binder[0].lstrip().strip()
                    self.honeyIP = binder[1].lstrip().strip()
                    self.honeyPort = int(binder[2].lstrip().strip())
                    return True, self.sensorName, self.honeyIP, self.honeyPort
                else:
                    return False, result[0], None, None
        self.sensorName = self.cfg.get('honeypot','sensor_name')
        self.honeyIP = self.cfg.get('honeypot','honey_addr')
        self.honeyPort = int(self.cfg.get('honeypot','honey_port'))
        return True, self.sensorName, self.honeyIP, self.honeyPort
        
    def preAuthConn(self, input):
        success, theSensorName, theIP, thePort = input
        if success:
            if not self.disconnected:
                log.msg('[SERVER] Connecting to Honeypot: ' + theSensorName + ' (' + theIP + ':' + str(thePort) + ')')
                clientFactory = client.HonsshClientFactory()
                clientFactory.server = self
                self.bindIP = self.net.setupNetworking(self.endIP, str(thePort))
                self.networkingSetup = True
                reactor.connectTCP(theIP, thePort, clientFactory, bindAddress=(self.bindIP, self.transport.getPeer().port), timeout=10)
                
                self.sshParse = ssh.SSH(self, self.out)
                            
                tunnelsUpDefer = threads.deferToThread(self.tunnelsUp)
                tunnelsUpDefer.addCallback(self.tunnelsUpConn)
        else:
            log.msg("[SERVER][ERROR] SCRIPT ERROR - " + theSensorName)
            log.msg("[SERVER][ERROR] - DISCONNECTING ATTACKER")
            self.loseConnection()
        
    def tunnelsUp(self):
        self.timeoutCount = 0
        while not self.clientConnected:
            time.sleep(0.5)
            self.timeoutCount = self.timeoutCount + 0.5
            if self.timeoutCount == 10:
                break
        return self.clientConnected

    def tunnelsUpConn(self, success):
        if success:
            log.msg("[SERVER] CLIENT CONNECTED, REPLAYING BUFFERED PACKETS")
            self.out.connectionMade(self.endIP, self.transport.getPeer().port, self.honeyIP, self.honeyPort, self.sensorName)
            self.out.setVersion(self.otherVersionString)
            self.wasConnected = True
            for packet in self.delayedPackets:
                self.sshParse.parsePacket("[SERVER]", packet[0], packet[1])
            self.finishedSending = True
        else:
            log.msg("[SERVER][ERROR] COULD NOT CONNECT TO HONEYPOT AFTER 10 SECONDS - DISCONNECTING CLIENT")
            self.loseConnection()
        
class HonsshServerFactory(factory.SSHFactory):
    cfg = config()
    otherVersionString = ''
    connections = connections.Connections()
    hpLog = None
    dbLog = None
    
    def __init__(self):
        clientFactory = client.HonsshSlimClientFactory()
        clientFactory.server = self
        
        reactor.connectTCP(self.cfg.get('honeypot', 'honey_addr'), int(self.cfg.get('honeypot', 'honey_port')), clientFactory)
               
        if self.cfg.get('hpfeeds', 'enabled') == 'true':
            hp = hpfeeds.HPLogger()
            self.hpLog = hp.start(self.cfg)
            
        if self.cfg.get('database_mysql', 'enabled') == 'true':
            db = mysql.DBLogger()
            self.dbLog = db.start(self.cfg)
            
        log.msg('[SERVER] Acquiring SSH Version String from honey_addr:honey_port') 
    
    def buildProtocol(self, addr):
        t = HonsshServerTransport()
               
        t.ourVersionString = self.ourVersionString
        t.factory = self
        t.supportedPublicKeys = self.privateKeys.keys()

        if not self.primes:
            ske = t.supportedKeyExchanges[:]
            if 'diffie-hellman-group-exchange-sha1' in ske:
                ske.remove('diffie-hellman-group-exchange-sha1')
            if 'diffie-hellman-group-exchange-sha256' in ske:
                ske.remove('diffie-hellman-group-exchange-sha256')
            t.supportedKeyExchanges = ske
            
        t.supportedCiphers = ['aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-cbc', '3des-cbc', 'blowfish-cbc', 'cast128-cbc', 'aes192-cbc', 'aes256-cbc' ]
        t.supportedPublicKeys = ['ssh-rsa', 'ssh-dss']
        t.supportedMACs = [ 'hmac-md5', 'hmac-sha1']
        return t
