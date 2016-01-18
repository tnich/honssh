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
from honssh import log
from twisted.internet import reactor, protocol, defer
from honssh.config import config
import datetime, time, os, re, io, struct

class HonsshClientTransport(transport.SSHClientTransport):
    
    def connectionMade(self):
        log.msg(log.LGREEN, '[CLIENT]', 'New client connection')
        self.factory.server.client = self
        self.factory.server.sshParse.setClient(self)
        transport.SSHClientTransport.connectionMade(self)
        self.cfg = self.factory.server.cfg
        self.out = self.factory.server.out
        
    def verifyHostKey(self, pubKey, fingerprint):
        return defer.succeed(True)
    
    def connectionSecure(self):
        self.factory.server.clientConnected = True
        log.msg(log.LGREEN, '[CLIENT]', 'Client Connection Secured')
        
    def connectionLost(self, reason):
        transport.SSHClientTransport.connectionLost(self, reason)
        log.msg(log.LBLUE, '[CLIENT]', 'Lost connection with the Honeypot: ' + self.factory.server.sensor_name + ' (' + self.factory.server.honey_ip + ':' + str(self.factory.server.honey_port) + ')')
        if self.factory.server.post_auth_started or self.factory.server.post_auth.auth_plugin == None:
            self.factory.server.pre_auth.connection_lost()
        else:
            self.factory.server.post_auth.connection_lost()

        #try:
        #    self.factory.server.loseConnection()       
        #except:
        #    pass

    def dispatchMessage(self, messageNum, payload):
        if transport.SSHClientTransport.isEncrypted(self, "both"):
            self.factory.server.sshParse.parsePacket('[CLIENT]', messageNum, payload)
        else:
            transport.SSHClientTransport.dispatchMessage(self, messageNum, payload)

class HonsshClientFactory(protocol.ClientFactory):
    protocol = HonsshClientTransport   
    
class HonsshSlimClientTransport(transport.SSHClientTransport):
    gotVersion = False
    def dataReceived(self, data):
        self.buf = self.buf + data
        if not self.gotVersion:
            cfg = self.factory.server.cfg
            if self.buf.find('\n', self.buf.find('SSH-')) == -1:
                return
            lines = self.buf.split('\n')
            for p in lines:
                if p.startswith('SSH-'):
                    self.gotVersion = True
                    self.ourVersionString = p.strip()
                    self.factory.server.ourVersionString = self.ourVersionString
                    log.msg(log.LBLUE, '[CLIENT]', 'Got SSH Version String: ' + self.factory.server.ourVersionString)
                    self.loseConnection()
            
class HonsshSlimClientFactory(protocol.ClientFactory):
    protocol = HonsshSlimClientTransport  
    
    def clientConnectionFailed(self, connector, reason):
        log.msg(log.LRED, '[HONSSH][ERR][FATAL]' ,'HonSSH could not connect to the honeypot to accquire the SSH Version String.')
        log.msg(log.LRED, '[HONSSH][ERR][FATAL]' ,'Please ensure connectivity between HonSSH\'s client_addr to honey_ip:honey_port or set ssh_banner manually')
        log.msg(log.LRED, '[HONSSH][ERR][FATAL]' ,'...Gracefully Exiting')
        reactor.stop()
        
    def clientConnectionLost(self, connector, reason):
        log.msg(log.LGREEN, '[HONSSH]', 'HonSSH Boot Sequence Complete - Ready for attacks!') 
