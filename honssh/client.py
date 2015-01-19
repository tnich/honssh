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
from kippo.core.config import config
import datetime, time, os, re, io, struct

class HonsshClientTransport(transport.SSHClientTransport):
    
    def connectionMade(self):
        log.msg('[CLIENT] - New client connection')
        self.factory.server.client = self
        self.factory.server.sshParse.setClient(self)
        transport.SSHClientTransport.connectionMade(self)
        self.cfg = self.factory.server.cfg
        self.out = self.factory.server.out
        
    def verifyHostKey(self, pubKey, fingerprint):
        return defer.succeed(True)
    
    def connectionSecure(self):
        self.factory.server.clientConnected = True
        log.msg('[CLIENT] - Client Connection Secured')
        
    def connectionLost(self, reason):
        transport.SSHClientTransport.connectionLost(self, reason)
        log.msg("[CLIENT] - Lost connection with the honeypot: %s" % self.cfg.get('honeypot', 'honey_addr'))

    def dispatchMessage(self, messageNum, payload):
        if transport.SSHClientTransport.isEncrypted(self, "both"):
            self.factory.server.sshParse.parsePacket('[CLIENT]', messageNum, payload)
        else:
            transport.SSHClientTransport.dispatchMessage(self, messageNum, payload)
        
##        for i in self.factory.server.interactors:
##            i.sessionWrite(data)

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
                    log.msg("[CLIENT] - " + self.factory.server.otherVersionString)
                    self.loseConnection()
            
class HonsshSlimClientFactory(protocol.ClientFactory):
    protocol = HonsshSlimClientTransport  
