# Copyright (c) 2013 Thomas Nicholson <tnnich@googlemail.com>
# See the COPYRIGHT file for more information
# Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.

from twisted.conch.ssh import transport, service
from twisted.python import log
from twisted.internet import protocol, defer
from honssh import txtlog, extras
from kippo.core import ttylog
from kippo.core.config import config
import datetime, time, os


class HonsshClientTransport(transport.SSHClientTransport):
    cfg = config()
    firstTry = False
    failedString = ''
    def connectionMade(self):
        log.msg('New client connection')
        self.factory.server.client = self
        transport.SSHClientTransport.connectionMade(self)
        self.txtlog_file = self.factory.server.txtlog_file
        self.ttylog_file = self.factory.server.ttylog_file
        
    def verifyHostKey(self, pubKey, fingerprint):
        return defer.succeed(True)
    
    def connectionSecure(self):
        log.msg('Client Connection Secured')
        
    def dispatchMessage(self, messageNum, payload):
        if transport.SSHClientTransport.isEncrypted(self, "both"):
            self.factory.server.sendPacket(messageNum, payload)
            
            if messageNum == 94:
                data = payload[8:]
                if(self.factory.server.tabPress):
                    self.factory.server.command = self.factory.server.command + repr(data)[1:2]
                ttylog.ttylog_write(self.ttylog_file, len(data), ttylog.TYPE_OUTPUT, time.time(), data)
                for i in self.factory.server.interactors:
                    i.sessionWrite(data)
            elif messageNum == 51:
                if self.firstTry:
                    self.failedString = self.failedString +  datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " - Failed login - Username:%s Password:%s\n" % (self.factory.server.currUsername, self.factory.server.currPassword)
                else:
                    self.firstTry = True
            elif messageNum == 52:
                extras.successLogin(self.factory.server.endIP)
                if not os.path.exists(os.path.join('sessions/' + self.factory.server.endIP)):
                    os.makedirs(os.path.join('sessions/' + self.factory.server.endIP))
                ttylog.ttylog_open(self.ttylog_file, time.time())
                txtlog.log(self.txtlog_file, self.factory.server.connectionString)
                txtlog.logna(self.txtlog_file, self.failedString)
                self.failedString = ''
                txtlog.log(self.txtlog_file, "Successful login - Username:%s Password:%s" % (self.factory.server.currUsername, self.factory.server.currPassword))
            elif messageNum == 97:
                ttylog.ttylog_close(self.ttylog_file, time.time())
                txtlog.log(self.txtlog_file, "Lost connection from: %s" % self.factory.server.endIP)
            else:           
                log.msg("OUTPUT: MessageNum: " + str(messageNum) + " Encrypted " + repr(payload).decode("utf-8"))
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
