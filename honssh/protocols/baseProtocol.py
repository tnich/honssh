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

from twisted.python import log

class BaseProtocol():
    
    data = ''
    packetSize = 0
    name = ''
    uuid = ''
    ttylog_file = None
    
    def __init__(self):
        pass
                   
    def parsePacket(self, parent, theData):
        #log.msg(parent + ' ' + repr(theData))
        #log.msg(parent + ' ' + '\'\\x' + "\\x".join("{:02x}".format(ord(c)) for c in self.data) + '\'')
        pass
        
    def processCommand(self, uuid, name, command):
        self.out.commandEntered(uuid, name, command)
    
    def channelClosed(self):
        pass
        
    def extractInt(self, len):
        value = int(self.data[:len].encode('hex'), 16)
        self.packetSize = self.packetSize - len
        self.data = self.data[len:]
        return value
    
    def extractString(self):
        len = self.extractInt(4)
        value = str(self.data[:len])
        self.packetSize = self.packetSize - len
        self.data = self.data[len:]
        return value
    
    def extractBool(self):
        value = self.extractInt(1)
        return bool(value)
        
    def extractData(self):
        length = self.extractInt(4)
        self.packetSize = length
        value = self.data
        self.packetSize = self.packetSize - len(value)
        self.data = ''
        return value