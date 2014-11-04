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
from honssh.protocols import baseProtocol 
import re, io, datetime

class ExecTerm(baseProtocol.BaseProtocol):  
    size = -1
    fileName = ''
    theFile = ''
    scp = False
   
    def __init__(self, out, uuid, chanName, command):
        self.name = chanName
        self.out = out
        self.uuid = uuid
                
        if command.startswith('scp'):
            self.scp = True
            self.out.commandEntered(self.uuid, self.name + ' [SCP]', command)
        else:
            self.ttylog_file = self.out.logLocation + datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3] + '_' + self.name[1:-1] + '.tty'
            self.out.openTTY(self.ttylog_file)
            self.out.inputTTY(self.ttylog_file, 'INPUT: ' + command + '\n\n')
            self.processCommand(self.uuid, self.name, command)
                        
    def channelClosed(self):
        if not self.scp:
            self.out.closeTTY(self.ttylog_file)
    
    def parsePacket(self, parent, payload): 
        self.data = payload   
        
        if self.scp:
            if parent == '[SERVER]':
                if self.size == -1:
                    match = re.match('C\d{4} (\d*) (.*)', self.data)
                    if match:
                        self.size = int(match.group(1))
                        self.fileName = str(match.group(2))                    
                else:
                    self.theFile = self.theFile + self.data[:self.size]
                    self.size = self.size - len(self.data[:self.size])
                    if self.size == 0:
                        if self.out.cfg.get('download','passive') == 'true':
                            self.out.makeDownloadsFolder()
                            outfile = self.out.downloadFolder + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + "-" + self.fileName
                            f = open(outfile, 'wb')
                            f.write(self.theFile)
                            f.close()
                            self.out.fileDownloaded((self.name + ' [SCP]', self.uuid, True, self.fileName, outfile, None))
                        
                        self.fileName = ''
                        self.theFile = ''
                        self.size = -1                        
        else:
            self.out.inputTTY(self.ttylog_file, payload)   