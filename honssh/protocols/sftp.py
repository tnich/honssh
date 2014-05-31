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
import datetime, io 

class SFTP():
    packetSize = 0
    data = ''
    prevID = ''
    ID = ''
    handle = ''
    path = ''
    command = ''
    payloadSize = 0
    payloadOffset = 0
    theFile = ''
    
    packetLayout = [
                {'num': 1,      'name': 'SSH_FXP_INIT'},             #['uint32', 'version'], [['string', 'extension_name'], ['string', 'extension_data']]]
                {'num': 2,      'name': 'SSH_FXP_VERSION'},          #[['uint32', 'version'], [['string', 'extension_name'], ['string', 'extension_data']]]
                {'num': 3,      'name': 'SSH_FXP_OPEN'},             #[['uint32', 'id'], ['string', 'filename'], ['uint32', 'pflags'], ['ATTRS', 'attrs']]
                {'num': 4,      'name': 'SSH_FXP_CLOSE'},            #[['uint32', 'id'], ['string', 'handle']]
                {'num': 5,      'name': 'SSH_FXP_READ'},             #[['uint32', 'id'], ['string', 'handle'], ['uint64', 'offset'], ['uint32', 'len']]
                {'num': 6,      'name': 'SSH_FXP_WRITE'},            #[['uint32', 'id'], ['string', 'handle'], ['uint64', 'offset'], ['string', 'data']]
                {'num': 7,      'name': 'SSH_FXP_LSTAT'},            #[['uint32', 'id'], ['string', 'path']]
                {'num': 8,      'name': 'SSH_FXP_FSTAT'},            #[['uint32', 'id'], ['string', 'handle']]
                {'num': 9,      'name': 'SSH_FXP_SETSTAT'},          #[['uint32', 'id'], ['string', 'path'], ['ATTRS', 'attrs']]
                {'num': 10,     'name': 'SSH_FXP_FSETSTAT'},         #[['uint32', 'id'], ['string', 'handle'], ['ATTRS', 'attrs']]
                {'num': 11,     'name': 'SSH_FXP_OPENDIR'},          #[['uint32', 'id'], ['string', 'path']]
                {'num': 12,     'name': 'SSH_FXP_READDIR'},          #[['uint32', 'id'], ['string', 'handle']]
                {'num': 13,     'name': 'SSH_FXP_REMOVE'},           #[['uint32', 'id'], ['string', 'filename']]
                {'num': 14,     'name': 'SSH_FXP_MKDIR'},            #[['uint32', 'id'], ['string', 'path'], ['ATTRS', 'attrs']]
                {'num': 15,     'name': 'SSH_FXP_RMDIR'},            #[['uint32', 'id'], ['string', 'path']]
                {'num': 16,     'name': 'SSH_FXP_REALPATH'},         #[['uint32', 'id'], ['string', 'path']]
                {'num': 17,     'name': 'SSH_FXP_STAT'},             #[['uint32', 'id'], ['string', 'path']]
                {'num': 18,     'name': 'SSH_FXP_RENAME'},           #[['uint32', 'id'], ['string', 'oldpath'], ['string', 'newpath']]
                {'num': 19,     'name': 'SSH_FXP_READLINK'},         #[['uint32', 'id'], ['string', 'path']]
                {'num': 20,     'name': 'SSH_FXP_SYMLINK'},          #[['uint32', 'id'], ['string', 'linkpath'], ['string', 'targetpath']]
                {'num': 101,    'name': 'SSH_FXP_STATUS'},           #[['uint32', 'id'], ['uint32', 'error_code'], ['string', 'error_message'], ['string', 'language']]
                {'num': 102,    'name': 'SSH_FXP_HANDLE'},           #[['uint32', 'id'], ['string', 'handle']]
                {'num': 103,    'name': 'SSH_FXP_DATA'},             #[['uint32', 'id'], ['string', 'data']]
                {'num': 104,    'name': 'SSH_FXP_NAME'},             #[['uint32', 'id'], ['uint32', 'count'], [['string', 'filename'], ['string', 'longname'], ['ATTRS', 'attrs']]]
                {'num': 105,    'name': 'SSH_FXP_ATTRS'},            #[['uint32', 'id'], ['ATTRS', 'attrs']]
                {'num': 200,    'name': 'SSH_FXP_EXTENDED'},         #[]
                {'num': 201,    'name': 'SSH_FXP_EXTENDED_REPLY'}    #[]
                ]
                
    def __init__(self, outputFolder, out):
        self.outputFolder = outputFolder
        self.out = out
       
    def parsePacket(self, parent, theData): 
        self.data = theData   
        
        if self.packetSize == 0:
            self.packetSize = int(self.data[:4].encode('hex'), 16)
            self.data = self.data[4:]
            sftpNum = self.extractInt(1) 
            packet = ''
            for item in self.packetLayout:
                if sftpNum == item['num']:
                    packet = item['name']
                    
            #log.msg(parent + "[SFTP] - " + packet)
            
            self.prevID = self.ID
            self.ID = self.extractInt(4)
            
            if packet == 'SSH_FXP_OPENDIR':
                self.path = self.extractString()
                
            elif packet == 'SSH_FXP_REALPATH':
                self.path = self.extractString()
                self.command = 'cd ' + self.path
                log.msg(parent + '[SFTP] - Entered Command: ' + self.command)
                self.out.commandEntered(self.command)
                
            elif packet == 'SSH_FXP_OPEN':
                self.path = self.extractString()
                pflags = '{0:08b}'.format(self.extractInt(4))
                if pflags[6] == '1':
                    self.command = 'put ' + self.path
                    self.theFile = ''
                elif pflags[7] == '1':
                    self.command = 'get ' + self.path
                else:
                    #Unknown PFlag
                    self.out.errLog("New SFTP pflag detected - Please raise a HonSSH issue on google code with the details: %s %s" % (pflags, self.data))
                self.packetSize = 0
                #log.msg(parent + '[SFTP] - Entered Command: ' + self.command)
                self.out.commandEntered(self.command)
                    
            elif packet == 'SSH_FXP_READ':
                pass
                
            elif packet == 'SSH_FXP_WRITE':
                if self.handle == self.extractString():
                    self.offset = self.extractInt(8)
                    self.theFile = self.theFile[:self.offset] + self.extractData()
                      
            elif packet == 'SSH_FXP_HANDLE':
                if self.ID == self.prevID:
                    self.handle = self.extractString()
                    
            elif packet == 'SSH_FXP_READDIR':
                if self.handle == self.extractString():
                    self.command = 'ls ' + self.path
                    
            elif packet == 'SSH_FXP_SETSTAT':
                self.path = self.extractString()
                self.command = self.extractAttrs() + ' ' + self.path 
                self.packetSize = 0
                
            elif packet == 'SSH_FXP_EXTENDED':
                cmd = self.extractString()
                self.path = self.extractString()
                if cmd == 'statvfs@openssh.com':
                    self.command = 'df ' + self.path
                elif cmd == 'hardlink@openssh.com':
                    self.command = 'ln ' + self.path + ' ' + self.extractString()
                elif cmd == 'posix-rename@openssh.com':
                    self.command = 'mv ' + self.path + ' ' + self.extractString()
                else:
                    #UNKNOWN COMMAND
                    self.out.errLog("New SFTP Extended Command detected - Please raise a HonSSH issue on google code with the details: %s %s" % (cmd, self.data))
                self.packetSize = 0
            elif packet == 'SSH_FXP_EXTENDED_REPLY':
                log.msg(parent + '[SFTP] - Entered Command: ' + self.command)
                self.out.commandEntered(self.command)
                self.packetSize = 0
                
            elif packet == 'SSH_FXP_CLOSE':
                if self.handle == self.extractString():
                    if 'get' in self.command:
                        log.msg(parent + '[SFTP] - Finished Downloading: ' + self.path)
                        self.out.commandEntered(self.command)
                    elif 'put' in self.command:
                        log.msg(parent + '[SFTP] - Finished Uploading: ' + self.path)

                        self.out.makeDownloadsFolder()
                        outfile = self.outputFolder + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + "-" + self.path.split('/')[-1]
                        f = open(outfile, 'wb')
                        f.write(self.theFile)
                        f.close()
                        self.out.fileDownloaded((True, '', outfile, None))
                
            elif packet == 'SSH_FXP_SYMLINK':
                self.command = 'ln -s ' + self.extractString() + ' ' + self.extractString()
                
            elif packet == 'SSH_FXP_MKDIR':
                self.command = 'mkdir ' + self.extractString()
                self.packetSize = 0
                
            elif packet == 'SSH_FXP_REMOVE':
                self.command = 'rm ' + self.extractString()
                
            elif packet == 'SSH_FXP_RMDIR':
                self.command = 'rmdir ' + self.extractString()
                
            elif packet == 'SSH_FXP_STATUS':
                if self.ID == self.prevID:
                    code = self.extractInt(4)
                    if code in [0, 1]:
                        if 'get' not in self.command and 'put' not in self.command:
                            log.msg(parent + '[SFTP] - Entered Command: ' + self.command)
                            self.out.commandEntered(self.command)
                    else:
                        message = self.extractString()
                        log.msg(parent + '[SFTP] - Failed Command: ' + self.command + ' Reason: ' + message)
                        self.out.commandEntered(self.command)
                self.packetSize = 0
            else:
                self.packetSize = 0
        else:
            self.theFile = self.theFile + self.data
            self.packetSize = self.packetSize - len(self.data)
                   
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
    
    def extractData(self):
        len = self.extractInt(4)
        value = self.data[:len]
        self.packetSize = self.packetSize - len
        self.data = self.data[len:]
        return value
    
    def extractAttrs(self):
        cmd = ''
        flags = '{0:08b}'.format(self.extractInt(4))
        if flags[5] == '1':
            perms = '{0:09b}'.format(self.extractInt(4))
            log.msg(parent + "PERMS:" + perms)
            chmod = str(int(perms[:3], 2)) + str(int(perms[3:6], 2)) + str(int(perms[6:], 2))
            cmd = 'chmod ' + chmod
        elif flags[6] == '1':
            user = str(self.extractInt(4))
            group = str(self.extractInt(4))
            cmd = 'chown ' + user + ':'  + group
        else:
            #Unknown attribute
            self.out.errLog("New SFTP Attribute detected - Please raise a HonSSH issue on google code with the details: %s %s" % (flags, self.data))
        return cmd


   
'''
CLIENT                              SERVER

    SSH_FXP_INIT    -->    
                    <--    SSH_FXP_VERSION

    SSH_FXP_OPEN    -->
                    <--    SSH_FXP_HANDLE (or SSH_FXP_STATUS if fail)

    SSH_FXP_READ    -->
                    <--    SSH_FXP_DATA (or SSH_FXP_STATUS if fail)

    SSH_FXP_WRITE   -->
                    <--    SSH_FXP_STATUS

    SSH_FXP_REMOVE  -->
                    <--    SSH_FXP_STATUS

    SSH_FXP_RENAME  -->
                    <--    SSH_FXP_STATUS

    SSH_FXP_MKDIR   -->
                    <--    SSH_FXP_STATUS

    SSH_FXP_RMDIR   -->
                    <--    SSH_FXP_STATUS

    SSH_FXP_OPENDIR -->
                    <--    SSH_FXP_HANDLE (or SSH_FXP_STATUS if fail)

    SSH_FXP_READDIR -->
                    <--    SSH_FXP_NAME (or SSH_FXP_STATUS if fail)

    SSH_FXP_STAT    -->         //Follows symlinks 
                    <--    SSH_FXP_ATTRS (or SSH_FXP_STATUS if fail)

    SSH_FXP_LSTAT    -->         //Does not follow symlinks 
                    <--    SSH_FXP_ATTRS (or SSH_FXP_STATUS if fail)

    SSH_FXP_FSTAT    -->         //Works on an open file/handle not a file path like (L)STAT 
                    <--    SSH_FXP_ATTRS (or SSH_FXP_STATUS if fail)

    SSH_FXP_SETSTAT -->          //Sets file attributes on path
                    <--    SSH_FXP_STATUS

    SSH_FXP_FSETSTAT-->          //Sets file attributes on a handle
                    <--    SSH_FXP_STATUS

    SSH_FXP_READLINK -->        //Used to find the target of a symlink
                    <--    SSH_FXP_NAME (or SSH_FXP_STATUS if fail)

    SSH_FXP_SYMLINK  -->        //Used to create a symlink
                    <--    SSH_FXP_NAME (or SSH_FXP_STATUS if fail)

    SSH_FXP_REALPATH -->          //Relative path
                    <--    SSH_FXP_NAME (or SSH_FXP_STATUS if fail)

    SSH_FXP_CLOSE   -->                     //Closes handle not session
                    <--    SSH_FXP_STATUS
'''