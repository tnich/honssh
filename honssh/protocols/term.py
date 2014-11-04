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
import datetime
import re
import binascii

class Term(baseProtocol.BaseProtocol):    
    command = ''
    pointer = 0
    tabPress = False
    upArrow = False
    
    def __init__(self, out, uuid, chanName):
        self.name = chanName
        self.uuid = uuid
        self.out = out
        self.ttylog_file = self.out.logLocation + datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3] + '_' + self.name[1:-1] + '.tty'
        self.out.openTTY(self.ttylog_file)
    
    def channelClosed(self):
        self.out.closeTTY(self.ttylog_file)
    
    def parsePacket(self, parent, payload): 
        self.data = payload   
         
        if parent == '[SERVER]':
            while len(self.data) != 0: 
                if self.data[:1] == '\x09': #If Tab Pressed
                    self.tabPress = True 
                    self.data = self.data[1:]
                elif self.data[:1] == '\x7f' or self.data[:1] == '\x08':   #If Backspace Pressed
                    if self.pointer != 0:
                        self.command = self.command[:self.pointer-1] + self.command[self.pointer:]
                        self.pointer = self.pointer - 1
                    self.data = self.data[1:]
                elif self.data[:1] == '\x0d' or self.data[:1] == '\x03':  #if enter or ctrl+c
                    if self.data[:1] == '\x03':
                        self.command = self.command + "^C"
                    self.data = self.data[1:]
                    log.msg("[SERVER] - Entered command: %s" % (self.command))
                    self.processCommand(self.uuid, self.name, self.command)
                    
                    self.command = ''
                    self.pointer = 0
                elif self.data[:3] == '\x1b\x4f\x48':   #If Home Pressed
                    self.pointer = 0
                    self.data = self.data[3:]
                elif self.data[:3] == '\x1b\x4f\x46':   #If End Pressed
                    self.pointer = len(self.command)
                    self.data = self.data[3:]
                elif self.data[:3] == '\x1b\x5b\x43':   #If Right Pressed
                    if self.pointer != len(self.command):
                        self.pointer = self.pointer + 1
                    self.data = self.data[3:]
                elif self.data[:3] == '\x1b\x5b\x44':   #If Left Pressed
                    if self.pointer != 0:
                        self.pointer = self.pointer - 1
                    self.data = self.data[3:]
                elif self.data[:3] == '\x1b\x5b\x41' or self.data[:3] == '\x1b\x5b\x42':  #If up or down arrow
                    self.upArrow = True
                    self.data = self.data[3:]
                else:                   
                    self.command = self.command[:self.pointer] + self.data[:1] + self.command[self.pointer:]
                    self.pointer = self.pointer + 1
                    self.data = self.data[1:]
        
        elif parent == '[CLIENT]':
            self.out.inputTTY(self.ttylog_file, self.data) #Log to TTY File
            
            if self.tabPress:
                if not self.data.startswith('\x0d'):
                    if self.data != '\x07':
                        self.command = self.command + self.data
                self.tabPress = False
            if self.upArrow:
                while len(self.data) != 0:
                    if self.data[:1] == '\x08': #Backspace
                        self.command = self.command[:-1]
                        self.pointer = self.pointer - 1
                        self.data = self.data[1:]
                    elif self.data[:3] == '\x1b\x5b\x4b': #ESC[K - Clear Line
                        self.command = self.command[:self.pointer]
                        self.data = self.data[3:]
                    elif self.data[:1] == '\x0d':
                        self.pointer = 0
                        self.data = self.data[1:]
                    elif self.data[:3] == '\x1b\x5b\x43': #Right Arrow
                        self.pointer = self.pointer + 1
                        self.data = self.data[3:]
                    elif self.data[:2] == '\x1b\x5b' and self.data[3] =='\x50':
                        self.data = self.data[4:]
                    elif self.data[:1] != '\x07' and self.data[:1] != '\x0d': #Needed?!
                        self.command = self.command[:self.pointer] + self.data[:1] + self.command[self.pointer:]
                        self.pointer = self.pointer + 1
                        self.data = self.data[1:]
                    
                self.upArrow = False