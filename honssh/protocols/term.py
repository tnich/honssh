# Copyright (c) 2016 Thomas Nicholson <tnnich@googlemail.com>
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

from honssh import log
from honssh.protocols import baseProtocol 
import datetime


class Term(baseProtocol.BaseProtocol):
    def __init__(self, out, uuid, chan_name, ssh, client_id):
        super(Term, self).__init__(uuid, chan_name, ssh)

        self.command = ''
        self.pointer = 0
        self.tabPress = False
        self.upArrow = False

        self.out = out
        self.clientID = client_id
        self.ttylog_file = self.out.logLocation + datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f") \
                           + '_' + self.name[1:-1] + '.tty'
        self.out.open_tty(self.uuid, self.ttylog_file)
        self.interactors = []
        self.out.register_self(self)

    def channel_closed(self):
        self.out.close_tty(self.ttylog_file)
        for i in self.interactors:
            i.transport.loseConnection()
    
    def parse_packet(self, parent, payload):
        self.data = payload   
         
        if parent == '[SERVER]':
            # Log to TTY File
            self.out.input_tty(self.ttylog_file, self.data)

            while len(self.data) > 0:
                # If Tab Pressed
                if self.data[:1] == '\x09':
                    self.tabPress = True 
                    self.data = self.data[1:]
                # If Backspace Pressed
                elif self.data[:1] == '\x7f' or self.data[:1] == '\x08':
                    if self.pointer > 0:
                        self.command = self.command[:self.pointer-1] + self.command[self.pointer:]
                        self.pointer -= 1
                    self.data = self.data[1:]
                # If enter or ctrl+c or newline
                elif self.data[:1] == '\x0d' or self.data[:1] == '\x03' or self.data[:1] == '\x0a':
                    if self.data[:1] == '\x03':
                        self.command += "^C"

                    self.data = self.data[1:]
                    if self.command != '':
                        log.msg(log.LPURPLE, '[TERM]', 'Entered command: %s' % self.command)
                        self.out.command_entered(self.uuid, self.command)
                    
                    self.command = ''
                    self.pointer = 0
                # If Home Pressed
                elif self.data[:3] == '\x1b\x4f\x48':
                    self.pointer = 0
                    self.data = self.data[3:]
                # If End Pressed
                elif self.data[:3] == '\x1b\x4f\x46':
                    self.pointer = len(self.command)
                    self.data = self.data[3:]
                # If Right Pressed
                elif self.data[:3] == '\x1b\x5b\x43':
                    if self.pointer != len(self.command):
                        self.pointer += 1
                    self.data = self.data[3:]
                # If Left Pressed
                elif self.data[:3] == '\x1b\x5b\x44':
                    if self.pointer != 0:
                        self.pointer -= 1
                    self.data = self.data[3:]
                # If up or down arrow
                elif self.data[:3] == '\x1b\x5b\x41' or self.data[:3] == '\x1b\x5b\x42':
                    self.upArrow = True
                    self.data = self.data[3:]
                else:                   
                    self.command = self.command[:self.pointer] + self.data[:1] + self.command[self.pointer:]
                    self.pointer += 1
                    self.data = self.data[1:]
        
        elif parent == '[CLIENT]':
            # Log to TTY File
            self.out.output_tty(self.ttylog_file, self.data)
            for i in self.interactors:
                i.sendKeystroke(self.data)
            
            if self.tabPress:
                if not self.data.startswith('\x0d'):
                    if self.data != '\x07':
                        self.command = self.command + self.data
                self.tabPress = False

            if self.upArrow:
                while len(self.data) != 0:
                    # Backspace
                    if self.data[:1] == '\x08':
                        self.command = self.command[:-1]
                        self.pointer -= 1
                        self.data = self.data[1:]
                    # ESC[K - Clear Line
                    elif self.data[:3] == '\x1b\x5b\x4b':
                        self.command = self.command[:self.pointer]
                        self.data = self.data[3:]
                    elif self.data[:1] == '\x0d':
                        self.pointer = 0
                        self.data = self.data[1:]
                    # Right Arrow
                    elif self.data[:3] == '\x1b\x5b\x43':
                        self.pointer += 1
                        self.data = self.data[3:]
                    elif self.data[:2] == '\x1b\x5b' and self.data[3] == '\x50':
                        self.data = self.data[4:]
                    # Needed?!
                    elif self.data[:1] != '\x07' and self.data[:1] != '\x0d':
                        self.command = self.command[:self.pointer] + self.data[:1] + self.command[self.pointer:]
                        self.pointer += 1
                        self.data = self.data[1:]
                    else:
                        self.pointer += 1
                        self.data = self.data[1:]

                self.upArrow = False
            
    def addInteractor(self, interactor):
        self.interactors.append(interactor)

    def del_interactor(self, interactor):
        self.interactors.remove(interactor)

    def inject(self, message):
        message = message.encode('utf8')
        # Log to TTY File
        self.out.interact_tty(self.ttylog_file, message)
        self.ssh.inject_key(self.clientID, message)
