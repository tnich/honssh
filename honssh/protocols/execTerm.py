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

from honssh.config import Config
from honssh.protocols import baseProtocol
import re
import datetime


class ExecTerm(baseProtocol.BaseProtocol):
    size = -1
    fileName = ''
    file = ''
    scp = False

    def __init__(self, out, uuid, chan_name, command, ssh, blocked):
        super(ExecTerm, self).__init__(uuid, chan_name, ssh)

        self.cfg = Config.getInstance()
        self.out = out
        self.out.register_self(self)

        if command.startswith('scp'):
            self.scp = True
            self.fileName = ''
            self.file = ''
            self.size = -1
        else:
            self.scp = False
            self.ttylog_file = self.out.logLocation + datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f") \
                               + '_' + self.name[1:-1] + '.tty'
            self.out.open_tty(self.uuid, self.ttylog_file)
            self.out.input_tty(self.ttylog_file, 'INPUT: ' + command + '\n\n')

        self.out.command_entered(self.uuid, command, blocked=blocked)

    def channel_closed(self):
        if not self.scp:
            self.out.close_tty(self.ttylog_file)

    def parse_packet(self, parent, payload):
        self.data = payload

        if self.scp:
            if parent == '[SERVER]':
                if self.size == -1:
                    match = re.match('C\d{4} (\d*) (.*)', self.data)
                    if match:
                        self.size = int(match.group(1))
                        self.fileName = str(match.group(2))
                        self.out.download_started(self.uuid, self.fileName)
                else:
                    self.file = self.file + self.data[:self.size]
                    self.size -= len(self.data[:self.size])

                    if self.size == 0:
                        if self.cfg.getboolean(['download', 'passive']):
                            self.out.make_downloads_folder()
                            outfile = self.out.downloadFolder + datetime.datetime.now().strftime(
                                "%Y%m%d_%H%M%S_%f") + "-" + self.fileName
                            f = open(outfile, 'wb')
                            f.write(self.file)
                            f.close()
                            self.out.file_downloaded((self.uuid, True, self.fileName, outfile, None))

                        self.fileName = ''
                        self.file = ''
                        self.size = -1
        else:
            self.out.input_tty(self.ttylog_file, payload)
