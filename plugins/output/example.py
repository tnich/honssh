#!/usr/bin/env python

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
from honssh import log

class Plugin():

    def __init__(self):
        self.cfg = Config.getInstance()

    def start_server(self):
        log.msg(log.PLAIN, '[PLUGIN][EXAMPLE]', 'START SERVER')

    def set_server(self, server):
        log.msg(log.PLAIN, '[PLUGIN][EXAMPLE]', 'SET SERVER')

    def connection_made(self, sensor):
        log.msg(log.PLAIN, '[PLUGIN][EXAMPLE]', sensor)

    def connection_lost(self, sensor):
        log.msg(log.PLAIN, '[PLUGIN][EXAMPLE]', sensor)

    def set_client(self, sensor):
        log.msg(log.PLAIN, '[PLUGIN][EXAMPLE]', sensor)

    def login_successful(self, sensor):
        log.msg(log.PLAIN, '[PLUGIN][EXAMPLE]', sensor)

    def login_failed(self, sensor):
        log.msg(log.PLAIN, '[PLUGIN][EXAMPLE]', sensor)

    def channel_opened(self, sensor):
        log.msg(log.PLAIN, '[PLUGIN][EXAMPLE]', sensor)

    def channel_closed(self, sensor):
        log.msg(log.PLAIN, '[PLUGIN][EXAMPLE]', sensor)

    def command_entered(self, sensor):
        log.msg(log.PLAIN, '[PLUGIN][EXAMPLE]', sensor)

    def download_started(self, sensor):
        log.msg(log.PLAIN, '[PLUGIN][EXAMPLE]', sensor)

    def download_finished(self, sensor):
        log.msg(log.PLAIN, '[PLUGIN][EXAMPLE]', sensor)

    def packet_logged(self, sensor):
        log.msg(log.PLAIN, '[PLUGIN][EXAMPLE]', sensor)

    def validate_config(self):
        props = [['example','enabled']]
        for prop in props:
            if not config.checkExist(self.cfg,prop) or not config.checkValidBool(self.cfg, prop):
                return False
        return True
