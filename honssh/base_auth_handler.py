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

from honssh import log
from honssh import plugins

import time

class Base_Auth():
    
    def __init__(self, server):
        self.server = server
        self.auth_plugin = None
        self.cfg = self.server.cfg
        
        self.finishedSending = False
        self.delayedPackets = []
        self.networkingSetup = False
        
    def get_conn_details(self):
        plugin_list = plugins.get_plugin_list(type='honeypot')
        self.auth_plugin = plugins.import_auth_plugins(self.name, plugin_list, self.cfg)
        if self.auth_plugin == None:
            log.msg(log.LRED, '[' + self.name + ']', 'NO PLUGIN ENABLED FOR ' + self.name)
            return {'success':False}
        else:
            return plugins.run_plugins_function(self.auth_plugin, 'get_' + self.name.lower() + '_details', False, self.conn_details)
        
    def is_pot_connected(self):
        self.timeoutCount = 0
        while not self.server.clientConnected:
            time.sleep(0.5)
            self.timeoutCount = self.timeoutCount + 0.5
            if self.timeoutCount == 10:
                break
        return self.server.clientConnected
