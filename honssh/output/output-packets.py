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
from honssh.utils import validation

import os


class Plugin(object):
    def __init__(self):
        self.cfg = Config.getInstance()
        self.log_file = None

    def packet_logged(self, sensor):
        session = sensor['session']
        self.log_file = session['log_location'] + session['start_time'] + '.log-adv'
        packet = session['packet']
        self.adv_log(packet['date_time'],
                     '%s - %s - %s' % (packet['direction'], packet['packet'].ljust(37), repr(packet['payload'])))

    def validate_config(self):
        props = [['output-packets', 'enabled']]
        for prop in props:
            if not self.cfg.check_exist(prop, validation.check_valid_boolean):
                return False
        return True

    def adv_log(self, dt, message):
        set_permissions = False

        if not os.path.isfile(self.log_file):
            set_permissions = True

        f = file(self.log_file, 'a')
        f.write(dt + " - " + message + "\n")
        f.close()

        if set_permissions:
            os.chmod(self.log_file, 0644)
