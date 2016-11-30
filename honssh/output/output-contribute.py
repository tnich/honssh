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

import json
import urllib2


class Plugin(object):
    def __init__(self):
        self.cfg = Config.getInstance()

    def connection_lost(self, sensor):
        sensor['session'].pop('log_location')

        for channel in sensor['session']['channels']:
            if 'class' in channel:
                channel.pop('class')

            if 'ttylog_file' in channel:
                fp = open(channel['ttylog_file'], 'rb')
                ttydata = fp.read()
                fp.close()
                channel['ttylog'] = ttydata.encode('hex')
                channel.pop('ttylog_file')

            for download in channel['downloads']:
                if 'file' in download:
                    download.pop('file')

        self.post_json(sensor)

    def post_json(self, the_json):
        try:
            req = urllib2.Request('https://honssh.com/testing/contribute.php')
            req.add_header('Content-Type', 'application/json')
            req.add_header('User-Agent', 'HonSSH-Contribute')
            req.add_header('Accept', 'text/plain')
            urllib2.urlopen(req, json.dumps(the_json))
        except Exception:
            pass

    def validate_config(self):
        props = [['output-contribute', 'enabled']]

        for prop in props:
            if not self.cfg.check_exist(prop, validation.check_valid_boolean) or not self.cfg.getboolean(prop):
                return False
        return True
