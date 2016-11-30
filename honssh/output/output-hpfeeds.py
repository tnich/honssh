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
from honssh import log

from hpfeeds_server import hpfeeds_server


class Plugin(object):
    def __init__(self):
        self.cfg = Config.getInstance()
        self.server = None

    def start_server(self):
        log.msg(log.LCYAN, '[PLUGIN][HPFEEDS]', 'hpfeeds HPLogger start')

        server = self.cfg.get(['output-hpfeeds', 'server'])
        port = self.cfg.get(['output-hpfeeds', 'port'])
        ident = self.cfg.get(['output-hpfeeds', 'identifier'])
        secret = self.cfg.get(['output-hpfeeds', 'secret'])
        return hpfeeds_server.hpclient(server, port, ident, secret)

    def set_server(self, server):
        self.server = server

    def connection_lost(self, sensor):
        log.msg(log.LCYAN, '[PLUGIN][HPFEEDS]', 'publishing metadata to hpfeeds')

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

        log.msg(log.LCYAN, '[PLUGIN][HPFEEDS]', 'sessionMeta: ' + str(sensor))
        self.server.publish(hpfeeds_server.HONSSHSESHCHAN, **sensor)

    def login_successful(self, sensor):
        self.send_auth_meta(sensor)

    def login_failed(self, sensor):
        self.send_auth_meta(sensor)

    def send_auth_meta(self, sensor):
        auth = sensor['session']['auth']
        auth_meta = {'sensor_name': sensor['sensor_name'], 'datetime': auth['date_time'], 'username': auth['username'],
                     'password': auth['password'], 'success': auth['success']}
        log.msg(log.LCYAN, '[PLUGIN][HPFEEDS]', 'authMeta: ' + str(auth_meta))
        self.server.publish(hpfeeds_server.HONSSHAUTHCHAN, **auth_meta)

    def validate_config(self):
        props = [['output-hpfeeds', 'enabled']]
        for prop in props:
            if self.cfg.check_exist(prop, validation.check_valid_boolean):
                if not self.cfg.getboolean(prop):
                    return False

        # If hpfeeds is enabled check it's config
        if self.cfg.getboolean(['output-hpfeeds', 'enabled']):
            props = [['output-hpfeeds', 'server'], ['output-hpfeeds', 'identifier'], ['output-hpfeeds', 'secret']]
            for prop in props:
                if not self.cfg.check_exist(prop):
                    return False

            prop = ['output-hpfeeds', 'port']
            if not self.cfg.check_exist(prop, validation.check_valid_port):
                return False

        return True
