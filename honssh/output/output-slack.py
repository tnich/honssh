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

    def set_client(self, sensor):
        self.post_connection(sensor)

    def connection_lost(self, sensor):
        self.post_connection(sensor)

    def post_connection(self, sensor):
        session = sensor['session']
        if 'end_time' in session:
            pretext = 'Connection Lost'
        else:
            pretext = 'Connection Made'

        attach = [{'color': '#439FE0', 'pretext': pretext, 'title': session['session_id'],
                   'fields': [{'title': 'Peer IP', 'value': session['peer_ip'], 'short': True},
                              {'title': 'Country', 'value': session['country'], 'short': True},
                              {'title': 'Peer Port', 'value': session['peer_port'], 'short': True},
                              {'title': 'Client', 'value': session['version'], 'short': True}]}]
        self.post_json(attach, sensor)

    def login_failed(self, sensor):
        self.post_login(sensor)

    def login_successful(self, sensor):
        self.post_login(sensor)

    def post_login(self, sensor):
        session = sensor['session']
        auth = session['auth']

        if auth['success']:
            pretext = 'Login Successful'
            color = 'good'
        else:
            pretext = 'Login Failed'
            color = 'danger'

        attach = [{'color': color, 'pretext': pretext, 'title': session['session_id'],
                   'fields': [{'title': 'Username', 'value': auth['username'], 'short': True},
                              {'title': 'Password', 'value': auth['password'], 'short': True}]}]
        self.post_json(attach, sensor)

    def channel_opened(self, sensor):
        self.post_channel(sensor)

    def channel_closed(self, sensor):
        self.post_channel(sensor)

    def post_channel(self, sensor):
        session = sensor['session']
        channel = session['channel']

        if 'end_time' in channel:
            pretext = 'Channel Closed'
        else:
            pretext = 'Channel Opened'

        attach = [{'color': '#ff6600', 'pretext': pretext,
                   'title': session['session_id'] + ' - ' + channel['name'] + ' - ' + channel['uuid']}]
        self.post_json(attach, sensor)

    def command_entered(self, sensor):
        session = sensor['session']
        channel = session['channel']
        command = channel['command']

        attach = [{'color': '#764FA5', 'pretext': 'Command Entered',
                   'title': session['session_id'] + ' - ' + channel['name'] + ' - ' + channel['uuid'],
                   'fields': [{'title': 'Command', 'value': command['command'], 'short': False}]}]
        self.post_json(attach, sensor)

    def download_started(self, sensor):
        self.post_download(sensor)

    def download_finished(self, sensor):
        self.post_download(sensor)

    def post_download(self, sensor):
        session = sensor['session']
        channel = session['channel']
        download = channel['download']

        fields = [{'title': 'URL', 'value': download['link'], 'short': True}]

        if 'end_time' in download:
            pretext = 'Download Finished'
            fields.append({'title': 'File', 'value': download['file'], 'short': True})
            fields.append({'title': 'Size', 'value': download['size'], 'short': True})
            fields.append({'title': 'SHA256', 'value': download['sha256'], 'short': True})
        else:
            pretext = 'Download Started'

        attach = [{'color': '#ffff66', 'pretext': pretext,
                   'title': session['session_id'] + ' - ' + channel['name'] + ' - ' + channel['uuid'],
                   'fields': fields}]
        self.post_json(attach, sensor)

    def post_json(self, attach, sensor):
        the_json = {'username': sensor['sensor_name'] + ' - (' + sensor['honey_ip'] + ':' + sensor['honey_port'] + ')',
                    'attachments': attach}

        req = urllib2.Request(self.cfg.get(['output-slack', 'webhook-url']))
        req.add_header('Content-Type', 'application/json')
        req.add_header('User-Agent', 'HonSSH-Contribute')
        req.add_header('Accept', 'text/plain')
        urllib2.urlopen(req, json.dumps(the_json))
        # log.msg(log.LPURPLE, '[PLUGIN][SLACK]', str(response.read()))

    def validate_config(self):
        props = [['output-slack', 'enabled']]
        for prop in props:
            if self.cfg.check_exist(prop, validation.check_valid_boolean):
                if not self.cfg.getboolean(prop):
                    return False

        props = [['output-slack', 'webhook-url']]
        for prop in props:
            if not self.cfg.check_exist(prop):
                return False

        return True
