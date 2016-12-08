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

import subprocess


class Plugin(object):
    def __init__(self):
        self.cfg = Config.getInstance()

    def _checkProp(self, prop):
        if self.cfg.check_exist(prop):
            val = self.cfg.get(prop)

            if len(val) > 0:
                return val
            else:
                return None

    def connection_made(self, sensor):
        prop = ['output-app_hooks', 'connection_made']
        val = self._checkProp(prop)

        if val is not None:
            session = sensor['session']
            command = '%s CONNECTION_MADE %s %s %s %s %s %s' % (val, session['start_time'], session['peer_ip'],
                                                                session['peer_port'], sensor['honey_ip'],
                                                                sensor['honey_port'], session['session_id'])
            self.runCommand(command)

    def connection_lost(self, sensor):
        prop = ['output-app_hooks', 'connection_lost']
        val = self._checkProp(prop)

        if val is not None:
            session = sensor['session']
            command = '%s CONNECTION_LOST %s %s %s %s %s %s' % (val, session['end_time'], session['peer_ip'],
                                                                session['peer_port'], sensor['honey_ip'],
                                                                sensor['honey_port'], session['session_id'])
            self.runCommand(command)

    def login_successful(self, sensor):
        prop = ['output-app_hooks', 'login_successful']
        val = self._checkProp(prop)

        if val is not None:
            session = sensor['session']
            command = '%s LOGIN_SUCCESSFUL %s %s %s %s' % (val, session['auth']['date_time'], session['peer_ip'],
                                                           session['auth']['username'], session['auth']['password'])
            self.runCommand(command)

    def login_failed(self, sensor):
        prop = ['output-app_hooks', 'login_failed']
        val = self._checkProp(prop)

        if val is not None:
            session = sensor['session']
            command = '%s LOGIN_FAILED %s %s %s %s' % (val, session['auth']['date_time'], session['peer_ip'],
                                                       session['auth']['username'], session['auth']['password'])
            self.runCommand(command)

    def channel_opened(self, sensor):
        prop = ['output-app_hooks', 'channel_opened']
        val = self._checkProp(prop)

        if val is not None:
            channel = sensor['session']['channel']
            command = '%s CHANNEL_OPENED %s %s %s' % (val, channel['start_time'], channel['name'], channel['uuid'])
            self.runCommand(command)

    def channel_closed(self, sensor):
        channel = sensor['session']['channel']

        prop = ['output-app_hooks', 'channel_closed']
        val = self._checkProp(prop)

        if val is not None:
            command = '%s CHANNEL_CLOSED %s %s %s' % (val, channel['end_time'], channel['name'], channel['uuid'])
            self.runCommand(command)

        if 'ttylog_file' in channel:
            prop = ['output-app_hooks', 'ttylog_closed']
            val = self._checkProp(prop)

            if val is not None:
                command = '%s TTYLOG_CLOSED %s %s' % (val, sensor['sensor_name'], channel['ttylog_file'])
                self.runCommand(command)

    def command_entered(self, sensor):
        prop = ['output-app_hooks', 'command_entered']
        val = self._checkProp(prop)

        if val is not None:
            channel = sensor['session']['channel']
            command = '%s COMMAND_ENTERED %s %s \'%s\'' % (val, channel['command']['date_time'], channel['uuid'],
                                                           channel['command']['command'])
            self.runCommand(command)

    def download_started(self, sensor):
        prop = ['output-app_hooks', 'download_started']
        val = self._checkProp(prop)

        if val is not None:
            channel = sensor['session']['channel']
            download = channel['download']
            command = '%s DOWNLOAD_STARTED %s %s %s %s' % (val, download['start_time'], channel['uuid'],
                                                           download['link'], download['file'])
            self.runCommand(command)

    def download_finished(self, sensor):
        prop = ['output-app_hooks', 'download_finished']
        val = self._checkProp(prop)

        if val is not None:
            channel = sensor['session']['channel']
            download = channel['download']
            command = '%s DOWNLOAD_FINISHED %s %s %s %s' % (val, download['end_time'], channel['uuid'],
                                                            download['link'], download['file'])
            self.runCommand(command)

    def validate_config(self):
        props = [['output-app_hooks', 'enabled']]

        for prop in props:
            if not self.cfg.check_exist(prop, validation.check_valid_boolean) or not self.cfg.getboolean(prop):
                return False
        return True

    def runCommand(self, command):
        sp = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        sp.communicate()
