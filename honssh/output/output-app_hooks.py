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

from honssh import config

import subprocess

class Plugin():

    def __init__(self, cfg):
        self.cfg = cfg
  
    def connection_made(self, sensor):
        if self.cfg.has_option('output-app_hooks', 'connection_made'):
            if self.cfg.get('output-app_hooks', 'connection_made') != '':
                session = sensor['session']
                command = '%s CONNECTION_MADE %s %s %s %s %s %s' % (self.cfg.get('output-app_hooks', 'connection_made'), session['start_time'], session['peer_ip'], session['peer_port'], sensor['honey_ip'], sensor['honey_port'], session['session_id'])
                self.runCommand(command)
    
    def connection_lost(self, sensor):
        if self.cfg.has_option('output-app_hooks', 'connection_lost'):
            if self.cfg.get('output-app_hooks', 'connection_lost') != '':
                session = sensor['session']
                command = '%s CONNECTION_LOST %s %s %s %s %s %s' % (self.cfg.get('output-app_hooks', 'connection_lost'), session['end_time'], session['peer_ip'], session['peer_port'], sensor['honey_ip'], sensor['honey_port'], session['session_id'])
                self.runCommand(command)
  
    def login_successful(self, sensor):
        if self.cfg.has_option('output-app_hooks', 'login_successful'):
            if self.cfg.get('output-app_hooks', 'login_successful') != '':
                session = sensor['session']
                command = '%s LOGIN_SUCCESSFUL %s %s %s %s' % (self.cfg.get('output-app_hooks', 'login_successful'), session['auth']['date_time'], session['peer_ip'], session['auth']['username'], session['auth']['password'])
                self.runCommand(command)
    
    def login_failed(self, sensor):
        if self.cfg.has_option('output-app_hooks', 'login_failed'):
            if self.cfg.get('output-app_hooks', 'login_failed') != '':
                session = sensor['session']
                command = '%s LOGIN_FAILED %s %s %s %s' % (self.cfg.get('output-app_hooks', 'login_failed'), session['auth']['date_time'], session['peer_ip'], session['auth']['username'], session['auth']['password'])
                self.runCommand(command)
       
    def channel_opened(self, sensor):
        if self.cfg.has_option('output-app_hooks', 'channel_opened'):
            if self.cfg.get('output-app_hooks', 'channel_opened') != '':
                channel = sensor['session']['channel']
                command = '%s CHANNEL_OPENED %s %s %s' % (self.cfg.get('output-app_hooks', 'channel_opened'), channel['start_time'], channel['name'], channel['channel_id'])
                self.runCommand(command)
    
    def channel_closed(self, sensor):
        if self.cfg.has_option('output-app_hooks', 'channel_closed'):
            if self.cfg.get('output-app_hooks', 'channel_closed') != '':
                channel = sensor['session']['channel']
                command = '%s CHANNEL_CLOSED %s %s %s' % (self.cfg.get('output-app_hooks', 'channel_closed'), channel['end_time'], channel['name'], channel['channel_id'])
                self.runCommand(command)
    
    def command_entered(self, sensor):
        if self.cfg.has_option('output-app_hooks', 'command_entered'):
            if self.cfg.get('output-app_hooks', 'command_entered') != '':
                channel = sensor['session']['channel']
                command = '%s COMMAND_ENTERED %s %s \'%s\'' % (self.cfg.get('output-app_hooks', 'command_entered'), channel['command']['date_time'], channel['channel_id'], channel['command']['command'])
                self.runCommand(command)

    def download_started(self, sensor):
        if self.cfg.has_option('output-app_hooks', 'download_started'):
            if self.cfg.get('output-app_hooks', 'download_started') != '':
                channel = sensor['session']['channel']
                download = channel['download']
                command = '%s DOWNLOAD_STARTED %s %s %s %s' % (self.cfg.get('output-app_hooks', 'download_started'), download['start_time'], channel['channel_id'], download['link'], download['file'])
                self.runCommand(command)

    def download_finished(self, sensor):
        if self.cfg.has_option('output-app_hooks', 'download_finished'):
            if self.cfg.get('output-app_hooks', 'download_finished') != '':
                channel = sensor['session']['channel']
                download = channel['download']
                command = '%s DOWNLOAD_FINISHED %s %s %s %s' % (self.cfg.get('output-app_hooks', 'download_finished'), download['end_time'], channel['channel_id'], download['link'], download['file'])
                self.runCommand(command)
       
    def validate_config(self):
        props = [['output-app_hooks','enabled']]
        for prop in props:
            if not config.checkExist(self.cfg,prop) or not config.checkValidBool(self.cfg, prop):
                return False
        return True

    def runCommand(self, command):
        sp = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        sp.communicate()
