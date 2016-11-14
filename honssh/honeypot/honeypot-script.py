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

import subprocess

from honssh.config import Config
from honssh.utils import validation


class Plugin(object):
    def __init__(self):
        self.cfg = Config.getInstance()
        self.connection_timeout = self.cfg.getint(['honeypot', 'connection_timeout'])

    def get_pre_auth_details(self, conn_details):
        command = '%s %s %s %s %s' % (
            self.cfg.get(['honeypot-script', 'pre-auth-script']), conn_details['peer_ip'], conn_details['local_ip'],
            conn_details['peer_port'], conn_details['local_port'])

        sp = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        result = sp.communicate()
        if sp.returncode == 0:
            binder = result[0].split(',')
            sensor_name = binder[0].lstrip().strip()
            honey_ip = binder[1].lstrip().strip()
            honey_port = int(binder[2].lstrip().strip())

            return {'success': True, 'sensor_name': sensor_name, 'honey_ip': honey_ip, 'honey_port': honey_port,
                    'connection_timeout': self.connection_timeout}
        else:
            return {'success': False}

    def get_post_auth_details(self, conn_details):
        command = '%s %s %s %s %s %s %s' % (
            self.cfg.get(['honeypot-script', 'post-auth-script']), conn_details['peer_ip'], conn_details['local_ip'],
            conn_details['peer_port'], conn_details['local_port'], conn_details['username'], conn_details['password'])

        sp = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        result = sp.communicate()
        if sp.returncode == 0:
            binder = result[0].split(',')
            sensor_name = binder[0].lstrip().strip()
            honey_ip = binder[1].lstrip().strip()
            honey_port = int(binder[2].lstrip().strip())
            username = binder[3].lstrip().strip()
            password = binder[4].lstrip().strip()
            return {'success': True, 'sensor_name': sensor_name, 'honey_ip': honey_ip, 'honey_port': honey_port,
                    'username': username, 'password': password, 'connection_timeout': self.connection_timeout}
        else:
            return {'success': False}

    def validate_config(self):
        props = [['honeypot-script', 'enabled'], ['honeypot-script', 'pre-auth'], ['honeypot-script', 'post-auth']]
        for prop in props:
            if not self.cfg.check_exist(prop, validation.check_valid_boolean):
                return False

        if self.cfg.getboolean(['honeypot-script', 'pre-auth']):
            props = [['honeypot-script', 'pre-auth-script']]
            for prop in props:
                if not self.cfg.check_exist(prop):
                    return False

        if self.cfg.getboolean(['honeypot-script', 'post-auth']):
            props = [['honeypot-script', 'post-auth-script']]
            for prop in props:
                if not self.cfg.check_exist(prop):
                    return False

        return True
