#!/usr/bin/env python

# Copyright (c) 2015 Robert Putt (http://www.github.com/robputt796)
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

from honssh import spoof
from honssh.config import Config
from honssh.utils import validation
from .docker_utils import docker_cleanup
from .docker_utils.docker_driver import DockerDriver


class Plugin(object):
    def __init__(self):
        self.cfg = Config.getInstance()
        self.connection_timeout = self.cfg.getint(['honeypot', 'connection_timeout'])
        self.docker_drive = None
        self.container = None
        self.sensor_name = None
        self.peer_ip = None
        self.channel_open = False
        self.is_local_docker = True

    def get_pre_auth_details(self, conn_details):
        return self.get_connection_details(conn_details)

    def get_post_auth_details(self, conn_details):
        success, username, password = spoof.get_connection_details(conn_details)
        if success:
            if self.container is None:
                details = self.get_connection_details(conn_details)
            else:
                details = conn_details
                details['success'] = True

            details['username'] = username
            details['password'] = password
            details['connection_timeout'] = self.connection_timeout
        else:
            details = {'success': False}

        return details

    def get_connection_details(self, conn_details):
        self.peer_ip = conn_details['peer_ip']

        uri = self.cfg.get(['honeypot-docker', 'uri'])
        image = self.cfg.get(['honeypot-docker', 'image'])
        launch_cmd = self.cfg.get(['honeypot-docker', 'launch_cmd'])
        self.sensor_name = self.cfg.get(['honeypot-docker', 'hostname'])
        honey_port = self.cfg.getint(['honeypot-docker', 'honey_port'])
        pids_limit = self.cfg.getint(['honeypot-docker', 'pids_limit'])
        mem_limit = self.cfg.get(['honeypot-docker', 'mem_limit'])
        memswap_limit = self.cfg.get(['honeypot-docker', 'memswap_limit'])
        shm_size = self.cfg.get(['honeypot-docker', 'shm_size'])
        cpu_period = self.cfg.getint(['honeypot-docker', 'cpu_period'])
        cpu_shares = self.cfg.getint(['honeypot-docker', 'cpu_shares'])
        cpuset_cpus = self.cfg.get(['honeypot-docker', 'cpuset_cpus'])
        reuse_container = self.cfg.get(['honeypot-docker', 'reuse_container'])

        self.is_local_docker = uri.startswith('unix://') or uri.startswith('http+unix://')

        self.docker_drive = DockerDriver(uri, image, launch_cmd, self.sensor_name, pids_limit, mem_limit, memswap_limit,
                                         shm_size, cpu_period, cpu_shares, cpuset_cpus, self.peer_ip, reuse_container)
        self.container = self.docker_drive.launch_container()

        honey_ip = self.container['ip']

        return {'success': True, 'sensor_name': self.sensor_name, 'honey_ip': honey_ip, 'honey_port': honey_port,
                'connection_timeout': self.connection_timeout}

    def login_successful(self):
        self.channel_open = True

        if self.is_local_docker:
            '''
            FIXME: Currently output_handler and this plugin do both construct the session folder path. This should be encapsulated.
            '''
            overlay_folder = self.cfg.get(['honeypot-docker', 'overlay_folder'])
            max_filesize = self.cfg.getint(['honeypot-docker', 'overlay_max_filesize'], 51200)
            use_revisions = self.cfg.getboolean(['honeypot-docker', 'overlay_use_revisions'])

            if self.docker_drive.watcher is None and len(overlay_folder) > 0:
                overlay_folder = '%s/%s/%s/%s' % \
                                 (self.cfg.get(['folders', 'session_path']),
                                  self.sensor_name,
                                  self.peer_ip,
                                  overlay_folder)

                self.docker_drive.start_watcher(overlay_folder, max_filesize, use_revisions)

    def connection_lost(self, conn_details):
        self.docker_drive.teardown_container(not self.channel_open)

    def start_server(self):
        if self.cfg.getboolean(['honeypot-docker', 'enabled']) and self.cfg.getboolean(['honeypot-docker', 'reuse_container']):
            ttl_prop = ['honeypot-docker', 'reuse_ttl']
            ttl = self.cfg.get(ttl_prop)
            interval_prop = ['honeypot-docker', 'reuse_ttl_check_interval']
            interval = self.cfg.get(interval_prop)

            ttl_valid = False
            interval_valid = False

            if len(ttl) > 0:
                ttl_valid = validation.check_valid_number(ttl_prop, ttl)

            if len(interval) > 0:
                interval_valid = validation.check_valid_number(interval_prop, interval)

            if ttl_valid and interval_valid:
                docker_cleanup.start_cleanup_loop(int(ttl), int(interval))
            elif ttl_valid:
                docker_cleanup.start_cleanup_loop(ttl=int(ttl))
            elif interval_valid:
                docker_cleanup.start_cleanup_loop(interval=int(interval))
            else:
                docker_cleanup.start_cleanup_loop()
        return None

    def validate_config(self):
        props = [['honeypot-docker', 'enabled'], ['honeypot-docker', 'pre-auth'], ['honeypot-docker', 'post-auth'],
                 ['honeypot-docker', 'reuse_container'], ['honeypot-docker', 'overlay_use_revisions']]
        for prop in props:
            if not self.cfg.check_exist(prop, validation.check_valid_boolean):
                return False

        props = [['honeypot-docker', 'image'], ['honeypot-docker', 'uri'], ['honeypot-docker', 'hostname'],
                 ['honeypot-docker', 'launch_cmd'], ['honeypot-docker', 'honey_port']]
        for prop in props:
            if not self.cfg.check_exist(prop):
                return False

        return True
