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

from honssh import config
from honssh import spoof

from docker import Client

from honssh import log

class Plugin():
    
    def __init__(self, cfg):
        self.cfg = cfg
        self.connection_timeout = int(self.cfg.get('honeypot','connection_timeout'))

    def get_pre_auth_details(self, conn_details):
        return self.get_connection_details()

    def get_post_auth_details(self, conn_details):
        success, username, password = spoof.get_connection_details(self.cfg, conn_details)

        if success:
            if self.cfg.get('honeypot-docker', 'pre-auth') == 'true':
                details = conn_details
                details['success'] = True
            else:
                details = self.get_connection_details()
            details['username'] = username
            details['password'] = password
            details['connection_timeout'] = self.connection_timeout
        else:
            details = {'success':False}
        return details
        
    def get_connection_details(self):
        socket = self.cfg.get('honeypot-docker', 'uri')
        image = self.cfg.get('honeypot-docker', 'image')
        launch_cmd = self.cfg.get('honeypot-docker', 'launch_cmd')
        hostname = self.cfg.get('honeypot-docker', 'hostname')
        honey_port = config.get_int(self.cfg, 'honeypot-docker', 'honey_port')
        pids_limit = config.get_int(self.cfg, 'honeypot-docker', 'pids_limit')
        mem_limit = self.cfg.get('honeypot-docker', 'mem_limit')
        memswap_limit = self.cfg.get('honeypot-docker', 'memswap_limit')
        shm_size = self.cfg.get('honeypot-docker', 'shm_size')
        cpu_period = config.get_int(self.cfg, 'honeypot-docker', 'cpu_period')
        cpu_shares = config.get_int(self.cfg, 'honeypot-docker', 'cpu_shares')
        cpuset_cpus = self.cfg.get('honeypot-docker', 'cpuset_cpus')

        self.docker_drive = docker_driver(socket, image, launch_cmd, hostname, pids_limit, mem_limit, memswap_limit, shm_size, 
                                                cpu_period, cpu_shares, cpuset_cpus)
        self.container = self.docker_drive.launch_container()

        log.msg(log.LCYAN, '[PLUGIN][DOCKER]', 'Launched container (%s, %s)' % (self.container['ip'], self.container['id']))
        sensor_name = hostname
        honey_ip = self.container['ip']

        return {'success':True, 'sensor_name':sensor_name, 'honey_ip':honey_ip, 'honey_port':honey_port, 'connection_timeout':self.connection_timeout}
    
    def connection_lost(self, conn_details):
        log.msg(log.LCYAN, '[PLUGIN][DOCKER]', 'Stopping container (%s, %s)' % (self.container['ip'], self.container['id']))
        self.docker_drive.teardown_container()
        
    def validate_config(self):
        props = [['honeypot-docker','enabled'], ['honeypot-docker','pre-auth'], ['honeypot-docker','post-auth']]
        for prop in props:
            if not config.checkExist(self.cfg,prop) or not config.checkValidBool(self.cfg, prop):
                return False
            
        props = [['honeypot-docker','image'], ['honeypot-docker','uri'], ['honeypot-docker','hostname'], ['honeypot-docker','launch_cmd'], ['honeypot-docker','honey_port']]
        for prop in props:
            if not config.checkExist(self.cfg,prop):
                return False 

        return True


class docker_driver():
    def __init__(self, socket, image, launch_cmd, hostname, pids_limit, mem_limit, memswap_limit, shm_size, cpu_period, 
                        cpu_shares, cpuset_cpus):
        self.container_id = 0
        self.connection = None
        self.socket = socket
        self.image = image
        self.hostname = hostname
        self.launch_cmd = launch_cmd
        self.pids_limit = pids_limit
        self.mem_limit = mem_limit
        self.memswap_limit = memswap_limit
        self.shm_size = shm_size
        self.cpu_period = cpu_period
        self.cpu_shares = cpu_shares
        self.cpuset_cpus = cpuset_cpus
        self.make_connection()
    
    def make_connection(self):
        self.connection = Client(self.socket)
        
    def launch_container(self):
        host_config = self.connection.create_host_config(pids_limit=self.pids_limit, mem_limit=self.mem_limit,
                                                                memswap_limit=self.memswap_limit, shm_size=self.shm_size,
                                                                cpu_period=self.cpu_period, cpu_shares=self.cpu_shares,
                                                                cpuset_cpus=self.cpuset_cpus)
        self.container_id = self.connection.create_container(image=self.image, tty=True, hostname=self.hostname, host_config=host_config)['Id']
        self.connection.start(self.container_id)
        exec_id = self.connection.exec_create(self.container_id, self.launch_cmd)['Id']
        self.connection.exec_start(exec_id, tty=True)
        container_data = self.connection.inspect_container(self.container_id)
        return {"id": self.container_id,
                "ip": container_data['NetworkSettings']['Networks']['bridge']['IPAddress']}
              
    def teardown_container(self):
        self.connection.stop(self.container_id)
