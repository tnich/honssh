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
from honssh import spoof

class Plugin():
    
    def __init__(self, cfg):
        self.cfg = cfg
        
    def get_pre_auth_details(self, conn_details):
        return self.get_connection_details()
        
    def get_post_auth_details(self, conn_details):
        success, username, password = spoof.get_connection_details(self.cfg, conn_details)
        if success:
            details = self.get_connection_details()
            details['username'] = username
            details['password'] = password
        else:
            details = {'success':False}
        return details

    def get_connection_details(self):
        sensor_name = self.cfg.get('honeypot-static', 'sensor_name')
        honey_ip = self.cfg.get('honeypot-static', 'honey_ip')
        honey_port = int(self.cfg.get('honeypot-static', 'honey_port'))
        connection_timeout = int(self.cfg.get('honeypot','connection_timeout'))

        return {'success':True, 'sensor_name':sensor_name, 'honey_ip':honey_ip, 'honey_port':honey_port, 'connection_timeout':connection_timeout}

    def validate_config(self):
        props = [['honeypot-static','enabled'], ['honeypot-static','pre-auth'], ['honeypot-static','post-auth']]
        for prop in props:
            if not config.checkExist(self.cfg,prop) or not config.checkValidBool(self.cfg, prop):
                return False
            
        props = [['honeypot-static','honey_ip']]
        for prop in props:
            if not config.checkExist(self.cfg,prop) or not config.checkValidIP(self.cfg,prop):
                return False
            
        props = [['honeypot-static','honey_port']]
        for prop in props:
            if not config.checkExist(self.cfg,prop) or not config.checkValidPort(self.cfg,prop):
                return False 
            
        props = [['honeypot-static','sensor_name']]
        for prop in props:
            if not config.checkExist(self.cfg,prop):
                return False           

        return True    
