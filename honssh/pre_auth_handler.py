# Copyright (c) 2013 Thomas Nicholson <tnnich@googlemail.com>
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

from twisted.python import log
from twisted.internet import threads
from twisted.internet import reactor

import time

from honssh import plugins
from honssh import client

class Pre_Auth():
    
    def __init__(self, server):
        self.server = server
        
        self.cfg = self.server.cfg
        
        self.sensor_name = ''
        self.honey_ip = ''
        self.honey_port = ''
        
        self.disconnected = False
        self.networkingSetup = False

        self.finishedSending = False
        self.delayedPackets = []
        
        self.conn_details = {'peer_ip':self.server.peer_ip, 'peer_port':self.server.peer_port, 'local_ip':self.server.local_ip, 'local_port':self.server.local_port}
        
        conn_details_defer = threads.deferToThread(self.get_conn_details)
        conn_details_defer.addCallback(self.connect_to_pot)

    def get_conn_details(self):
        plugin_list = plugins.get_plugin_list(type='honeypot')
        self.pre_auth_plugin = plugins.import_pre_auth_plugins(plugin_list, self.cfg)
        if self.pre_auth_plugin == None:
            log.msg('[PRE-AUTH] NO PLUGIN ENABLED FOR PRE-AUTH')
            return {'success':False}
        else:
            return plugins.run_plugins_function(self.pre_auth_plugin, 'get_connection_details', False, self.conn_details)

    def connect_to_pot(self, returned_conn_details):
        if returned_conn_details['success']:
            self.sensor_name = returned_conn_details['sensor_name']
            self.honey_ip = returned_conn_details['honey_ip']
            self.honey_port = returned_conn_details['honey_port']
            
            if not self.disconnected:
                log.msg('[PRE_AUTH] Connecting to Honeypot: %s (%s:%s)' % (self.sensor_name, self.honey_ip, self.honey_port))
                client_factory = client.HonsshClientFactory()
                client_factory.server = self.server
                self.bind_ip = self.server.net.setupNetworking(self.server.peer_ip, self.honey_ip, self.honey_port)
                self.networkingSetup = True
                reactor.connectTCP(self.honey_ip, self.honey_port, client_factory, bindAddress=(self.bind_ip, self.server.peer_port), timeout=10)

                pot_connect_defer = threads.deferToThread(self.is_pot_connected)
                pot_connect_defer.addCallback(self.pot_connected)
        else:
            log.msg("[PRE_AUTH][ERROR] PLUGIN ERROR - DISCONNECTING ATTACKER")
            self.server.loseConnection()
    
    def is_pot_connected(self):
        self.timeoutCount = 0
        while not self.server.clientConnected:
            time.sleep(0.5)
            self.timeoutCount = self.timeoutCount + 0.5
            if self.timeoutCount == 10:
                break
        return self.server.clientConnected
        
    def pot_connected(self, success):
        if success:
            if not self.disconnected:
                self.server.connection_setup(self.sensor_name, self.honey_ip, self.honey_port)
                
                log.msg("[PRE_AUTH] CLIENT CONNECTED, REPLAYING BUFFERED PACKETS")
                for packet in self.delayedPackets:
                    self.server.sshParse.parsePacket("[SERVER]", packet[0], packet[1])
                self.finishedSending = True
            else:
                self.server.client.loseConnection()
        else:
            log.msg("[PRE_AUTH][ERROR] COULD NOT CONNECT TO HONEYPOT AFTER 10 SECONDS - DISCONNECTING CLIENT")
            self.server.loseConnection()
        
    def connection_lost(self):
        self.disconnected = True
        if self.networkingSetup:
            self.server.net.removeNetworking(self.server.factory.connections.connections)
        
        if self.pre_auth_plugin:
            plugins.run_plugins_function(self.pre_auth_plugin, 'connection_lost', True, self.conn_details)
