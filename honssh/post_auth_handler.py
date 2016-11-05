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

from honssh import base_auth_handler
from twisted.internet import threads
from twisted.internet import reactor
from honssh import plugins
from honssh import client
from honssh import log

class Post_Auth(base_auth_handler.Base_Auth):
    
    def __init__(self, server):   
        self.name = 'POST_AUTH'     
        base_auth_handler.Base_Auth.__init__(self, server)
        self.send_auth = False
        self.username = False
        self.password = False
        
        self.auth_packet_number = 0
        
    def start(self, username, password):
        self.conn_details = {'peer_ip':self.server.peer_ip, 'peer_port':self.server.peer_port, 'local_ip':self.server.local_ip, 'local_port':self.server.local_port, 'username':username, 'password':password}

        conn_details_defer = threads.deferToThread(self.get_conn_details)
        conn_details_defer.addCallback(self.connect_to_pot)
        
    def connect_to_pot(self, returned_conn_details):
        if returned_conn_details:
            if returned_conn_details['success']:
                self.sensor_name = returned_conn_details['sensor_name']
                self.honey_ip = returned_conn_details['honey_ip']
                self.honey_port = returned_conn_details['honey_port']
                self.username = returned_conn_details['username']
                self.password = returned_conn_details['password']
                connection_timeout = returned_conn_details['connection_timeout']

                self.auth_packets = [[5, self.to_string('ssh-userauth')], [50, self.to_string(self.username) + self.to_string('ssh-connection') + self.to_string('none')]]
                
                if self.sensor_name == self.server.sensor_name and self.honey_ip == self.server.honey_ip and self.honey_port == self.server.honey_port:
                    log.msg(log.LGREEN, '[POST_AUTH]', 'Details the same as pre-auth, not re-directing')
                    self.dont_post_auth()
                else:             
                    self.server.client.loseConnection()  
                    self.server.clientConnected = False
                    if not self.server.disconnected:
                        log.msg(log.LGREEN, '[POST_AUTH]', 'Connecting to Honeypot: %s (%s:%s)' % (self.sensor_name, self.honey_ip, self.honey_port))
                        client_factory = client.HonsshClientFactory()
                        client_factory.server = self.server
                        self.bind_ip = self.server.net.setupNetworking(self.server.peer_ip, self.honey_ip, self.honey_port)
                        self.networkingSetup = True
                        reactor.connectTCP(self.honey_ip, self.honey_port, client_factory, bindAddress=(self.bind_ip, self.server.peer_port+1), timeout=connection_timeout)
                        pot_connect_defer = threads.deferToThread(self.is_pot_connected)
                        pot_connect_defer.addCallback(self.pot_connected)
            else:
                log.msg(log.LBLUE, '[POST_AUTH]', 'SUCCESS = FALSE, NOT POST-AUTHING')
                self.dont_post_auth()
        else:
                log.msg(log.LRED, '[POST_AUTH][ERROR]', 'PLUGIN ERROR - DISCONNECTING ATTACKER')
                self.server.loseConnection()
    
    def pot_connected(self, success):
        if success:
            if not self.server.disconnected:
                self.send_next()
            else:
                self.server.client.loseConnection()
        else:
            log.msg(log.LRED, '[POST_AUTH][ERROR]', 'COULD NOT CONNECT TO HONEYPOT AFTER 10 SECONDS - DISCONNECTING CLIENT')
            self.server.loseConnection()
            
    def send_next(self):
        if self.auth_packet_number == len(self.auth_packets):
            self.send_login()
            self.server.connection_init(self.sensor_name, self.honey_ip, self.honey_port)
            self.server.connection_setup()
        else:
            packet = self.auth_packets[self.auth_packet_number]
            self.server.sshParse.parsePacket('[SERVER]', packet[0], packet[1])
        
        self.auth_packet_number = self.auth_packet_number + 1
            
    def to_string(self, message):
        return self.server.sshParse.stringToHex(message)
    
    def send_login(self):
        
        if self.username:
            if self.conn_details['username'] != self.username:
                log.msg(log.LPURPLE, '[POST_AUTH]', 'Spoofing Username')
                self.server.spoofed = True
        else:
            self.username = self.conn_details['username']
        if self.password:
            if self.conn_details['password'] != self.password:
                log.msg(log.LPURPLE, '[POST_AUTH]', 'Spoofing Password')
                self.server.spoofed = True
        else:
            self.password = self.conn_details['password']
        
        self.finishedSending = True
        self.server.post_auth_started = False
        packet = [50, self.to_string(self.username) + self.to_string('ssh-connection') + self.to_string('password') + '\x00' + self.to_string(self.password)]    
        self.server.sshParse.sendBack('[CLIENT]', packet[0], packet[1])
        
        if self.server.post_auth_started:
            log.msg(log.LGREEN, '[POST_AUTH]', 'CLIENT CONNECTED, REPLAYING BUFFERED PACKETS')
            for packet in self.delayedPackets:
                self.server.sshParse.parsePacket("[SERVER]", packet[0], packet[1])
        
    def connection_lost(self):
        self.server.disconnected = True
        if self.networkingSetup:
            self.server.net.removeNetworking(self.server.factory.connections.connections)
        
        if self.auth_plugin:
            if self.server.clientConnected:
                plugins.run_plugins_function(self.auth_plugin, 'connection_lost', True, self.conn_details)
                
    def dont_post_auth(self):
        self.server.post_auth_started = False
        self.auth_plugin = None
        self.send_login()
