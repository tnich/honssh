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

from twisted.internet import reactor
from twisted.internet import threads

from honssh import base_auth_handler
from honssh import client
from honssh import log
from honssh import plugins


class PreAuth(base_auth_handler.BaseAuth):
    def __init__(self, server):
        super(PreAuth, self).__init__(server, 'PRE_AUTH')

        self.sensor_name = None
        self.honey_ip = None
        self.honey_port = None

    def start(self):
        self.conn_details = {'peer_ip': self.server.peer_ip, 'peer_port': self.server.peer_port,
                             'local_ip': self.server.local_ip, 'local_port': self.server.local_port}

        conn_details_defer = threads.deferToThread(self.get_conn_details)
        conn_details_defer.addCallback(self.connect_to_pot)

    def connect_to_pot(self, returned_conn_details):
        if returned_conn_details:
            if returned_conn_details['success']:
                self.sensor_name = returned_conn_details['sensor_name']
                self.honey_ip = returned_conn_details['honey_ip']
                self.honey_port = returned_conn_details['honey_port']
                self.connection_timeout = returned_conn_details['connection_timeout']

                if not self.server.disconnected:
                    log.msg(log.LGREEN, '[PRE_AUTH]',
                            'Connecting to Honeypot: %s (%s:%s)' % (self.sensor_name, self.honey_ip, self.honey_port))
                    client_factory = client.HonsshClientFactory()
                    client_factory.server = self.server
                    bind_ip = self.server.net.setup_networking(self.server.peer_ip, self.honey_ip, self.honey_port)
                    self.networkingSetup = True
                    reactor.connectTCP(self.honey_ip, self.honey_port, client_factory,
                                       bindAddress=(bind_ip, self.server.peer_port + 2),
                                       timeout=self.connection_timeout)

                    pot_connect_defer = threads.deferToThread(self.is_pot_connected)
                    pot_connect_defer.addCallback(self.pot_connected)
            else:
                log.msg(log.LRED, '[PRE_AUTH][ERROR]', 'PLUGIN ERROR - DISCONNECTING ATTACKER')
                self.server.loseConnection()
        else:
            log.msg(log.LRED, '[PRE_AUTH][ERROR]', 'PLUGIN ERROR - DISCONNECTING ATTACKER')
            self.server.loseConnection()

    def pot_connected(self, success):
        if success:
            if not self.server.disconnected:
                self.server.connection_init(self.sensor_name, self.honey_ip, self.honey_port)
                self.server.connection_setup()
                log.msg(log.LGREEN, '[PRE_AUTH]', 'CLIENT CONNECTED, REPLAYING BUFFERED PACKETS')
                for packet in self.delayedPackets:
                    self.server.sshParse.parse_packet("[SERVER]", packet[0], packet[1])
                self.finishedSending = True
            else:
                self.server.client.loseConnection()
        else:
            log.msg(log.LRED, '[PRE_AUTH][ERROR]',
                    'COULD NOT CONNECT TO HONEYPOT AFTER %s SECONDS - DISCONNECTING CLIENT' % (self.connection_timeout))
            self.server.loseConnection()

    def connection_lost(self):
        if not self.server.post_auth_started:
            self.server.disconnected = True
            if self.networkingSetup:
                self.server.net.remove_networking(self.server.factory.connections.connections)

            if self.auth_plugin is not None:
                if self.server.clientConnected:
                    plugins.run_plugins_function([self.auth_plugin], 'connection_lost', True, self.conn_details)
        else:
            if self.auth_plugin is not None:
                plugins.run_plugins_function([self.auth_plugin], 'connection_lost', True, self.conn_details)
