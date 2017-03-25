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

from twisted.conch.ssh import factory
from twisted.internet import reactor

from honssh import client, networking, honsshServer, connections, plugins
from honssh import log
from honssh import output_handler
from honssh import post_auth_handler
from honssh import pre_auth_handler
from honssh.config import Config
from honssh.protocols import ssh


class HonsshServerTransport(honsshServer.HonsshServer):
    def __init__(self):
        self.cfg = Config.getInstance()
        self.timeoutCount = 0
        self.interactors = []

        self.out = None
        self.net = None
        self.sshParse = None

        self.wasConnected = False
        self.disconnected = False
        self.clientConnected = False
        self.post_auth_started = False
        self.spoofed = False

        self.peer_ip = None
        self.peer_port = 0
        self.local_ip = None
        self.local_port = 0

        self.pre_auth = None
        self.post_auth = None

        self.sensor_name = None
        self.honey_ip = None
        self.honey_port = 0

    def connectionMade(self):
        self.out = output_handler.Output(self.factory)
        self.net = networking.Networking()

        self.sshParse = ssh.SSH(self, self.out)

        self.peer_ip = self.transport.getPeer().host
        self.peer_port = self.transport.getPeer().port + 1
        self.local_ip = self.transport.getHost().host
        self.local_port = self.transport.getHost().port

        self.pre_auth = pre_auth_handler.PreAuth(self)
        self.post_auth = post_auth_handler.PostAuth(self)

        # Get auth plugins
        plugin_list = plugins.get_plugin_list(plugin_type='honeypot')
        pre_auth_plugin = plugins.import_auth_plugin(self.pre_auth.name, plugin_list)
        post_auth_plugin = plugins.import_auth_plugin(self.post_auth.name, plugin_list)

        # Check pre auth plugin is set
        if pre_auth_plugin is None:
            log.msg(log.LRED, '[SERVER]', 'NO AUTH PLUGIN ENABLED FOR ' + self.pre_auth.name)
        else:
            self.pre_auth.auth_plugin = pre_auth_plugin

        # Check post auth plugin is set
        if post_auth_plugin is None:
            log.msg(log.LRED, '[SERVER]', 'NO AUTH PLUGIN ENABLED FOR ' + self.post_auth.name)
        else:
            self.post_auth.auth_plugin = post_auth_plugin

        # Check for same auth plugin
        if post_auth_plugin.__class__ is pre_auth_plugin.__class__:
            # Share auth plugin instance
            self.post_auth.auth_plugin = self.pre_auth.auth_plugin

        # Execute pre auth
        self.pre_auth.start()

        honsshServer.HonsshServer.connectionMade(self)

    def connectionLost(self, reason):
        try:
            self.client.loseConnection()
        except:
            pass
        honsshServer.HonsshServer.connectionLost(self, reason)

        if self.wasConnected:
            self.out.connection_lost()

    def ssh_KEXINIT(self, packet):
        return honsshServer.HonsshServer.ssh_KEXINIT(self, packet)

    def dispatchMessage(self, message_num, payload):
        if honsshServer.HonsshServer.isEncrypted(self, "both"):
            if not self.post_auth_started:
                self.packet_buffer(self.pre_auth, message_num, payload)
            else:
                self.packet_buffer(self.post_auth, message_num, payload)
        else:
            honsshServer.HonsshServer.dispatchMessage(self, message_num, payload)

    def packet_buffer(self, stage, message_num, payload):
        if not self.clientConnected:
            log.msg(log.LPURPLE, '[SERVER]', 'CONNECTION TO HONEYPOT NOT READY, BUFFERING PACKET')
            stage.delayedPackets.append([message_num, payload])
        else:
            if not stage.finishedSending:
                stage.delayedPackets.append([message_num, payload])
            else:
                self.sshParse.parse_packet("[SERVER]", message_num, payload)

    def sendPacket(self, message_num, payload):
        honsshServer.HonsshServer.sendPacket(self, message_num, payload)

    def connection_init(self, sensor_name, honey_ip, honey_port):
        self.sensor_name = sensor_name
        self.honey_ip = honey_ip
        self.honey_port = honey_port

    def connection_setup(self):
        self.wasConnected = True
        self.out.connection_made(self.peer_ip, self.peer_port, self.honey_ip, self.honey_port, self.sensor_name)
        self.out.set_version(self.otherVersionString)

    def start_post_auth(self, username, password, auth_type):
        self.post_auth_started = True
        self.post_auth.start(username, password, auth_type)

    def login_successful(self, username, password):
        self.post_auth.login_successful()

    def login_failed(self, username, password):
        self.post_auth.login_failed()


class HonsshServerFactory(factory.SSHFactory):
    def __init__(self):
        self.cfg = Config.getInstance()
        self.otherVersionString = ''
        self.connections = connections.Connections()
        self.plugin_servers = []
        self.ourVersionString = self.cfg.get(['honeypot', 'ssh_banner'])

        if len(self.ourVersionString) > 0:
            log.msg(log.LPURPLE, '[SERVER]', 'Using ssh_banner for SSH Version String: ' + self.ourVersionString)
        else:
            if self.cfg.getboolean(['honeypot-static', 'enabled']):
                log.msg(log.LPURPLE, '[SERVER]', 'Acquiring SSH Version String from honey_ip:honey_port')
                client_factory = client.HonsshSlimClientFactory()
                client_factory.server = self

                reactor.connectTCP(self.cfg.get(['honeypot-static', 'honey_ip']),
                                   int(self.cfg.get(['honeypot-static', 'honey_port'])), client_factory)
            elif self.cfg.getboolean(['honeypot-docker', 'enabled']):
                log.msg(log.LRED, '[SERVER][ERR]', 'You need to configure the ssh_banner for docker manually!')

        plugin_list = plugins.get_plugin_list()
        loaded_plugins = plugins.import_plugins(plugin_list)
        for plugin in loaded_plugins:
            plugin_server = plugins.run_plugins_function([plugin], 'start_server', False)
            plugin_name = plugins.get_plugin_name(plugin)
            self.plugin_servers.append({'name': plugin_name, 'server': plugin_server})

        if self.ourVersionString != '':
            log.msg(log.LGREEN, '[HONSSH]', 'HonSSH Boot Sequence Complete - Ready for attacks!')

    def buildProtocol(self, addr):
        t = HonsshServerTransport()

        t.ourVersionString = self.ourVersionString
        t.factory = self
        t.supportedPublicKeys = self.privateKeys.keys()

        if not self.primes:
            ske = t.supportedKeyExchanges[:]
            if 'diffie-hellman-group-exchange-sha1' in ske:
                ske.remove('diffie-hellman-group-exchange-sha1')
            if 'diffie-hellman-group-exchange-sha256' in ske:
                ske.remove('diffie-hellman-group-exchange-sha256')
            t.supportedKeyExchanges = ske

        t.supportedCiphers = ['aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-cbc', '3des-cbc', 'blowfish-cbc',
                              'cast128-cbc', 'aes192-cbc', 'aes256-cbc']
        t.supportedPublicKeys = ['ssh-rsa', 'ssh-dss']
        t.supportedMACs = ['hmac-md5', 'hmac-sha1']
        return t
