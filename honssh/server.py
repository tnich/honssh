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
from honssh import log
from twisted.internet import reactor
from honssh import client, networking, honsshServer, connections, plugins
from honssh import output_handler
from honssh import pre_auth_handler
from honssh import post_auth_handler
from honssh.protocols import ssh
from honssh.config import config

class HonsshServerTransport(honsshServer.HonsshServer):
    cfg = config()
       
    def connectionMade(self):
        self.timeoutCount = 0
        self.interactors = []
        self.wasConnected = False

        self.out = output_handler.Output(self.factory)
        self.net = networking.Networking()
        
        self.sshParse = ssh.SSH(self, self.out)

        self.disconnected = False
        self.clientConnected = False
        self.post_auth_started = False
        self.spoofed = False
        
        self.peer_ip = self.transport.getPeer().host
        self.peer_port = self.transport.getPeer().port+1
        self.local_ip = self.transport.getHost().host
        self.local_port = self.transport.getHost().port
        
        self.pre_auth = pre_auth_handler.Pre_Auth(self)
        self.post_auth = post_auth_handler.Post_Auth(self)
        
        honsshServer.HonsshServer.connectionMade(self)
        
    def connectionLost(self, reason):
        try:
            self.client.loseConnection()       
        except:
            pass
        honsshServer.HonsshServer.connectionLost(self, reason)
        
        if self.wasConnected:       
            self.out.connectionLost()
            
    def ssh_KEXINIT(self, packet):
        return honsshServer.HonsshServer.ssh_KEXINIT(self, packet)
       
    def dispatchMessage(self, messageNum, payload):
        if honsshServer.HonsshServer.isEncrypted(self, "both"):
            if not self.post_auth_started:
                self.packet_buffer(self.pre_auth, messageNum, payload)
            else:
                self.packet_buffer(self.post_auth, messageNum, payload)
        else:                    
            honsshServer.HonsshServer.dispatchMessage(self, messageNum, payload)

    def packet_buffer(self, stage, messageNum, payload):
        if not self.clientConnected:
            log.msg(log.LPURPLE, '[SERVER]', 'CONNECTION TO HONEYPOT NOT READY, BUFFERING PACKET')
            stage.delayedPackets.append([messageNum, payload])
        else:
            if not stage.finishedSending:
                stage.delayedPackets.append([messageNum, payload])
            else:
                self.sshParse.parsePacket("[SERVER]", messageNum, payload)
        
    def sendPacket(self, messageNum, payload):
        honsshServer.HonsshServer.sendPacket(self, messageNum, payload)
        
    def connection_init(self, sensor_name, honey_ip, honey_port):
        self.sensor_name = sensor_name
        self.honey_ip = honey_ip
        self.honey_port = honey_port
        
    def connection_setup(self):
        self.wasConnected = True
        self.out.connectionMade(self.peer_ip, self.peer_port, self.honey_ip, self.honey_port, self.sensor_name)
        self.out.setVersion(self.otherVersionString)
        
    def start_post_auth(self, username, password):
        self.post_auth_started = True
        self.post_auth.start(username, password)
        

class HonsshServerFactory(factory.SSHFactory):
    cfg = config()
    otherVersionString = ''
    connections = connections.Connections()
    plugin_servers = []
    
    def __init__(self):
        self.ourVersionString = self.cfg.get('honeypot', 'ssh_banner')
        if self.ourVersionString == '':
            if self.cfg.get('honeypot-static', 'enabled') == 'true':
                log.msg(log.LPURPLE, '[SERVER]', 'Acquiring SSH Version String from honey_ip:honey_port')
                clientFactory = client.HonsshSlimClientFactory()
                clientFactory.server = self

                reactor.connectTCP(self.cfg.get('honeypot-static', 'honey_ip'), int(self.cfg.get('honeypot-static', 'honey_port')), clientFactory)
            elif self.cfg.get('honeypot-docker', 'enabled') == 'true':
                log.msg(log.LRED, '[SERVER][ERR]', 'You need to configure the ssh_banner for docker manually!')
        else:
            log.msg(log.LPURPLE, '[SERVER]', 'Using ssh_banner for SSH Version String: ' + self.ourVersionString)
        
        plugin_list = plugins.get_plugin_list(type='output')
        loaded_plugins = plugins.import_plugins(plugin_list, self.cfg)
        for plugin in loaded_plugins:
            plugin_server = plugins.run_plugins_function([plugin], 'start_server', False)
            plugin_name = plugins.get_plugin_name(plugin)
            self.plugin_servers.append({'name':plugin_name, 'server':plugin_server})
            
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
            
        t.supportedCiphers = ['aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-cbc', '3des-cbc', 'blowfish-cbc', 'cast128-cbc', 'aes192-cbc', 'aes256-cbc' ]
        t.supportedPublicKeys = ['ssh-rsa', 'ssh-dss']
        t.supportedMACs = [ 'hmac-md5', 'hmac-sha1']
        return t
