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

import sys
import os

from twisted.internet import reactor
from twisted.conch.ssh.keys import Key
from twisted.python import log
from twisted.application import internet, service

from honssh.config import Config
from honssh import server, interact

if not os.path.exists('honssh.cfg'):
    print '[ERR][FATAL] honssh.cfg is missing!'
    sys.exit(1)

cfg = Config.getInstance()

'''
Check to activate dev mode
'''
devmode_prop = ['devmode', 'enabled']
if cfg.has_option(devmode_prop[0], devmode_prop[1]) and cfg.getboolean(devmode_prop):
    log.startLogging(sys.stdout, setStdout=0)

'''
Validate configuration
'''
if not cfg.validate_config():
    sys.exit(1)

ssh_addr = cfg.get(['honeypot', 'ssh_addr'])

'''
Log and session paths
'''
log_path = cfg.get(['folders', 'log_path'])
if not os.path.exists(log_path):
    os.makedirs(log_path)
    os.chmod(log_path, 0755)

session_path = cfg.get(['folders', 'session_path'])
if not os.path.exists(session_path):
    os.makedirs(session_path)
    os.chmod(session_path, 0755)

'''
Read public and private keys
'''
with open(cfg.get(['honeypot', 'private_key'])) as privateBlobFile:
    privateBlob = privateBlobFile.read()
    privateKey = Key.fromString(data=privateBlob)

with open(cfg.get(['honeypot', 'public_key'])) as publicBlobFile:
    publicBlob = publicBlobFile.read()
    publicKey = Key.fromString(data=publicBlob)

with open(cfg.get(['honeypot', 'private_key_dsa'])) as privateBlobFile:
    privateBlob = privateBlobFile.read()
    privateKeyDSA = Key.fromString(data=privateBlob)

with open(cfg.get(['honeypot', 'public_key_dsa'])) as publicBlobFile:
    publicBlob = publicBlobFile.read()
    publicKeyDSA = Key.fromString(data=publicBlob)

'''
Startup server factory
'''
serverFactory = server.HonsshServerFactory()
serverFactory.privateKeys = {'ssh-rsa': privateKey, 'ssh-dss': privateKeyDSA}
serverFactory.publicKeys = {'ssh-rsa': publicKey, 'ssh-dss': publicKeyDSA}

'''
Start up server
'''
ssh_port_prop = ['honeypot', 'ssh_port']
if cfg.has_option(devmode_prop[0], devmode_prop[1]) and cfg.getboolean(devmode_prop):
    reactor.listenTCP(cfg.getint(ssh_port_prop), serverFactory, interface=ssh_addr)
else:
    application = service.Application('honeypot')
    service = internet.TCPServer(cfg.getint(ssh_port_prop), serverFactory, interface=ssh_addr)
    service.setServiceParent(application)

'''
Start interaction server if enabled
'''
if cfg.getboolean(['interact', 'enabled']):
    interact_interface_prop = ['interact', 'interface']
    iport = cfg.getint(['interact', 'port'])

    if cfg.has_option(devmode_prop[0], devmode_prop[1]) and cfg.getboolean(devmode_prop):
        reactor.listenTCP(iport, interact.make_interact_factory(serverFactory),
                          interface=cfg.get(interact_interface_prop))
    else:
        service = internet.TCPServer(iport, interact.make_interact_factory(serverFactory),
                                     interface=cfg.get(interact_interface_prop))
        service.setServiceParent(application)

if cfg.has_option(devmode_prop[0], devmode_prop[1]) and cfg.getboolean(devmode_prop):
    reactor.run()
