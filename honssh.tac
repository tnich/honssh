from twisted.internet import reactor
from twisted.conch.ssh.keys import Key
from twisted.python import log
from twisted.application import internet, service
import sys, os
from honssh import server
from kippo.core.config import config

if not os.path.exists('honssh.cfg'):
    print 'ERROR: honssh.cfg is missing!'
    sys.exit(1)

log.startLogging(sys.stdout, setStdout=0)
cfg = config()

#TODO: If extras voice check for python-espeak

ssh_addr = cfg.get('honeypot', 'ssh_addr')

if not os.path.exists(cfg.get('honeypot', 'log_path')):
    os.makedirs(cfg.get('honeypot', 'log_path'))
if not os.path.exists(cfg.get('honeypot', 'session_path')):
    os.makedirs(cfg.get('honeypot', 'session_path'))

with open(cfg.get('honeypot', 'private_key')) as privateBlobFile:
    privateBlob = privateBlobFile.read()
    privateKey = Key.fromString(data=privateBlob)

with open(cfg.get('honeypot', 'public_key')) as publicBlobFile:
    publicBlob = publicBlobFile.read()
    publicKey = Key.fromString(data=publicBlob)    
    
serverFactory = server.HonsshServerFactory()
serverFactory.privateKeys = {'ssh-rsa': privateKey}
serverFactory.publicKeys = {'ssh-rsa': publicKey}


application = service.Application('honeypot')
service = internet.TCPServer(int(cfg.get('honeypot', 'ssh_port')), serverFactory, interface=ssh_addr)
service.setServiceParent(application)
#reactor.listenTCP(int(cfg.get('honeypot', 'ssh_port')), serverFactory, interface=ssh_addr)

if cfg.get('honeypot', 'interact_enabled').lower() in ('yes', 'true', 'on'):
    iport = int(cfg.get('honeypot', 'interact_port'))
    from kippo.core import interact
    from twisted.internet import protocol
    service = internet.TCPServer(iport, interact.makeInteractFactory(serverFactory), interface=cfg.get('honeypot', 'interact_interface'))
    service.setServiceParent(application)
    #reactor.listenTCP(iport, interact.makeInteractFactory(serverFactory), interface=cfg.get('honeypot', 'interact_interface'))

#reactor.run()