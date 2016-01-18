from honssh import log
from honssh import plugins

import time

class Base_Auth():
    
    def __init__(self, server):
        self.server = server
        self.auth_plugin = None
        self.cfg = self.server.cfg
        
        self.finishedSending = False
        self.delayedPackets = []
        self.networkingSetup = False
        
    def get_conn_details(self):
        plugin_list = plugins.get_plugin_list(type='honeypot')
        self.auth_plugin = plugins.import_auth_plugins(self.name, plugin_list, self.cfg)
        if self.auth_plugin == None:
            log.msg(log.LRED, '[' + self.name + ']', 'NO PLUGIN ENABLED FOR ' + self.name)
            return {'success':False}
        else:
            return plugins.run_plugins_function(self.auth_plugin, 'get_' + self.name.lower() + '_details', False, self.conn_details)
        
    def is_pot_connected(self):
        self.timeoutCount = 0
        while not self.server.clientConnected:
            time.sleep(0.5)
            self.timeoutCount = self.timeoutCount + 0.5
            if self.timeoutCount == 10:
                break
        return self.server.clientConnected