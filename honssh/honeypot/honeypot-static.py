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
        
        return {'success':True, 'sensor_name':sensor_name, 'honey_ip':honey_ip, 'honey_port':honey_port}

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