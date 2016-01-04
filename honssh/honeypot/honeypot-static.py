from honssh import config


class Plugin():
    
    def __init__(self, cfg):
        self.cfg = cfg

    def get_connection_details(self, conn_details):
        success = True
        sensor_name = self.cfg.get('honeypot-static', 'sensor_name')
        honey_ip = self.cfg.get('honeypot-static', 'honey_ip')
        honey_port = int(self.cfg.get('honeypot-static', 'honey_port'))
        
        return {'success':success, 'sensor_name':sensor_name, 'honey_ip':honey_ip, 'honey_port':honey_port}

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