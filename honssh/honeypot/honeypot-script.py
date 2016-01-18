from honssh import config

import subprocess


class Plugin():
    
    def __init__(self, cfg):
        self.cfg = cfg

    def get_pre_auth_details(self, conn_details):
        command = '%s %s %s %s %s' % (self.cfg.get('honeypot-script', 'pre-auth-script'), conn_details['peer_ip'], conn_details['local_ip'], conn_details['peer_port'], conn_details['local_port'])
        sp = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        result = sp.communicate()
        if sp.returncode == 0:
            binder = result[0].split(',')
            sensor_name = binder[0].lstrip().strip()
            honey_ip = binder[1].lstrip().strip()
            honey_port = int(binder[2].lstrip().strip())
            return {'success':True, 'sensor_name':sensor_name, 'honey_ip':honey_ip, 'honey_port':honey_port}
        else:
            return {'success':False}
                
    def get_post_auth_details(self, conn_details):
        command = '%s %s %s %s %s %s %s' % (self.cfg.get('honeypot-script', 'post-auth-script'), conn_details['peer_ip'], conn_details['local_ip'], conn_details['peer_port'], conn_details['local_port'], conn_details['username'], conn_details['password'])
        sp = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        result = sp.communicate()
        if sp.returncode == 0:
            binder = result[0].split(',')
            sensor_name = binder[0].lstrip().strip()
            honey_ip = binder[1].lstrip().strip()
            honey_port = int(binder[2].lstrip().strip())
            username = binder[3].lstrip().strip()
            password = binder[4].lstrip().strip()
            return {'success':True, 'sensor_name':sensor_name, 'honey_ip':honey_ip, 'honey_port':honey_port, 'username':username, 'password':password}
        else:
            return {'success':False}

    def validate_config(self):
        props = [['honeypot-script','enabled'], ['honeypot-script','pre-auth'], ['honeypot-script','post-auth']]
        for prop in props:
            if not config.checkExist(self.cfg,prop) or not config.checkValidBool(self.cfg, prop):
                return False
        if self.cfg.get('honeypot-script','pre-auth') == 'true':
            props = [['honeypot-script','pre-auth-script']]
            for prop in props:
                if not config.checkExist(self.cfg,prop):
                    return False  
        if self.cfg.get('honeypot-script','post-auth') == 'true':
            props = [['honeypot-script','post-auth-script']]
            for prop in props:
                if not config.checkExist(self.cfg,prop):
                    return False 

        return True    