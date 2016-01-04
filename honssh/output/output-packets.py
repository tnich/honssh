from honssh import config

import os

class Plugin():

    def __init__(self, cfg):
        self.cfg = cfg
    
    def packet_logged(self, sensor):
        session = sensor['session']
        self.log_file = session['log_location'] + session['start_time'] + '.log-adv'
        packet = session['packet']
        self.adv_log(packet['date_time'], '%s - %s - %s' % (packet['direction'], packet['packet'].ljust(37), repr(packet['payload'])))

   
    def validate_config(self):
        props = [['output-packets','enabled']]
        for prop in props:
            if not config.checkExist(self.cfg,prop) or not config.checkValidBool(self.cfg, prop):
                return False
        return True


    def adv_log(self, dt, message):
        setPermissions = False
    
        if(os.path.isfile(self.log_file) == False):
            setPermissions = True
    
        f = file(self.log_file, 'a')
        f.write(dt + " - " + message + "\n")
        f.close()
 
        if(setPermissions):
            os.chmod(self.log_file, 0644)
