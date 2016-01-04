from honssh import config

from twisted.python import log

import json
import urllib2

class Plugin():

    def __init__(self, cfg):
        self.cfg = cfg
        
    def connection_lost(self, sensor):
        sensor['session'].pop('log_location')

        for channel in sensor['session']['channels']:
            if 'class' in channel:
                channel.pop('class')
            if 'ttylog_file' in channel:
                fp = open(channel['ttylog_file'], 'rb')
                ttydata = fp.read()
                fp.close()
                channel['ttylog'] = ttydata.encode('hex')
                channel.pop('ttylog_file')
                
        self.post_json(sensor)
    
    def post_json(self, the_json):
        req = urllib2.Request('https://honssh.com/test/hello.php')
        req.add_header('Content-Type', 'application/json')
        req.add_header('User-Agent', 'HonSSH-Contribute')
        req.add_header('Accept', 'text/plain')
        response = urllib2.urlopen(req, json.dumps(the_json))
        log.msg('[PLUGIN][CONTRIBUTE] RESPONSE ' + str(response.read()))
        
    def validate_config(self):
        props = [['output-contribute','enabled']]
        for prop in props:
            if not config.checkExist(self.cfg,prop) or not config.checkValidBool(self.cfg, prop):
                return False
        return True
    