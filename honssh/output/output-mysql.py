from honssh import config

from kippo.dblog import mysql
from twisted.python import log

import datetime
import time

class Plugin():

    def __init__(self, cfg):
        self.cfg = cfg
        
    def start_server(self):
        return mysql.ReconnectingConnectionPool('MySQLdb',
            host = self.cfg.get('output-mysql', 'host'),
            db = self.cfg.get('output-mysql', 'database'),
            user = self.cfg.get('output-mysql', 'username'),
            passwd = self.cfg.get('output-mysql', 'password'),
            port = int(self.cfg.get('output-mysql', 'port')),
            cp_min = 1,
            cp_max = 1)
            
    def set_server(self, server):
        self.server = server
          
    def connection_lost(self, sensor):
        session = sensor['session']
        self.simpleQuery('UPDATE `sessions` SET `endtime` = FROM_UNIXTIME(%s) WHERE `id` = %s', (self.nowUnix(session['end_time']), session['session_id']))
    
    def login_successful(self, sensor):
        auth = sensor['session']['auth']
        self.simpleQuery('INSERT INTO `auth` (`success`, `username`, `password`, `timestamp`) VALUES (%s, %s, %s, FROM_UNIXTIME(%s))', ( 1, auth['username'], auth['password'], self.nowUnix(auth['date_time'])))
        
        r = yield self.db.runQuery('SELECT `id` FROM `sensors` WHERE `ip` = %s AND `name` = %s AND `port` = %s', (sensor['honey_ip'], sensor['sensor_name'], sensor['honey_port']))
        if r:
            id = r[0][0]
        else:
            yield self.db.runQuery('INSERT INTO `sensors` (`ip`, `name`, `port`) VALUES (%s, %s, %s)', (sensor['honey_ip'], sensor['sensor_name'], sensor['honey_port']))
            r = yield self.db.runQuery('SELECT LAST_INSERT_ID()')
            id = int(r[0][0])
        # now that we have a sensorID, continue creating the session
        session = sensor['session']
        self.simpleQuery('INSERT INTO `sessions` (`id`, `starttime`, `sensor`, `ip`, `port`) VALUES (%s, FROM_UNIXTIME(%s), %s, %s, %s)', (session['session_id'], self.nowUnix(session['start_time']), id, session['peer_ip'], session['peer_port']))    
        
        r = yield self.db.runQuery('SELECT `id` FROM `clients` WHERE `version` = %s', (session['version']))
        if r:
            id = int(r[0][0])
        else:
            yield self.db.runQuery('INSERT INTO `clients` (`version`) VALUES (%s)', (session['version']))
            r = yield self.db.runQuery('SELECT LAST_INSERT_ID()')
            id = int(r[0][0])
        self.simpleQuery('UPDATE `sessions` SET `client` = %s WHERE `id` = %s', (id, session['session_id']))

    def login_failed(self, sensor):
        auth = sensor['session']['auth']
        self.simpleQuery('INSERT INTO `auth` (`success`, `username`, `password`, `timestamp`) VALUES (%s, %s, %s, FROM_UNIXTIME(%s))', ( 0, auth['username'], auth['password'], self.nowUnix(auth['date_time'])))
    
    def channel_opened(self, sensor):
        channel = sensor['session']['channel']
        self.simpleQuery('INSERT INTO `channels` (`id`, `type`, `starttime`, `sessionid`) VALUES (%s, %s, FROM_UNIXTIME(%s), %s)', (channel['channel_id'], channel['name'], self.nowUnix(channel['start_time']), sensor['session']['session_id']))
    
    def channel_closed(self, sensor):
        channel = sensor['session']['channel']
        self.simpleQuery('UPDATE `channels` SET `endtime` = FROM_UNIXTIME(%s) WHERE `id` = %s', (self.nowUnix(channel['end_time']), channel['channel_id']))
        if 'ttylog_file' in channel:            
            fp = open(channel['ttylog_file'], 'rb')
            ttydata = fp.read()
            fp.close()
            self.simpleQuery('INSERT INTO `ttylog` (`channelid`, `ttylog`) VALUES (%s, %s)', (channel['channel_id'], ttydata))
    
    def command_entered(self, sensor):
        channel = sensor['session']['channel']
        command = channel['command']
        self.simpleQuery('INSERT INTO `commands` (`timestamp`, `channelid`, `command`) VALUES (FROM_UNIXTIME(%s), %s, %s)', (self.nowUnix(command['date_time']), channel['channel_id'], command['command']))

    def download_finished(self, sensor):
        channel = sensor['session']['channel']
        download = channel['download']
        self.simpleQuery('INSERT INTO `downloads` (`channelid`, `timestamp`, `link`, `outfile`) VALUES (%s, FROM_UNIXTIME(%s), %s, %s)', (channel['channel_id'], self.nowUnix(download['start_time']), download['link'], download['file']))
        
    
    def sqlerror(self, error):
        log.msg('[PLUGIN][MYSQL] SQL Error:' + str(error.value))

    def simpleQuery(self, sql, args):
        """ Just run a deferred sql query, only care about errors """
        d = self.server.runQuery(sql, args)
        d.addErrback(self.sqlerror)
        
    def nowUnix(self, dt):
        """return the current UTC time as an UNIX timestamp"""
        return int(time.mktime(datetime.datetime.strptime(dt,"%Y%m%d_%H%M%S_%f").timetuple()))
    
    
    def validate_config(self):
        props = [['output-mysql','enabled']]
        for prop in props:
            if not config.checkExist(self.self.cfg,prop) or not config.checkValidBool(self.self.cfg, prop):
                return False    
        
        #If output-mysql is enabled check it's config
        if self.cfg.get('output-mysql','enabled') == 'true':
            prop = ['output-mysql','port']
            if not config.checkExist(self.cfg,prop) or not config.checkValidPort(self.cfg,prop):
                return False
            props = [['output-mysql','host'], ['output-mysql','database'], ['output-mysql','username'], ['output-mysql','password']]
            for prop in props:
                if not config.checkExist(self.cfg,prop):
                    return False
        return True