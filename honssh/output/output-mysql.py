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

from honssh.config import Config
from honssh.utils import validation
from honssh import log

import datetime
import time
import MySQLdb


class Plugin(object):
    def __init__(self):
        self.cfg = Config.getInstance()
        self.server = None

    def connect_dbserver(self):
        db = MySQLdb.connect(
            host=self.cfg.get(['output-mysql', 'host']),
            db=self.cfg.get(['output-mysql', 'database']),
            user=self.cfg.get(['output-mysql', 'username']),
            passwd=self.cfg.get(['output-mysql', 'password']),
            port=int(self.cfg.get(['output-mysql', 'port'])))
        db.ping(True)
        return db

    def set_server(self, server):
        self.server = server

    def connection_lost(self, sensor):
        session = sensor['session']
        self.insert('UPDATE `sessions` SET `endtime` = FROM_UNIXTIME(%s) WHERE `id` = %s',
                    (self.now_unix(session['end_time']), session['session_id']))

    def login_successful(self, sensor):
        auth = sensor['session']['auth']
        self.insert(
            'INSERT INTO `auth` (`success`, `username`, `password`, `timestamp`) VALUES (%s, %s, %s, FROM_UNIXTIME(%s))',
            (1, auth['username'], auth['password'], self.now_unix(auth['date_time'])))

        id = self.insert_sensor(sensor)
        # now that we have a sensorID, continue creating the session
        session = sensor['session']
        self.insert(
            'INSERT INTO `sessions` (`id`, `starttime`, `sensor`, `ip`, `port`) VALUES (%s, FROM_UNIXTIME(%s), %s, %s, %s)',
            (session['session_id'], self.now_unix(session['start_time']), id, session['peer_ip'], session['peer_port']))

        id = self.insert_client(session)
        self.insert('UPDATE `sessions` SET `client` = %s WHERE `id` = %s', (id, session['session_id']))

    def login_failed(self, sensor):
        auth = sensor['session']['auth']
        self.insert(
            'INSERT INTO `auth` (`success`, `username`, `password`, `timestamp`) VALUES (%s, %s, %s, FROM_UNIXTIME(%s))',
            (0, auth['username'], auth['password'], self.now_unix(auth['date_time'])))

    def channel_opened(self, sensor):
        channel = sensor['session']['channel']
        self.insert(
            'INSERT INTO `channels` (`id`, `type`, `starttime`, `sessionid`) VALUES (%s, %s, FROM_UNIXTIME(%s), %s)', (
            channel['uuid'], channel['name'], self.now_unix(channel['start_time']),
            sensor['session']['session_id']))

    def channel_closed(self, sensor):
        channel = sensor['session']['channel']
        self.insert('UPDATE `channels` SET `endtime` = FROM_UNIXTIME(%s) WHERE `id` = %s',
                    (self.now_unix(channel['end_time']), channel['uuid']))

        if 'ttylog_file' in channel:
            fp = open(channel['ttylog_file'], 'rb')
            ttydata = fp.read()
            fp.close()
            self.insert('INSERT INTO `ttylog` (`channelid`, `ttylog`) VALUES (%s, %s)',
                        (channel['uuid'], ttydata))

    def command_entered(self, sensor):
        channel = sensor['session']['channel']
        command = channel['command']
        self.insert('INSERT INTO `commands` (`timestamp`, `channelid`, `command`) VALUES (FROM_UNIXTIME(%s), %s, %s)',
                    (self.now_unix(command['date_time']), channel['uuid'], command['command']))

    def download_finished(self, sensor):
        channel = sensor['session']['channel']
        download = channel['download']
        self.insert(
            'INSERT INTO `downloads` (`channelid`, `timestamp`, `link`, `outfile`) VALUES (%s, FROM_UNIXTIME(%s), %s, %s)',
            (channel['uuid'], self.now_unix(download['start_time']), download['link'], download['file']))

    def insert_sensor(self, sensor):
        r = self.get_sensor_id(sensor)
        if len(r) == 0:
            self.insert('INSERT INTO `sensors` (`ip`, `name`, `port`) VALUES (%s, %s, %s)',
                        (sensor['honey_ip'], sensor['sensor_name'], sensor['honey_port']))
            r = self.get_sensor_id(sensor)
        return r[0]['id']

    def get_sensor_id(self, sensor):
        return self.select('SELECT `id` FROM `sensors` WHERE `ip` = %s AND `name` = %s AND `port` = %s',
                           (sensor['honey_ip'], sensor['sensor_name'], sensor['honey_port']))

    def insert_client(self, session):
        r = self.get_client_id(session)
        if len(r) == 0:
            self.insert('INSERT INTO `clients` (`version`) VALUES (%s)', (session['version'],))
            r = self.get_client_id(session)
        return r[0]['id']

    def get_client_id(self, session):
        return self.select('SELECT `id` FROM `clients` WHERE `version` = %s', (session['version'],))

    def insert(self, query, args=None):
        server = self.connect_dbserver()
        cursor = server.cursor()

        try:
            cursor.execute(query, args)
            server.commit()
        except MySQLdb.OperationalError, e:
            self.sqlerror(e)
            self.insert(query, args)
        except Exception, e:
            self.sqlerror(e)
            server.rollback()
        finally:
            server.close()

    def select(self, query, args=None):
        results = None
        server = self.connect_dbserver()
        cursor = server.cursor(MySQLdb.cursors.DictCursor)

        try:
            cursor.execute(query, args)
            results = cursor.fetchall()
        except MySQLdb.OperationalError, e:
            self.sqlerror(e)
            results = self.select(query, args)
        except Exception, e:
            self.sqlerror(e)
        finally:
            server.close()
        return results

    def sqlerror(self, error):
        log.msg(log.LRED, '[PLUGIN][MYSQL]', 'SQL Error:' + str(error))

    def now_unix(self, dt):
        """return the current UTC time as an UNIX timestamp"""
        return int(time.mktime(datetime.datetime.strptime(dt, "%Y%m%d_%H%M%S_%f").timetuple()))

    def validate_config(self):
        props = [['output-mysql', 'enabled']]
        for prop in props:
            if not self.cfg.check_exist(prop, validation.check_valid_boolean):
                return False

        # If output-mysql is enabled check it's config
        if self.cfg.getboolean(['output-mysql', 'enabled']):
            prop = ['output-mysql', 'port']
            if not self.cfg.check_exist(prop, validation.check_valid_port):
                return False

            props = [['output-mysql', 'host'], ['output-mysql', 'database'], ['output-mysql', 'username'],
                     ['output-mysql', 'password']]
            for prop in props:
                if not self.cfg.check_exist(prop):
                    return False
        return True
