# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
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

from twisted.enterprise import adbapi
from twisted.internet import defer
from twisted.python import log
import MySQLdb, uuid, time

class ReconnectingConnectionPool(adbapi.ConnectionPool):
    """Reconnecting adbapi connection pool for MySQL.

    This class improves on the solution posted at
    http://www.gelens.org/2008/09/12/reinitializing-twisted-connectionpool/
    by checking exceptions by error code and only disconnecting the current
    connection instead of all of them.

    Also see:
    http://twistedmatrix.com/pipermail/twisted-python/2009-July/020007.html

    """
    def _runInteraction(self, interaction, *args, **kw):
        try:
            return adbapi.ConnectionPool._runInteraction(
                self, interaction, *args, **kw)
        except MySQLdb.OperationalError, e:
            if e[0] not in (2006, 2013):
                raise
            log.msg("RCP: got error %s, retrying operation" %(e))
            conn = self.connections.get(self.threadID())
            self.disconnect(conn)
            # try the interaction again
            return adbapi.ConnectionPool._runInteraction(
                self, interaction, *args, **kw)

class DBLogger():
    def start(self, cfg):
        if cfg.has_option('database_mysql', 'port'):
            port = int(cfg.get('database_mysql', 'port'))
        else:
            port = 3306
        return ReconnectingConnectionPool('MySQLdb',
            host = cfg.get('database_mysql', 'host'),
            db = cfg.get('database_mysql', 'database'),
            user = cfg.get('database_mysql', 'username'),
            passwd = cfg.get('database_mysql', 'password'),
            port = port,
            cp_min = 1,
            cp_max = 1)
            
    def setClient(self, dblog, cfg):
        self.db = dblog
        self.cfg = cfg

            
    def sqlerror(self, error):
        print 'SQL Error:', error.value

    def simpleQuery(self, sql, args):
        """ Just run a deferred sql query, only care about errors """
        d = self.db.runQuery(sql, args)
        d.addErrback(self.sqlerror)

    def createSession(self, sid, peerIP, peerPort, hostIP, hostPort):
        self.createSessionWhenever(sid, peerIP, peerPort, hostIP, hostPort)

    # This is separate since we can't return with a value
    @defer.inlineCallbacks
    def createSessionWhenever(self, sid, peerIP, peerPort, hostIP, hostPort):
        sensorname = self.cfg.get('honeypot','sensor_name')
        r = yield self.db.runQuery('SELECT `id` FROM `sensors` WHERE `ip` = %s AND `name` = %s AND `port` = %s', (hostIP, sensorname, hostPort))
        if r:
            id = r[0][0]
        else:
            yield self.db.runQuery('INSERT INTO `sensors` (`ip`, `name`, `port`) VALUES (%s, %s, %s)', (hostIP, sensorname, hostPort))
            r = yield self.db.runQuery('SELECT LAST_INSERT_ID()')
            id = int(r[0][0])
        # now that we have a sensorID, continue creating the session
        self.simpleQuery('INSERT INTO `sessions` (`id`, `starttime`, `sensor`, `ip`, `port`) VALUES (%s, FROM_UNIXTIME(%s), %s, %s, %s)', (sid, self.nowUnix(), id, peerIP, peerPort))
            
    def nowUnix(self):
        """return the current UTC time as an UNIX timestamp"""
        return int(time.mktime(time.gmtime()[:-1] + (-1,)))

    def handleConnectionLost(self, sid):
        self.simpleQuery('UPDATE `sessions` SET `endtime` = FROM_UNIXTIME(%s) WHERE `id` = %s', (self.nowUnix(), sid))

    def handleLoginFailed(self, username, password):
        self.simpleQuery('INSERT INTO `auth` (`success`, `username`, `password`, `timestamp`) VALUES (%s, %s, %s, FROM_UNIXTIME(%s))', (0, username, password, self.nowUnix()))

    def handleLoginSucceeded(self, username, password):
        self.simpleQuery('INSERT INTO `auth` (`success`, `username`, `password`, `timestamp`) VALUES (%s, %s, %s, FROM_UNIXTIME(%s))', ( 1, username, password, self.nowUnix()))
            
    def channelOpened(self, sessionID, uuid, channelName):
        self.simpleQuery('INSERT INTO `channels` (`id`, `type`, `starttime`, `sessionid`) VALUES (%s, %s, FROM_UNIXTIME(%s), %s)', (uuid, channelName, self.nowUnix(), sessionID))
        
    def channelClosed(self, uuid, ttylog=None):
        self.simpleQuery('UPDATE `channels` SET `endtime` = FROM_UNIXTIME(%s) WHERE `id` = %s', (self.nowUnix(), uuid))
        if ttylog != None:
            fp = open(ttylog, 'rb')
            ttydata = fp.read()
            fp.close()
            self.simpleQuery('INSERT INTO `ttylog` (`channelid`, `ttylog`) VALUES (%s, %s)', (uuid, ttydata))

    def handleCommand(self, uuid, theCommand):
        self.simpleQuery('INSERT INTO `commands` (`timestamp`, `channelid`, `command`) VALUES (FROM_UNIXTIME(%s), %s, %s)', (self.nowUnix(), uuid, theCommand))

    @defer.inlineCallbacks
    def handleClientVersion(self, session, version):
        r = yield self.db.runQuery('SELECT `id` FROM `clients` WHERE `version` = %s', (version))
        if r:
            id = int(r[0][0])
        else:
            yield self.db.runQuery('INSERT INTO `clients` (`version`) VALUES (%s)', (version))
            r = yield self.db.runQuery('SELECT LAST_INSERT_ID()')
            id = int(r[0][0])
        self.simpleQuery('UPDATE `sessions` SET `client` = %s WHERE `id` = %s', (id, session))

    def handleFileDownload(self, uuid, url, outfile):
        self.simpleQuery('INSERT INTO `downloads` (`channelid`, `timestamp`, `url`, `outfile`) VALUES (%s, FROM_UNIXTIME(%s), %s, %s)', (uuid, self.nowUnix(), url, outfile))
