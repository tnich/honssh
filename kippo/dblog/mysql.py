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
        self.cfg = cfg
        self.db = ReconnectingConnectionPool('MySQLdb',
            host = cfg.get('database_mysql', 'host'),
            db = cfg.get('database_mysql', 'database'),
            user = cfg.get('database_mysql', 'username'),
            passwd = cfg.get('database_mysql', 'password'),
            port = port,
            cp_min = 1,
            cp_max = 1)
            
    def sqlerror(self, error):
        print 'SQL Error:', error.value

    def simpleQuery(self, sql, args):
        """ Just run a deferred sql query, only care about errors """
        d = self.db.runQuery(sql, args)
        d.addErrback(self.sqlerror)

    def createSession(self, peerIP, peerPort, hostIP, hostPort):
        sid = uuid.uuid1().hex
        self.createSessionWhenever(sid, peerIP, hostIP)
        return sid

    # This is separate since we can't return with a value
    @defer.inlineCallbacks
    def createSessionWhenever(self, sid, peerIP, hostIP):
        sensorname = self.cfg.get('honeypot','sensor_name')
        r = yield self.db.runQuery(
            'SELECT `id` FROM `sensors` WHERE `ip` = %s', (sensorname,))
        if r:
            id = r[0][0]
        else:
            yield self.db.runQuery(
                'INSERT INTO `sensors` (`ip`) VALUES (%s)', (sensorname,))
            r = yield self.db.runQuery('SELECT LAST_INSERT_ID()')
            id = int(r[0][0])
        # now that we have a sensorID, continue creating the session
        self.simpleQuery(
            'INSERT INTO `sessions` (`id`, `starttime`, `sensor`, `ip`)' + \
            ' VALUES (%s, FROM_UNIXTIME(%s), %s, %s)',
            (sid, self.nowUnix(), id, peerIP))
            
    def nowUnix(self):
        """return the current UTC time as an UNIX timestamp"""
        return int(time.mktime(time.gmtime()[:-1] + (-1,)))
    def ttylog(self, ttylog):
        f = file(ttylog)
        ttylog = f.read(10485760)
        f.close()
        return ttylog

    def handleConnectionLost(self, session, ttylogFile=None):
        if ttylogFile != None:
            ttylogOut = self.ttylog(ttylogFile)
            self.simpleQuery(
                'INSERT INTO `ttylog` (`session`, `ttylog`) VALUES (%s, %s)',
                (session, ttylogOut))
        self.simpleQuery(
            'UPDATE `sessions` SET `endtime` = FROM_UNIXTIME(%s)' + \
            ' WHERE `id` = %s',
            (self.nowUnix(), session))

    def handleLoginFailed(self, session, username, password):
        self.simpleQuery('INSERT INTO `auth` (`session`, `success`' + \
            ', `username`, `password`, `timestamp`)' + \
            ' VALUES (%s, %s, %s, %s, FROM_UNIXTIME(%s))',
            (session, 0, username, password, self.nowUnix()))

    def handleLoginSucceeded(self, session, username, password):
        self.simpleQuery('INSERT INTO `auth` (`session`, `success`' + \
            ', `username`, `password`, `timestamp`)' + \
            ' VALUES (%s, %s, %s, %s, FROM_UNIXTIME(%s))',
            (session, 1, username, password, self.nowUnix()))

    def handleCommand(self, session, theCommand):
        self.simpleQuery('INSERT INTO `input`' + \
            ' (`session`, `timestamp`, `success`, `input`)' + \
            ' VALUES (%s, FROM_UNIXTIME(%s), %s, %s)',
            (session, self.nowUnix(), 1, theCommand))

    @defer.inlineCallbacks
    def handleClientVersion(self, session, version):
        r = yield self.db.runQuery(
            'SELECT `id` FROM `clients` WHERE `version` = %s', \
            (version))
        if r:
            id = int(r[0][0])
        else:
            yield self.db.runQuery(
                'INSERT INTO `clients` (`version`) VALUES (%s)', \
                (version))
            r = yield self.db.runQuery('SELECT LAST_INSERT_ID()')
            id = int(r[0][0])
        self.simpleQuery(
            'UPDATE `sessions` SET `client` = %s WHERE `id` = %s',
            (id, session))

    def handleFileDownload(self, session, url, outfile):
        self.simpleQuery('INSERT INTO `downloads`' + \
            ' (`session`, `timestamp`, `url`, `outfile`)' + \
            ' VALUES (%s, FROM_UNIXTIME(%s), %s, %s)',
            (session, self.nowUnix(), url, outfile))
