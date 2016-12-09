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

from honssh import log
from twisted.internet import threads
from honssh.config import Config
from honssh import plugins
from kippo.core import ttylog

import datetime
import time
import os
import re
import uuid
import getopt
import hashlib
import socket
import urllib2
import base64
import GeoIP


class Output(object):
    def __init__(self, factory):
        self.cfg = Config.getInstance()
        self.connections = factory.connections
        self.plugin_servers = factory.plugin_servers
        self.loaded_plugins = None
        self.sensor_name = None
        self.honey_ip = None
        self.honey_port = None
        self.end_ip = None
        self.end_port = None
        self.session_id = None
        self.logLocation = None
        self.downloadFolder = None

    def connection_made(self, end_ip, end_port, honey_ip, honey_port, sensor_name):
        plugin_list = plugins.get_plugin_list(plugin_type='output')
        self.loaded_plugins = plugins.import_plugins(plugin_list)

        dt = self.get_date_time()
        self.sensor_name = sensor_name
        self.honey_ip = honey_ip
        self.honey_port = str(honey_port)
        self.end_ip = end_ip
        self.end_port = str(end_port)
        self.session_id = uuid.uuid4().hex
        self.logLocation = self.cfg.get(['folders', 'session_path']) + "/" + self.sensor_name + "/" + end_ip + "/"

        self.downloadFolder = self.logLocation + 'downloads/'

        for plugin in self.loaded_plugins:
            plugin_name = plugins.get_plugin_name(plugin)
            for plugin_server in self.plugin_servers:
                if plugin_server['name'] == plugin_name:
                    plugins.run_plugins_function([plugin], 'set_server', False, plugin_server['server'])
                    break

        country = self.cname(self.end_ip)
        if not country:
            country = ''

        session = self.connections.add_session(self.sensor_name, self.end_ip, self.end_port, dt, self.honey_ip,
                                               self.honey_port, self.session_id, self.logLocation, country)
        plugins.run_plugins_function(self.loaded_plugins, 'connection_made', True, session)

    def connection_lost(self):
        log.msg(log.LRED, '[OUTPUT]', 'Lost Connection with the attacker: %s' % self.end_ip)

        dt = self.get_date_time()

        channels = self.connections.get_channels(self.session_id)
        if channels is not None:
            for channel in channels:
                if 'end_time' not in channel:
                    self._channel_closed(channel['uuid'])

        session = self.connections.set_session_close(self.session_id, dt)
        plugins.run_plugins_function(self.loaded_plugins, 'connection_lost', True, session)
        self.connections.del_session(self.session_id)

    def set_version(self, version):
        session = self.connections.set_client(self.session_id, version)
        plugins.run_plugins_function(self.loaded_plugins, 'set_client', True, session)

    def login_successful(self, username, password, spoofed):
        dt = self.get_date_time()
        self.make_session_folder()

        auth = self.connections.add_auth(self.session_id, dt, username, password, True, spoofed)
        plugins.run_plugins_function(self.loaded_plugins, 'login_successful', True, auth)

    def login_failed(self, username, password):
        dt = self.get_date_time()

        auth = self.connections.add_auth(self.session_id, dt, username, password, False, False)
        plugins.run_plugins_function(self.loaded_plugins, 'login_failed', True, auth)

    def command_entered(self, channel_id, the_command, blocked=False):
        dt = self.get_date_time()
        command = self.connections.add_command(channel_id, dt, the_command, blocked)
        plugins.run_plugins_function(self.loaded_plugins, 'command_entered', True, command)

        the_commands_split = re.findall(r'(?:[^;&|<>()"\']|["\'](?:\\.|[^"\'])*[\'"])+', the_command)
        the_commands = []

        for command in the_commands_split:
            the_commands.extend(command.split('\n'))

        for command in the_commands:
            command = command.strip().rstrip()

            if self.cfg.getboolean(['download', 'active']):
                if command.startswith('wget '):
                    command = command[4:]
                    command_args = re.findall(r'(?:[^\s"]|"(?:\\.|[^"])*")+', command)
                    args, links = getopt.getopt(command_args,
                                                'VhbdqvFcNS46xErkKmpHLnp:e:o:a:i:B:t:O:T:w:Q:P:U:l:A:R:D:I:X:',
                                                ['version', 'help', 'background', 'execute=', 'output-file=',
                                                 'append-output=', 'debug', 'quiet', 'verbose', 'report-speed=',
                                                 'input-file=', 'force-html', 'base=', 'config=', 'bind-address=',
                                                 'tries=', 'output-document=', 'backups=', 'continue', 'progress=',
                                                 'timestamping', 'no-use-server-timestamps', 'server-response',
                                                 'spider', 'timeout=', 'dns-timeout=', 'connect-timeout=',
                                                 'read-timeout=', 'limit-rate=', 'wait=', 'waitretry=', 'random-wait',
                                                 'no-proxy', 'quota=', 'no-dns-cache', 'restrict-file-names=',
                                                 'inet4-only', 'inet6-only', 'prefer-family=', 'retry-connrefused',
                                                 'user=', 'password=', 'ask-password', 'no-iri', 'local-encoding=',
                                                 'remote-encoding=', 'unlink', 'force-directories',
                                                 'protocol-directories', 'cut-dirs=', 'directory-prefix=',
                                                 'default-page=', 'adjust-extension', 'http-user=', 'http-password=',
                                                 'no-http-keep-alive', 'no-cache', 'no-cookies', 'load-cookies=',
                                                 'save-cookies=', 'keep-session-cookies', 'ignore-length', 'header=',
                                                 'max-redirect=', 'proxy-user=', 'proxy-password=', 'referer=',
                                                 'save-headers', 'user-agent=', 'post-data=', 'post-file=', 'method=',
                                                 'body-data=', 'body-file=', 'content-disposition', 'content-on-error',
                                                 'trust-server-names', 'auth-no-challenge', 'secure-protocol=',
                                                 'https-only', 'no-check-certificate', 'certificate=',
                                                 'certificate-type=', 'private-key=', 'private-key-type=',
                                                 'ca-certificate=', 'ca-directory=', 'random-file=', 'egd-file=',
                                                 'warc-file=', 'warc-header=', 'warc-max-size=', 'warc-cdx',
                                                 'warc-dedup=', 'no-warc-compression', 'no-warc-digests',
                                                 'no-warc-keep-log', 'warc-tempdir=', 'ftp-user=', 'ftp-password=',
                                                 'no-remove-listing', 'no-glob', 'no-passive-ftp',
                                                 'preserve-permissions', 'retr-symlinks', 'recursive', 'level=',
                                                 'delete-after', 'convert-links', 'backup-converted', 'mirror',
                                                 'page-requisites', 'strict-comments', 'accept=', 'reject=',
                                                 'accept-regex=', 'reject-regex=', 'regex-type=', 'domains=',
                                                 'exclude-domains=', 'follow-ftp', 'follow-tags=', 'ignore-tags=',
                                                 'ignore-case', 'span-hosts', 'relative', 'include-directories=',
                                                 'exclude-directories=', 'no-verbose', 'no-clobber', 'no-directories',
                                                 'no-host-directories', 'no-parent'])
                    username = ''
                    password = ''
                    for a in args:
                        if a[0] in ['--user', '--http-user', '--ftp-user']:
                            username = a[1]
                        if a[0] in ['--password', '--http-password', '--ftp-password']:
                            password = a[1]

                    for l in links:
                        self.active_download(channel_id, l, username, password)

    def active_download(self, channel_id, link, user, password):
        dt = self.get_date_time()

        self.make_downloads_folder()

        filename = dt + "-" + link.split("/")[-1]
        file_out = self.downloadFolder + filename

        if not link.startswith('http://') or not link.startswith('https://'):
            link = 'http://' + link

        d = threads.deferToThread(self.download_file, channel_id, link, file_out, user, password)
        d.addCallback(self.file_downloaded)

        self.download_started(channel_id, link)

    def download_started(self, channel_id, link):
        dt = self.get_date_time()
        download = self.connections.add_download(channel_id, dt, link)
        plugins.run_plugins_function(self.loaded_plugins, 'download_started', True, download)

    def file_downloaded(self, download):
        finished = False
        file_meta = ''

        if len(download) == 3:
            finished = download[1]
            file_meta = download[2]
            download = download[0]
        else:
            error = download[4]

        if finished:
            if file_meta != '':
                dt = self.get_date_time()
                channel_id, success, link, file, error = download

                download = self.connections.set_download_close(channel_id, dt, link, file, success, file_meta[0],
                                                               file_meta[1])
                plugins.run_plugins_function(self.loaded_plugins, 'download_finished', True, download)
        else:
            if error:
                log.msg(log.LRED, '[OUTPUT]', download)
            else:
                d = threads.deferToThread(self.get_file_meta, download)
                d.addCallback(self.file_downloaded)

    def channel_opened(self, channel_id, channel_name):
        dt = self.get_date_time()
        channel = self.connections.add_channel(self.session_id, channel_name, dt, channel_id)
        plugins.run_plugins_function(self.loaded_plugins, 'channel_opened', True, channel)

    def channel_closed(self, channel):
        self._channel_closed(channel.uuid)

    def _channel_closed(self, channel_id):
        dt = self.get_date_time()
        channel = self.connections.set_channel_close(channel_id, dt)
        plugins.run_plugins_function(self.loaded_plugins, 'channel_closed', True, channel)

    def packet_logged(self, direction, packet, payload):
        if self.cfg.getboolean(['packet_logging', 'enabled']):
            dt = self.get_date_time()
            self.make_session_folder()
            sensor, session = self.connections.get_session(self.session_id)
            session_copy = self.connections.return_session(sensor, session)
            session_copy['session']['packet'] = {'date_time': dt, 'direction': direction, 'packet': packet,
                                                 'payload': payload}
            plugins.run_plugins_function(self.loaded_plugins, 'packet_logged', True, session_copy)

    def open_tty(self, uuid, ttylog_file):
        self.connections.add_ttylog_file(uuid, ttylog_file)
        ttylog.ttylog_open(ttylog_file, time.time())

    def input_tty(self, ttylog_file, data):

        ttylog.ttylog_write(ttylog_file, len(data), ttylog.TYPE_INPUT, time.time(), data)

    def output_tty(self, ttylog_file, data):
        ttylog.ttylog_write(ttylog_file, len(data), ttylog.TYPE_OUTPUT, time.time(), data)

    def interact_tty(self, ttylog_file, data):
        ttylog.ttylog_write(ttylog_file, len(data), ttylog.TYPE_INTERACT, time.time(), data)

    def close_tty(self, ttylog_file):
        ttylog.ttylog_close(ttylog_file, time.time())

    def port_forward_log(self, channel_name, conn_details):
        the_dns = ''
        try:
            the_dns = ' (' + socket.gethostbyaddr(conn_details['srcIP'])[0] + ')'
        except:
            pass
        # TODO: LOG SOMEWHERE
        log.msg(log.LPURPLE, '[OUTPUT]',
                channel_name + ' Source: ' + conn_details['srcIP'] + ':' + str(conn_details['srcPort']) + the_dns)

        the_dns = ''
        try:
            the_dns = ' (' + socket.gethostbyaddr(conn_details['dstIP'])[0] + ')'
        except:
            pass
        # TODO: LOG SOMEWHERE
        log.msg(log.LPURPLE, '[OUTPUT]',
                channel_name + ' Destination: ' + conn_details['dstIP'] + ':' + str(conn_details['dstPort']) + the_dns)

    def make_session_folder(self):
        if not os.path.exists(self.logLocation):
            os.makedirs(self.logLocation)
            os.chmod(self.logLocation, 0755)
            os.chmod('/'.join(self.logLocation.split('/')[:-2]), 0755)

    def make_downloads_folder(self):
        if not os.path.exists(self.downloadFolder):
            os.makedirs(self.downloadFolder)
            os.chmod(self.downloadFolder, 0755)

    def get_file_meta(self, download):
        channel_id, success, link, the_file, error = download
        if success:
            f = file(the_file, 'rb')
            sha256 = hashlib.sha256()
            while True:
                data = f.read(2 ** 20)
                if not data:
                    break
                sha256.update(data)
            f.close()

            sha256_hash = sha256.hexdigest()
            file_size = os.path.getsize(the_file)
            return download, True, [sha256_hash, file_size]
        else:
            return download, True, ''

    def download_file(self, channel_id, link, file_out, user, password):
        response = False
        error = ''
        try:
            request = urllib2.Request(link)
            request.add_header('Accept', 'text/plain')
            if user and password:
                if link.startswith('ftp://'):
                    link = link[:6] + user + ':' + password + '@' + link[6:]
                    request = urllib2.Request(link)
                else:
                    base64string = base64.encodestring('%s:%s' % (user, password)).replace('\n', '')
                    request.add_header("Authorization", "Basic %s" % base64string)
            response = urllib2.urlopen(request)
        except Exception, ex:
            error = str(ex)

        if response:
            the_file = response.read()
            f = open(file_out, 'wb')
            f.write(the_file)
            f.close()
            return channel_id, True, link, file_out, None
        else:
            return channel_id, False, link, None, error

    def get_date_time(self):
        return datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")

    def register_self(self, register):
        sensor, session, channel = self.connections.get_channel(register.uuid)
        channel['class'] = register

    def cname(self, ipv4_str):  # Thanks Are.
        """Checks the ipv4_str against the GeoIP database. Returns the full country name of origin if 
        the IPv4 address is found in the database. Returns None if not found."""
        geo = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
        country = geo.country_name_by_addr(ipv4_str)
        return country
