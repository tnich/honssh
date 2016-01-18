# Copyright (c) 2013 Thomas Nicholson <tnnich@googlemail.com>
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
from twisted.internet import threads, reactor
from honssh.config import config
#from honssh import txtlog
from honssh import plugins
from kippo.core import ttylog
#from kippo.dblog import mysql
#from hpfeeds import hpfeeds
import datetime
import time
import os
import struct
import re
import subprocess
import uuid
import getopt
import hashlib
import socket
import urllib2
import base64
import GeoIP

class Output():
    cfg = config()

    def __init__(self, factory):
        self.connections = factory.connections
        self.plugin_servers = factory.plugin_servers
    
    def connectionMade(self, end_ip, end_port, honey_ip, honey_port, sensor_name):
        plugin_list = plugins.get_plugin_list(type='output')
        self.loaded_plugins = plugins.import_plugins(plugin_list, self.cfg)
        
        dt = self.getDateTime()
        self.sensor_name = sensor_name
        self.honey_ip = honey_ip
        self.honey_port = str(honey_port)
        self.end_ip = end_ip
        self.end_port = str(end_port)
        self.session_id = uuid.uuid4().hex        
        self.logLocation = self.cfg.get('folders', 'session_path') + "/" + self.sensor_name + "/"+ end_ip + "/"
        
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

        session = self.connections.add_session(self.sensor_name, self.end_ip, self.end_port, dt, self.honey_ip, self.honey_port, self.session_id, self.logLocation, country)
        plugins.run_plugins_function(self.loaded_plugins, 'connection_made', True, session)
        
    def connectionLost(self):
        log.msg(log.LRED, '[OUTPUT]', 'Lost Connection with the attacker: %s' % self.end_ip)
        
        dt = self.getDateTime()
        session = self.connections.set_session_close(self.session_id, dt)
        plugins.run_plugins_function(self.loaded_plugins, 'connection_lost', True, session)
        self.connections.del_session(self.session_id)
    
    def setVersion(self, version):
        session = self.connections.set_client(self.session_id, version)
        plugins.run_plugins_function(self.loaded_plugins, 'set_client', True, session)
     
    def loginSuccessful(self, username, password, spoofed):
        dt = self.getDateTime()
        self.makeSessionFolder()
        
        auth = self.connections.add_auth(self.session_id, dt, username, password, True, spoofed)
        plugins.run_plugins_function(self.loaded_plugins, 'login_successful', True, auth)
        
    def loginFailed(self, username, password):
        dt = self.getDateTime()

        auth = self.connections.add_auth(self.session_id, dt, username, password, False, False)        
        plugins.run_plugins_function(self.loaded_plugins, 'login_failed', True, auth)

    def commandEntered(self, channel_id, the_command, blocked=False):
        dt = self.getDateTime()
        command = self.connections.add_command(channel_id, dt, the_command, blocked)
        plugins.run_plugins_function(self.loaded_plugins, 'command_entered', True, command)
            
        the_commands_split = re.findall(r'(?:[^;&|<>"\']|["\'](?:\\.|[^"\'])*[\'"])+', the_command)
        the_commands = []
        
        for command in the_commands_split:
            the_commands.extend(command.split('\n'))

        for command in the_commands:
            command = command.strip().rstrip()

            if self.cfg.get('download','active') == 'true':
                if command.startswith('wget '):
                    command = command[4:]
                    commandArgs = re.findall(r'(?:[^\s"]|"(?:\\.|[^"])*")+', command)
                    args, links = getopt.getopt(commandArgs, 'VhbdqvFcNS46xErkKmpHLnp:e:o:a:i:B:t:O:T:w:Q:P:U:l:A:R:D:I:X:', ['version','help','background','execute=','output-file=','append-output=','debug','quiet','verbose','report-speed=','input-file=','force-html','base=','config=','bind-address=','tries=','output-document=', 'backups=','continue','progress=','timestamping','no-use-server-timestamps','server-response','spider','timeout=','dns-timeout=','connect-timeout=','read-timeout=','limit-rate=','wait=','waitretry=', 'random-wait','no-proxy','quota=','no-dns-cache','restrict-file-names=','inet4-only','inet6-only','prefer-family=','retry-connrefused','user=','password=','ask-password','no-iri','local-encoding=','remote-encoding=','unlink','force-directories','protocol-directories','cut-dirs=','directory-prefix=','default-page=','adjust-extension','http-user=','http-password=','no-http-keep-alive','no-cache','no-cookies','load-cookies=','save-cookies=','keep-session-cookies','ignore-length','header=','max-redirect=','proxy-user=','proxy-password=','referer=','save-headers','user-agent=','post-data=','post-file=','method=','body-data=','body-file=','content-disposition','content-on-error','trust-server-names','auth-no-challenge','secure-protocol=','https-only','no-check-certificate','certificate=','certificate-type=','private-key=','private-key-type=','ca-certificate=','ca-directory=','random-file=','egd-file=','warc-file=','warc-header=','warc-max-size=','warc-cdx','warc-dedup=','no-warc-compression','no-warc-digests','no-warc-keep-log','warc-tempdir=','ftp-user=','ftp-password=','no-remove-listing','no-glob','no-passive-ftp','preserve-permissions','retr-symlinks','recursive','level=','delete-after','convert-links','backup-converted','mirror','page-requisites','strict-comments','accept=','reject=','accept-regex=','reject-regex=','regex-type=','domains=','exclude-domains=','follow-ftp','follow-tags=','ignore-tags=','ignore-case','span-hosts','relative','include-directories=','exclude-directories=','no-verbose','no-clobber','no-directories','no-host-directories','no-parent'])
                    username = ''
                    password = ''
                    for a in args:
                        if a[0] in ['--user', '--http-user', '--ftp-user']:
                            username = a[1]
                        if a[0] in ['--password', '--http-password', '--ftp-password']:
                            password = a[1]
                            
                    for l in links:
                        self.activeDownload(channel_id, l, username, password)
    
    def activeDownload(self, channel_id, link, user, password):
        dt = self.getDateTime()

        self.makeDownloadsFolder()

        filename = dt + "-" + link.split("/")[-1]
        fileOut = self.downloadFolder + filename
        
        if '//' not in link:
            link = 'http://' + link
        
        d = threads.deferToThread(self.download_file, channel_id, link, fileOut, user, password)
        d.addCallback(self.fileDownloaded)
        
        self.downloadStarted(channel_id, link)

    def downloadStarted(self, channel_id, link):
        dt = self.getDateTime()
        download = self.connections.add_download(channel_id, dt, link)
        plugins.run_plugins_function(self.loaded_plugins, 'download_started', True, download)

    def fileDownloaded(self, input):
        finished = False
        file_meta = ''
        if len(input) == 3:
            finished = input[1]
            file_meta = input[2]
            input = input[0]
        else:
            error = input[4]
        if finished:
            if file_meta != '':
                dt = self.getDateTime()
                channel_id, success, link, file, error = input
                
                download = self.connections.set_download_close(channel_id, dt, link, file, success, file_meta[0], file_meta[1])
                plugins.run_plugins_function(self.loaded_plugins, 'download_finished', True, download)
        else:
            if error:
                log.msg(log.LRED, '[OUTPUT]', input)
            else:
                d = threads.deferToThread(self.get_file_meta, input)
                d.addCallback(self.fileDownloaded)

    def channelOpened(self, channel_id, channel_name):
        dt = self.getDateTime()
        channel = self.connections.add_channel(self.session_id, channel_name, dt, channel_id)
        plugins.run_plugins_function(self.loaded_plugins, 'channel_opened', True, channel)

    def channelClosed(self, channel):
        dt = self.getDateTime()
        channel = self.connections.set_channel_close(channel.uuid, dt, channel.ttylog_file)
        plugins.run_plugins_function(self.loaded_plugins, 'channel_closed', True, channel)
        #self.connections.del_channel(channel.uuid)

    def packet_logged(self, direction, packet, payload):
        if self.cfg.get('packet_logging', 'enabled') == 'true':
            dt = self.getDateTime()
            self.makeSessionFolder()
            sensor, session = self.connections.get_session(self.session_id)
            session_copy = self.connections.return_session(sensor, session)
            session_copy['session']['packet'] = {'date_time':dt, 'direction':direction, 'packet':packet, 'payload':payload}
            plugins.run_plugins_function(self.loaded_plugins, 'packet_logged', True, session_copy)
        
    def openTTY(self, ttylog_file):
        ttylog.ttylog_open(ttylog_file, time.time())
    def inputTTY(self, ttylog_file, data):
        ttylog.ttylog_write(ttylog_file, len(data), ttylog.TYPE_INPUT, time.time(), data)
    def outputTTY(self, ttylog_file, data):
        ttylog.ttylog_write(ttylog_file, len(data), ttylog.TYPE_OUTPUT, time.time(), data)
    def interactTTY(self, ttylog_file, data):
        ttylog.ttylog_write(ttylog_file, len(data), ttylog.TYPE_INTERACT, time.time(), data)
    def closeTTY(self, ttylog_file):
        ttylog.ttylog_close(ttylog_file, time.time())
        
    def portForwardLog(self, channelName, connDetails):
        dt = self.getDateTime()
        theDNS = ''
        try:
            theDNS = ' (' + socket.gethostbyaddr(connDetails['srcIP'])[0] + ')'
        except:
            pass
        ##txtlog.log(dt, self.txtlog_file, channelName + ' Source: ' + connDetails['srcIP'] + ':' + str(connDetails['srcPort']) + theDNS)
        log.msg(log.LPURPLE, '[OUTPUT]', channelName + ' Source: ' + connDetails['srcIP'] + ':' + str(connDetails['srcPort']) + theDNS)
        
        theDNS = ''
        try:
            theDNS = ' (' + socket.gethostbyaddr(connDetails['dstIP'])[0] + ')'
        except:
            pass
        ##txtlog.log(dt, self.txtlog_file, channelName + ' Destination: ' + connDetails['dstIP'] + ':' + str(connDetails['dstPort']) + theDNS)
        log.msg(log.LPURPLE, '[OUTPUT]', channelName + ' Destination: ' + connDetails['dstIP'] + ':' + str(connDetails['dstPort']) + theDNS)




    def makeSessionFolder(self):
        if not os.path.exists(self.logLocation):
            os.makedirs(self.logLocation)
            os.chmod(self.logLocation,0755)
            os.chmod('/'.join(self.logLocation.split('/')[:-2]),0755)
            
    def makeDownloadsFolder(self):
        if not os.path.exists(self.downloadFolder):
            os.makedirs(self.downloadFolder)
            os.chmod(self.downloadFolder,0755)
    
    def get_file_meta(self, input):
        channel_id, success, link, the_file, error = input
        if success:
            f = file(the_file, 'rb')
            sha256 = hashlib.sha256()
            while True:
                data = f.read(2**20)
                if not data:
                    break
                sha256.update(data)
            f.close()
        
            theSHA2256 = sha256.hexdigest()
            theSize = os.path.getsize(the_file)
            return input, True, [theSHA2256, theSize]
        else:
            return input, True, ''
    
    def download_file(self, channel_id, link, fileOut, user, password):
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
            theFile = response.read()
            f = open(fileOut, 'wb')
            f.write(theFile)
            f.close()
            return channel_id, True, link, fileOut, None
        else:
            return channel_id, False, link, None, error
        
    def getDateTime(self):
        return datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    
    def registerSelf(self, register):
        sensor, session, channel = self.connections.get_channel(register.uuid)
        channel['class'] = register

    def cname(self, ipv4_str): #Thanks Are.
        """Checks the ipv4_str against the GeoIP database. Returns the full country name of origin if 
        the IPv4 address is found in the database. Returns None if not found."""
        geo = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
        country = geo.country_name_by_addr(ipv4_str)
        return country
