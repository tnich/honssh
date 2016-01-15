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

from twisted.python import log
from twisted.internet import threads, reactor
from kippo.core.config import config
from honssh import txtlog
from kippo.core import ttylog
from kippo.dblog import mysql
from hpfeeds import hpfeeds
import datetime
import time
import os
import struct
import re
import subprocess
import uuid
import GeoIP
import getopt
import hashlib
import socket
import urllib2
import base64
import magic

class Output():
    cfg = config()

    def __init__(self, factory):
        self.hpLogClient = factory.hpLog
        self.dbLogClient = factory.dbLog
        self.connections = factory.connections
    
    def connectionMade(self, ip, port, honeyIP, honeyPort, sensorName):
        dt = self.getDateTime()
        self.sensorName = sensorName
        self.honeyIP = honeyIP
        self.honeyPort = honeyPort
        self.logLocation = self.cfg.get('folders', 'session_path') + "/" + self.sensorName + "/"+ ip + "/"
        self.downloadFolder = self.logLocation + 'downloads/'
        self.txtlog_file = self.logLocation + dt + ".log"
        self.endIP = ip
        self.endPort = port
        self.sessionID = uuid.uuid4().hex
        self.passwordTried = False
        self.loginSuccess = False
        self.ttyFiles = []

        
        if self.cfg.get('txtlog', 'enabled') == 'true':
            self.connectionString = '[POT  ] ' + self.sensorName + ' - ' + self.honeyIP + ':' + str(self.honeyPort)
            self.addConnectionString('[SSH  ] Incoming Connection from ' + ip +  ':' + str(port))
            country = self.cname(ip)
            if country != None:
                self.connectionString = self.connectionString + ' - ' + self.cname(ip)
            
        if self.cfg.get('database_mysql', 'enabled') == 'true':
            self.dbLog = mysql.DBLogger()
            self.dbLog.setClient(self.dbLogClient, self.cfg)
                        
        if self.cfg.get('hpfeeds', 'enabled') == 'true':
            self.hpLog = hpfeeds.HPLogger()
            self.hpLog.setClient(self.hpLogClient, self.cfg, self.sensorName)
        
        if self.cfg.has_option('app_hooks', 'connection_made'):
            if self.cfg.get('app_hooks', 'connection_made') != '':
                cmdString = self.cfg.get('app_hooks', 'connection_made') + " CONNECTION_MADE " + dt + " " + self.endIP + " " + str(port) + " " + self.honeyIP
                threads.deferToThread(self.runCommand, cmdString)   
        
        self.connections.addConn(self.sensorName, self.endIP, self.endPort, dt, self.honeyIP, self.honeyPort)
        
    def connectionLost(self):
        dt = self.getDateTime()
        log.msg("[OUTPUT] Lost Connection with the attacker: %s" % self.endIP)
        if not self.passwordTried:
            if self.cfg.get('txtlog', 'enabled') == 'true':
                txtlog.authLog(dt, self.cfg.get('folders', 'log_path') + "/" + datetime.datetime.now().strftime("%Y%m%d"), self.endIP, '', '', False)
            
        if self.loginSuccess:
            if self.cfg.get('txtlog', 'enabled') == 'true':
                if os.path.exists(self.txtlog_file):
                    txtlog.log(dt, self.txtlog_file, '[SSH  ] Lost Connection with ' + self.endIP)
                    
            if self.cfg.get('database_mysql', 'enabled') == 'true':
                self.dbLog.handleConnectionLost(dt, self.sessionID)
            if self.cfg.get('hpfeeds', 'enabled') == 'true':
                self.hpLog.handleConnectionLost(dt)
            if self.cfg.get('email', 'attack') == 'true':
                threads.deferToThread(self.email, self.sensorName + ' - Attack logged', self.txtlog_file, self.ttyFiles)
        
        if self.cfg.has_option('app_hooks', 'connection_lost'):
            if self.cfg.get('app_hooks', 'connection_lost') != '':
                cmdString = self.cfg.get('app_hooks', 'connection_lost') + " CONNECTION_LOST " + dt + " " + self.endIP
                threads.deferToThread(self.runCommand, cmdString)
            
        self.connections.delConn(self.sensorName, self.endIP, self.endPort)

    def setVersion(self, version):
        self.version = version
        if self.cfg.get('txtlog', 'enabled') == 'true':
            self.connectionString = self.connectionString + ' - ' + version
            
        self.connections.setClient(self.sensorName, self.endIP, version)

    def loginSuccessful(self, username, password):
        dt = self.getDateTime()
        self.passwordTried = True
        self.loginSuccess = True
        self.makeSessionFolder()
        if self.cfg.get('txtlog', 'enabled') == 'true':
            txtlog.authLog(dt, self.cfg.get('folders', 'log_path') + "/" + datetime.datetime.now().strftime("%Y%m%d"), self.endIP, username, password, True)
            txtlog.log(dt, self.txtlog_file, self.connectionString)
            txtlog.log(dt, self.txtlog_file, '[SSH  ] Login Successful: ' + username + ':' + password)
 
        if self.cfg.get('email', 'login') == 'true':
            threads.deferToThread(self.email, self.sensorName + ' - Login Successful', self.txtlog_file)
        
        if self.cfg.get('database_mysql', 'enabled') == 'true':
            self.dbLog.handleLoginSucceeded(dt, username, password)
            self.dbLog.createSession(dt, self.sessionID, self.endIP, self.endPort, self.honeyIP, self.honeyPort, self.sensorName)
            self.dbLog.handleClientVersion(self.sessionID, self.version)
                    
        if self.cfg.get('hpfeeds', 'enabled') == 'true':
            self.hpLog.handleLoginSucceeded(dt, username, password)
            self.hpLog.createSession(dt, self.sessionID, self.endIP, self.endPort, self.honeyIP, self.honeyPort)
            self.hpLog.handleClientVersion(self.version)
            
        if self.cfg.has_option('app_hooks', 'login_successful'):
            if self.cfg.get('app_hooks', 'login_successful') != '':
                cmdString = self.cfg.get('app_hooks', 'login_successful') + " LOGIN_SUCCESSFUL " + dt + " " + self.endIP + " " + username + " " + password
                threads.deferToThread(self.runCommand, cmdString)
        
    def loginFailed(self, username, password):
        dt = self.getDateTime()
        self.passwordTried = True
        if self.cfg.get('txtlog', 'enabled') == 'true':
            txtlog.authLog(dt, self.cfg.get('folders', 'log_path') + "/" + datetime.datetime.now().strftime("%Y%m%d"), self.endIP, username, password, False)
        
        if self.cfg.get('database_mysql', 'enabled') == 'true':
            self.dbLog.handleLoginFailed(dt, username, password)
            
        if self.cfg.get('hpfeeds', 'enabled') == 'true':
            self.hpLog.handleLoginFailed(dt, username, password)
            
        if self.cfg.has_option('app_hooks', 'login_failed'):
            if self.cfg.get('app_hooks', 'login_failed') != '':
                cmdString = self.cfg.get('app_hooks', 'login_failed') + " LOGIN_FAILED " + dt + " " + self.endIP + " " + username + " " + password
                threads.deferToThread(self.runCommand, cmdString)
        
    def commandEntered(self, uuid, channelName, theCommand):
        dt = self.getDateTime()
        if self.cfg.get('txtlog', 'enabled') == 'true':
            theCMD = theCommand.replace('\n', '\\n')
            txtlog.log(dt, self.txtlog_file, channelName + " Command Executed: %s" % (theCMD))
        if self.cfg.get('database_mysql', 'enabled') == 'true':
            self.dbLog.handleCommand(dt, uuid, theCommand)
        if self.cfg.get('hpfeeds', 'enabled') == 'true':
            self.hpLog.handleCommand(dt, uuid, theCommand)
            
        theCommandsSplit = re.findall(r'(?:[^;&|<>"\']|["\'](?:\\.|[^"\'])*[\'"])+', theCommand)
        theCMDs = []
        
        for cmd in theCommandsSplit:
            theCMDs.extend(cmd.split('\n'))

        for command in theCMDs:
            command = command.strip().rstrip()

            if self.cfg.has_option('app_hooks', 'command_entered'):
                if self.cfg.get('app_hooks', 'command_entered') != '':
                    cmdString = self.cfg.get('app_hooks', 'command_entered') + " COMMAND_ENTERED " + dt + " " + self.endIP + " '" + command + "'"
                    threads.deferToThread(self.runCommand, cmdString)
            
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
                        self.activeDownload(channelName, uuid, l, username, password)
    
    def activeDownload(self, channelName, uuid, link, user, password):
        dt = self.getDateTime()

        self.makeDownloadsFolder()

        filename = dt + "-" + link.split("/")[-1]
        fileOut = self.downloadFolder + filename
        
        d = threads.deferToThread(self.wget, channelName, uuid, link, fileOut, user, password)
        d.addCallback(self.fileDownloaded)
        
        if self.cfg.has_option('app_hooks', 'download_started'):
            if self.cfg.get('app_hooks', 'download_started') != '':
                cmdString = self.cfg.get('app_hooks', 'download_started') + " DOWNLOAD_STARTED " + dt + " " + self.endIP + " " + link + " " + fileOut
                threads.deferToThread(self.runCommand, cmdString)  

    def fileDownloaded(self, input):
        dt = self.getDateTime()

        channelName, uuid, success, link, file, error = input
        if success:
            if self.cfg.get('txtlog', 'enabled') == 'true':
                threads.deferToThread(self.generateSHA256, channelName, uuid, dt, self.cfg.get('folders', 'log_path') + '/downloads.log', self.endIP, link, file)
                
            if self.cfg.get('database_mysql', 'enabled') == 'true':
                self.dbLog.handleFileDownload(dt, uuid, link, file)
                
            if self.cfg.has_option('app_hooks', 'download_finished'):
                if self.cfg.get('app_hooks', 'download_finished') != '':
                    cmdString = self.cfg.get('app_hooks', 'download_finished') + " DOWNLOAD_FINISHED " + dt + " " + self.endIP + " " + link + " " + file
                    threads.deferToThread(self.runCommand, cmdString)  
        else:
            log.msg('[OUTPUT][DOWNLOAD][ERR]' + error)
            txtlog.log(self.getDateTime(), self.txtlog_file, channelName + ' [DOWNLOAD] - Cannot download URL: ' + link)

    def channelOpened(self, uuid, channelName):
        dt = self.getDateTime()
        if self.cfg.get('txtlog', 'enabled') == 'true':
            txtlog.log(dt, self.txtlog_file, channelName + ' Opened Channel')
            
        if self.cfg.get('database_mysql', 'enabled') == 'true':
            self.dbLog.channelOpened(dt, self.sessionID, uuid, channelName)
            
        if self.cfg.get('hpfeeds', 'enabled') == 'true':
            self.hpLog.channelOpened(dt, uuid, channelName)
          
        self.connections.addChannel(self.sensorName, self.endIP, self.endPort, channelName, dt, uuid)
            
    def channelClosed(self, channel):
        dt = self.getDateTime()
        if self.cfg.get('txtlog', 'enabled') == 'true':
            txtlog.log(dt, self.txtlog_file, channel.name + ' Closed Channel')
        
        if self.cfg.get('database_mysql', 'enabled') == 'true':
            self.dbLog.channelClosed(dt, channel.uuid, channel.ttylog_file)
            
        if self.cfg.get('hpfeeds', 'enabled') == 'true':
            self.hpLog.channelClosed(dt, channel.uuid, channel.ttylog_file)
            
        if channel.ttylog_file != None:
            self.ttyFiles.append(channel.ttylog_file)
        
        self.connections.delChannel(self.sensorName, self.endIP, self.endPort, channel.uuid)

        
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
        
    def genericLog(self, message):
        dt = self.getDateTime()
        self.makeSessionFolder()
        if self.cfg.get('txtlog', 'enabled') == 'true':
            txtlog.log(dt, self.txtlog_file, message)
    
    def addConnectionString(self, message):
        dt = self.getDateTime()
        self.connectionString = self.connectionString + '\n' + dt + ' - ' + message
        
    def writePossibleLink(self, ips):
        dt = self.getDateTime()
        if not self.endIP in ips:
            self.connectionString = self.connectionString + '\n' + dt + ' - [SSH  ] Attempted login with the same username and password as ' + ', '.join(ips) + ' - Possible link'
        
    def errLog(self, message):
        dt = self.getDateTime()
        self.makeSessionFolder()
        txtlog.log(dt, self.txtlog_file + "-err", message)
        
    def advancedLog(self, message):
        dt = self.getDateTime()
        self.makeSessionFolder()
        txtlog.log(dt, self.txtlog_file + "-adv", message)
        
    def writeSpoofPass(self, username, password):
        txtlog.spoofLog(self.cfg.get('folders', 'log_path') + "/spoof.log", username, password, self.endIP)
        
    def portForwardLog(self, channelName, connDetails):
        dt = self.getDateTime()
        theDNS = ''
        try:
            theDNS = ' (' + socket.gethostbyaddr(connDetails['srcIP'])[0] + ')'
        except:
            pass
        txtlog.log(dt, self.txtlog_file, channelName + ' Source: ' + connDetails['srcIP'] + ':' + str(connDetails['srcPort']) + theDNS)
        
        theDNS = ''
        try:
            theDNS = ' (' + socket.gethostbyaddr(connDetails['dstIP'])[0] + ')'
        except:
            pass
        txtlog.log(dt, self.txtlog_file, channelName + ' Destination: ' + connDetails['dstIP'] + ':' + str(connDetails['dstPort']) + theDNS)
    
    def makeSessionFolder(self):
        if not os.path.exists(self.logLocation):
            os.makedirs(self.logLocation)
            os.chmod(self.logLocation,0755)
            os.chmod('/'.join(self.logLocation.split('/')[:-2]),0755)
            
    def makeDownloadsFolder(self):
        if not os.path.exists(self.downloadFolder):
            os.makedirs(self.downloadFolder)
            os.chmod(self.downloadFolder,0755)
    
    def email(self, subject, body, attachment=None):
        try:
            #Start send mail code - provided by flofrihandy, modified by peg
            import smtplib
            from email.mime.base import MIMEBase
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText
            from email import Encoders
            msg = MIMEMultipart()
            msg['Subject'] = subject
            msg['From'] = self.cfg.get('email', 'from')
            msg['To'] = self.cfg.get('email', 'to')
            fp = open(self.txtlog_file, 'rb')
            msg_text = MIMEText(fp.read())
            fp.close()
            msg.attach(msg_text)
            if attachment != None:
                for tty in attachment:
                    fp = open(tty, 'rb')
                    logdata = MIMEBase('application', "octet-stream")
                    logdata.set_payload(fp.read())
                    fp.close()
                    Encoders.encode_base64(logdata)
                    logdata.add_header('Content-Disposition', 'attachment', filename=os.path.basename(tty))
                    msg.attach(logdata)
            s = smtplib.SMTP(self.cfg.get('email', 'host'), int(self.cfg.get('email', 'port')))
            if self.cfg.get('email', 'username') != '' and self.cfg.get('email', 'password') != '':
                s.ehlo()
                if self.cfg.get('email', 'use_tls') == 'true':
                    s.starttls()
                if self.cfg.get('email', 'use_smtpauth') == 'true':
                    s.login(self.cfg.get('email', 'username'), self.cfg.get('email', 'password'))
            s.sendmail(msg['From'], msg['To'].split(','), msg.as_string())
            s.quit() #End send mail code
        except Exception, ex:
            log.msg('[OUTPUT][EMAIL][ERR] - ' + str(ex))
    
    def cname(self, ipv4_str): #Thanks Are.
        """Checks the ipv4_str against the GeoIP database. Returns the full country name of origin if 
        the IPv4 address is found in the database. Returns None if not found."""
        geo = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
        country = geo.country_name_by_addr(ipv4_str)
        return country
    
    def generateSHA256(self, channelName, uuid, dt, logPath, theIP, link, outFile):
        f = file(outFile, 'rb')
        sha256 = hashlib.sha256()
        while True:
            data = f.read(2**20)
            if not data:
                break
            sha256.update(data)
        f.close()
        
        theSHA256 = sha256.hexdigest()
        theSize = os.path.getsize(outFile)
        txtlog.log(dt, self.txtlog_file, channelName + ' Downloaded: ' + link + ' - Saved: ' + outFile + ' - Size: ' + str(theSize) + ' - SHA256: ' + str(theSHA256))
        log.msg("Downloaded: %s" % outFile)
        txtlog.downloadLog(dt, logPath, theIP, link, outFile, theSize, theSHA256)

        if re.search("\.sh$", outFile):
            m = magic.open(magic.MAGIC_NONE)
            m.load()
            filetype =  m.file(outFile)
            if re.search("ASCII", filetype):
                f = file(outFile, 'r+')
                for line in f:
                    if re.search("(wget|curl)", line):
                        links = re.findall("(http\S*) ", line)

                        for l in links:
                            self.activeDownload(channelName, uuid, l, '', '')
                f.close()
    
    def wget(self, channelName, uuid, link, fileOut, user, password):
        response = False
        error = ''
        try:
            request = urllib2.Request(link)
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
            return channelName, uuid, True, link, fileOut, None
        else:
            return channelName, uuid, False, link, None, error
        
    def runCommand(self, command):
        log.msg('[APP-HOOKS] - ' + command)
        sp = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        sp.communicate()
        
    def getDateTime(self):
        return datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    
    def registerSelf(self, register):
        c = self.connections.getChan(register.uuid)
        c['class'] = register

