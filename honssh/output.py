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
import datetime, time, os, struct, re, subprocess, uuid, GeoIP, getopt, hashlib

class Output():
    cfg = config()

    def __init__(self, hpLog, dbLog):
        self.hpLogClient = hpLog
        self.dbLogClient = dbLog
    
    def connectionMade(self, ip, port):
        dt = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.logLocation = self.cfg.get('folders', 'session_path') + "/" + ip + "/"
        self.downloadFolder = self.logLocation + 'downloads/'
        self.txtlog_file = self.logLocation + dt + ".log"
        self.endIP = ip
        self.endPort = port
        self.sessionID = uuid.uuid4().hex
        self.passwordTried = False
        self.loginSuccess = False
        self.ttyFiles = []
        
        if self.cfg.get('txtlog', 'enabled') == 'true':
            self.connectionString = '[POT  ] ' + self.cfg.get('honeypot', 'sensor_name')
            self.addConnectionString('[SSH  ] Incoming Connection from ' + ip +  ':' + str(port))
            country = self.cname(ip)
            if country != None:
                self.connectionString = self.connectionString + ' - ' + self.cname(ip)
            
        if self.cfg.get('database_mysql', 'enabled') == 'true':
            self.dbLog = mysql.DBLogger()
            self.dbLog.setClient(self.dbLogClient, self.cfg)
                        
        if self.cfg.get('hpfeeds', 'enabled') == 'true':
            self.hpLog = hpfeeds.HPLogger()
            self.hpLog.setClient(self.hpLogClient, self.cfg)
        
        if self.cfg.has_option('app_hooks', 'connection_made'):
            if self.cfg.get('app_hooks', 'connection_made') != '':
                cmdString = self.cfg.get('app_hooks', 'connection_made') + " CONNECTION_MADE " + dt + " " + self.endIP + " " + str(port)
                threads.deferToThread(self.runCommand, cmdString)    
        
    def connectionLost(self):
        log.msg("[OUTPUT] Lost Connection with the attacker: %s" % self.endIP)
        if not self.passwordTried:
            if self.cfg.get('txtlog', 'enabled') == 'true':
                txtlog.authLog(self.cfg.get('folders', 'log_path') + "/" + datetime.datetime.now().strftime("%Y%m%d"), self.endIP, '', '', False)
            
        if self.loginSuccess:
            if self.cfg.get('txtlog', 'enabled') == 'true':
                if os.path.exists(self.txtlog_file):
                    txtlog.log(self.txtlog_file, '[SSH  ] Lost Connection with ' + self.endIP)
                    
            if self.cfg.get('database_mysql', 'enabled') == 'true':
                self.dbLog.handleConnectionLost(self.sessionID)
            if self.cfg.get('hpfeeds', 'enabled') == 'true':
                self.hpLog.handleConnectionLost()
            if self.cfg.get('email', 'attack') == 'true':
                threads.deferToThread(self.email, 'HonSSH - Attack logged', self.txtlog_file, self.ttyFiles)
        
        dt = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if self.cfg.has_option('app_hooks', 'connection_lost'):
            if self.cfg.get('app_hooks', 'connection_lost') != '':
                cmdString = self.cfg.get('app_hooks', 'connection_lost') + " CONNECTION_LOST " + dt + " " + self.endIP
                threads.deferToThread(self.runCommand, cmdString)
            
    def setVersion(self, version):
        self.version = version
        if self.cfg.get('txtlog', 'enabled') == 'true':
            self.connectionString = self.connectionString + ' - ' + version

    def loginSuccessful(self, username, password):
        self.passwordTried = True
        self.loginSuccess = True
        dt = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.makeSessionFolder()
        if self.cfg.get('txtlog', 'enabled') == 'true':
            txtlog.authLog(self.cfg.get('folders', 'log_path') + "/" + datetime.datetime.now().strftime("%Y%m%d"), self.endIP, username, password, True)
            txtlog.log(self.txtlog_file, self.connectionString)
            txtlog.log(self.txtlog_file, '[SSH  ] Login Successful: ' + username + ':' + password)
 
        if self.cfg.get('email', 'login') == 'true':
            threads.deferToThread(self.email, 'HonSSH - Login Successful', self.txtlog_file)
        
        if self.cfg.get('database_mysql', 'enabled') == 'true':
            self.dbLog.handleLoginSucceeded(username, password)
            self.dbLog.createSession(self.sessionID, self.endIP, self.endPort, self.cfg.get('honeypot', 'ssh_addr'), self.cfg.get('honeypot', 'ssh_port'))
            self.dbLog.handleClientVersion(self.sessionID, self.version)
                    
        if self.cfg.get('hpfeeds', 'enabled') == 'true':
            self.hpLog.handleLoginSucceeded(username, password)
            self.hpLog.createSession(self.sessionID, self.endIP, self.endPort, self.cfg.get('honeypot', 'ssh_addr'), self.cfg.get('honeypot', 'ssh_port'))
            self.hpLog.handleClientVersion(self.version)
            
        if self.cfg.has_option('app_hooks', 'login_successful'):
            if self.cfg.get('app_hooks', 'login_successful') != '':
                cmdString = self.cfg.get('app_hooks', 'login_successful') + " LOGIN_SUCCESSFUL " + dt + " " + self.endIP + " " + username + " " + password
                threads.deferToThread(self.runCommand, cmdString)
        
    def loginFailed(self, username, password):
        self.passwordTried = True
        dt = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if self.cfg.get('txtlog', 'enabled') == 'true':
            txtlog.authLog(self.cfg.get('folders', 'log_path') + "/" + datetime.datetime.now().strftime("%Y%m%d"), self.endIP, username, password, False)
        
        if self.cfg.get('database_mysql', 'enabled') == 'true':
            self.dbLog.handleLoginFailed(username, password)
            
        if self.cfg.get('hpfeeds', 'enabled') == 'true':
            self.hpLog.handleLoginFailed(username, password)
            
        if self.cfg.has_option('app_hooks', 'login_failed'):
            if self.cfg.get('app_hooks', 'login_failed') != '':
                cmdString = self.cfg.get('app_hooks', 'login_failed') + " LOGIN_FAILED " + dt + " " + self.endIP + " " + username + " " + password
                threads.deferToThread(self.runCommand, cmdString)
        
    def commandEntered(self, uuid, channelName, theCommand):
        if self.cfg.get('txtlog', 'enabled') == 'true':
            theCMD = theCommand.replace('\n', '\\n')
            txtlog.log(self.txtlog_file, channelName + " Command Executed: %s" % (theCMD))
        if self.cfg.get('database_mysql', 'enabled') == 'true':
            self.dbLog.handleCommand(uuid, theCommand)
        if self.cfg.get('hpfeeds', 'enabled') == 'true':
            self.hpLog.handleCommand(uuid, theCommand)
            
        theCommandsSplit = re.findall(r'(?:[^;&|<>"\']|["\'](?:\\.|[^"\'])*[\'"])+', theCommand)
        theCMDs = []
        
        for cmd in theCommandsSplit:
            theCMDs.extend(cmd.split('\n'))

        for command in theCMDs:
            command = command.strip().rstrip()

            dt = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
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
                        if a[0] in ['user', 'http-user', 'ftp-user']:
                            username = a[1]
                        if a[0] in ['password', 'http-password', 'ftp-password']:
                            password = a[1]
                            
                    for l in links:
                        self.activeDownload(channelName, uuid, l, username, password)
    
    def activeDownload(self, channelName, uuid, link, user, password):
        dt = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        self.makeDownloadsFolder()

        filename = dt + "-" + link.split("/")[-1]
        fileOut = self.cfg.get('folders', 'session_path') + '/' + self.endIP + '/downloads/' + filename
        wgetCommand = 'wget -O ' + fileOut + " "
        if user != '':
            wgetCommand = wgetCommand + '--user=' + user + ' '
        if password != '':
            wgetCommand = wgetCommand + '--password=' + password + ' '
        wgetCommand = wgetCommand + link
        
        d = threads.deferToThread(self.wget, channelName, uuid, wgetCommand, link, fileOut)
        d.addCallback(self.fileDownloaded)
        
        if self.cfg.has_option('app_hooks', 'download_started'):
            if self.cfg.get('app_hooks', 'download_started') != '':
                cmdString = self.cfg.get('app_hooks', 'download_started') + " DOWNLOAD_STARTED " + dt + " " + self.endIP + " " + link + " " + fileOut
                threads.deferToThread(self.runCommand, cmdString)  

    def fileDownloaded(self, input):
        dt = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        channelName, uuid, success, link, file, wgetError = input
        if success:
            if self.cfg.get('txtlog', 'enabled') == 'true':
                threads.deferToThread(self.generateMD5, channelName, dt, self.cfg.get('folders', 'log_path') + '/downloads.log', self.endIP, link, file)
                
            if self.cfg.get('database_mysql', 'enabled') == 'true':
                self.dbLog.handleFileDownload(uuid, link, file)
                
            if self.cfg.has_option('app_hooks', 'download_finished'):
                if self.cfg.get('app_hooks', 'download_finished') != '':
                    cmdString = self.cfg.get('app_hooks', 'download_finished') + " DOWNLOAD_FINISHED " + dt + " " + self.endIP + " " + link + " " + file
                    threads.deferToThread(self.runCommand, cmdString)  
        else:
            log.msg('[OUTPUT] FILE DOWNLOAD FAILED')
            log.msg('[OUTPUT] ' + wgetError)

    def channelOpened(self, uuid, channelName):
        if self.cfg.get('txtlog', 'enabled') == 'true':
            txtlog.log(self.txtlog_file, channelName + ' Opened Channel')
            
        if self.cfg.get('database_mysql', 'enabled') == 'true':
            self.dbLog.channelOpened(self.sessionID, uuid, channelName)
            
        if self.cfg.get('hpfeeds', 'enabled') == 'true':
            self.hpLog.channelOpened(uuid, channelName)
            
    def channelClosed(self, channel):
        if self.cfg.get('txtlog', 'enabled') == 'true':
            txtlog.log(self.txtlog_file, channel.name + ' Closed Channel')
        
        if self.cfg.get('database_mysql', 'enabled') == 'true':
            self.dbLog.channelClosed(channel.uuid, channel.ttylog_file)
            
        if self.cfg.get('hpfeeds', 'enabled') == 'true':
            self.hpLog.channelClosed(channel.uuid, channel.ttylog_file)
            
        if channel.ttylog_file != None:
            self.ttyFiles.append(channel.ttylog_file)
        
    def openTTY(self, ttylog_file):
        ttylog.ttylog_open(ttylog_file, time.time())
    def inputTTY(self, ttylog_file, data):
        ttylog.ttylog_write(ttylog_file, len(data), ttylog.TYPE_INPUT, time.time(), data)
    def closeTTY(self, ttylog_file):
        ttylog.ttylog_close(ttylog_file, time.time())
        
    def genericLog(self, message):
        self.makeSessionFolder()
        if self.cfg.get('txtlog', 'enabled') == 'true':
            txtlog.log(self.txtlog_file, message)
    
    def addConnectionString(self, message):
        self.connectionString = self.connectionString + '\n' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' - ' + message
        
    def writePossibleLink(self, ips):
        if not self.endIP in ips:
            self.connectionString = self.connectionString + '\n' + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ' - [SSH  ] Attempted login with the same username and password as ' + ', '.join(ips) + ' - Possible link'
        
    def errLog(self, message):
        self.makeSessionFolder()
        txtlog.log(self.txtlog_file + "-err", message)
        
    def advancedLog(self, message):
        self.makeSessionFolder()
        txtlog.log(self.txtlog_file + "-adv", message)
        
    def writeSpoofPass(self, username, password):
        txtlog.spoofLog(self.cfg.get('folders', 'log_path') + "/spoof.log", username, password, self.endIP)
    
    def makeSessionFolder(self):
        if not os.path.exists(os.path.join(self.cfg.get('folders', 'session_path') + '/' + self.endIP)):
            os.makedirs(os.path.join(self.cfg.get('folders', 'session_path') + '/' + self.endIP))
            os.chmod(os.path.join(self.cfg.get('folders', 'session_path') + '/' + self.endIP),0755)
            
    def makeDownloadsFolder(self):
        if not os.path.exists(self.cfg.get('folders', 'session_path') + '/' + self.endIP + '/downloads'):
            os.makedirs(self.cfg.get('folders', 'session_path') + '/' + self.endIP + '/downloads')
            os.chmod(self.cfg.get('folders', 'session_path') + '/' + self.endIP + '/downloads',0755)
    
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
    
    def generateMD5(self, channelName, dt, logPath, theIP, link, outFile):      
        f = file(outFile, 'rb')
        md5 = hashlib.md5()
        while True:
            data = f.read(2**20)
            if not data:
                break
            md5.update(data)
        f.close()
        
        theMD5 = md5.hexdigest()
        theSize = os.path.getsize(outFile)
        txtlog.log(self.txtlog_file, channelName + ' Downloaded: ' + link + ' - Saved: ' + outFile + ' - Size: ' + str(theSize) + ' - MD5: ' + str(theMD5))
        txtlog.downloadLog(dt, logPath, theIP, link, outFile, theSize, theMD5)
    
    def wget(self, channelName, uuid, wgetCommand, link, fileOut):
        sp = subprocess.Popen(wgetCommand, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        result = sp.communicate()
        if sp.returncode == 0:
            return channelName, uuid, True, link, fileOut, None
        else:
            return channelName, uuid, False, link, None, result[0]
        
    def runCommand(self, command):
        log.msg('[APP-HOOKS] - ' + command)
        sp = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        sp.communicate()
