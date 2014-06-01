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
import datetime, time, os, struct, re, subprocess

class Output():
    cfg = config()
    sessionType = ''
    
    def connectionMade(self, ip, port):
        dt = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.logLocation = self.cfg.get('folders', 'session_path') + "/" + ip + "/" + dt
        self.ttylog_file = self.logLocation + ".tty"      
        self.txtlog_file = self.logLocation + ".log"
        self.endIP = ip
        
        if self.cfg.get('txtlog', 'enabled') == 'true':
            self.connectionString = "Incoming connection from: %s:%s" % (ip, port)
        
        if self.cfg.get('database_mysql', 'enabled') == 'true':
            self.dbLog = mysql.DBLogger()
            self.dbLog.start(self.cfg)
            self.sid = self.dbLog.createSession(ip, port, self.cfg.get('honeypot', 'ssh_addr'), self.cfg.get('honeypot', 'ssh_port'))
            
        if self.cfg.get('hpfeeds', 'enabled') == 'true':
            self.hpLog = hpfeeds.HPLogger()
            self.hpLog.start(self.cfg)
            self.hpLog.createSession(ip, port, self.cfg.get('honeypot', 'ssh_addr'), self.cfg.get('honeypot', 'ssh_port'))
        
        if self.cfg.has_option('app_hooks', 'connection_made'):
            cmdString = self.cfg.get('app_hooks', 'connection_made') + " CONNECTION_MADE " + dt + " " + self.endIP + " " + str(port)
            threads.deferToThread(self.runCommand, cmdString)    
        
    def connectionLost(self):
        log.msg("[OUTPUT] Lost connection with the attacker: %s" % self.endIP)
        if self.cfg.get('txtlog', 'enabled') == 'true':
            if os.path.exists(self.txtlog_file):
                txtlog.log(self.txtlog_file, "Lost connection with the attacker: %s" % self.endIP)
        if self.sessionType == 'term' or self.sessionType == 'exec':
            ttylog.ttylog_close(self.ttylog_file, time.time())
            if self.cfg.get('database_mysql', 'enabled') == 'true':
                self.dbLog.handleConnectionLost(self.sid, self.ttylog_file)
            if self.cfg.get('hpfeeds', 'enabled') == 'true':
                self.hpLog.handleConnectionLost(self.ttylog_file)
            if self.cfg.get('email', 'attack') == 'true': 
                self.email('HonSSH - Attack logged', self.txtlog_file, self.ttylog_file)
        else:
            if self.cfg.get('database_mysql', 'enabled') == 'true':
                self.dbLog.handleConnectionLost(self.sid)
            if self.cfg.get('email', 'attack') == 'true':
                self.email('HonSSH - Attack logged', self.txtlog_file)
            if self.cfg.get('hpfeeds', 'enabled') == 'true':
                self.hpLog.handleConnectionLost() 
        
        dt = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if self.cfg.has_option('app_hooks', 'connection_lost'):
            cmdString = self.cfg.get('app_hooks', 'connection_lost') + " CONNECTION_LOST " + dt + " " + self.endIP
            threads.deferToThread(self.runCommand, cmdString)
            
    def setVersion(self, version):
        self.version = version
        if self.cfg.get('txtlog', 'enabled') == 'true':
            self.connectionString = self.connectionString + " - " + version
        if self.cfg.get('database_mysql', 'enabled') == 'true':
            self.dbLog.handleClientVersion(self.sid, self.version)
        if self.cfg.get('hpfeeds', 'enabled') == 'true':
            self.hpLog.handleClientVersion(self.version)
            
    def setSessionType(self, sessionType):
        self.sessionType = sessionType
        oldtxtlog_file = self.txtlog_file
        self.txtlog_file = self.logLocation + '-' + self.sessionType + ".log"
        
        if self.cfg.get('txtlog', 'enabled') == 'true':
            os.rename(oldtxtlog_file, self.txtlog_file)
            txtlog.log(self.txtlog_file, "Session Type: " + self.sessionType)
        #if self.cfg.get('database_mysql', 'enabled') == 'true':
            #self.dbLog.setSessionType(self.sid, self.version)
        if self.cfg.get('hpfeeds', 'enabled') == 'true':
            self.hpLog.setSessionType(self.sessionType)

    def loginSuccessful(self, username, password):
        dt = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.makeSessionFolder()
        if self.cfg.get('txtlog', 'enabled') == 'true':
            txtlog.otherLog(self.cfg.get('folders', 'log_path') + "/" + datetime.datetime.now().strftime("%Y%m%d"), self.endIP, username, password, True)
            txtlog.log(self.txtlog_file, self.connectionString)
            txtlog.log(self.txtlog_file, "Successful login - Username:%s Password:%s" % (username, password))
        
        if self.cfg.get('email', 'login') == 'true':
            self.email('HonSSH - Login Successful', self.txtlog_file)
        
        if self.cfg.get('database_mysql', 'enabled') == 'true':
            self.dbLog.handleLoginSucceeded(self.sid, username, password)
                    
        if self.cfg.get('hpfeeds', 'enabled') == 'true':
            self.hpLog.handleLoginSucceeded(username, password)
            
        if self.cfg.has_option('app_hooks', 'login_successful'):
            cmdString = self.cfg.get('app_hooks', 'login_successful') + " LOGIN_SUCCESSFUL " + dt + " " + self.endIP + " " + username + " " + password
            threads.deferToThread(self.runCommand, cmdString)
        
    def loginFailed(self, username, password):
        dt = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if self.cfg.get('txtlog', 'enabled') == 'true':
            txtlog.otherLog(self.cfg.get('folders', 'log_path') + "/" + datetime.datetime.now().strftime("%Y%m%d"), self.endIP, username, password, False)
        
        if self.cfg.get('database_mysql', 'enabled') == 'true':
            self.dbLog.handleLoginFailed(self.sid, username, password)
            
        if self.cfg.get('hpfeeds', 'enabled') == 'true':
            self.hpLog.handleLoginFailed(username, password)
            
        if self.cfg.has_option('app_hooks', 'login_failed'):
            cmdString = self.cfg.get('app_hooks', 'login_failed') + " LOGIN_FAILED " + dt + " " + self.endIP + " " + username + " " + password
            threads.deferToThread(self.runCommand, cmdString)
        
    def commandEntered(self, theCommand):
        if self.cfg.get('txtlog', 'enabled') == 'true':
            txtlog.log(self.txtlog_file, "Entered command: %s" % (theCommand))
        if self.cfg.get('database_mysql', 'enabled') == 'true':
            self.dbLog.handleCommand(self.sid, theCommand)
        if self.cfg.get('hpfeeds', 'enabled') == 'true':
            self.hpLog.handleCommand(theCommand)
            
        dt = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        #if self.cfg.has_option('app_hooks', 'command_entered'):
        #    cmdString = self.cfg.get('app_hooks', 'command_entered') + " COMMAND_ENTERED " + dt + " " + self.endIP + " " + theCommand
        #    threads.deferToThread(self.runCommand, cmdString)       
    
    def fileDownload(self, theCommand, link, user, password):
        dt = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        self.makeDownloadsFolder()
        if self.cfg.get('txtlog', 'enabled') == 'true':
            txtlog.log(self.txtlog_file, "wget Download Detected - %s" % theCommand)
        filename = dt + "-" + link.split("/")[-1]
        fileOut =self.cfg.get('folders', 'session_path') + '/' + self.endIP + '/downloads/' + filename
        wgetCommand = 'wget -O ' + fileOut + " "
        if user != '':
            wgetCommand = wgetCommand + '--user=' + user + ' '
        if password != '':
            wgetCommand = wgetCommand + '--password=' + password + ' '
        wgetCommand = wgetCommand + link
        
        d = threads.deferToThread(self.wget, wgetCommand, link, fileOut)
        d.addCallback(self.fileDownloaded)
        
        if self.cfg.has_option('app_hooks', 'download_started'):
            cmdString = self.cfg.get('app_hooks', 'download_started') + " DOWNLOAD_STARTED " + dt + " " + self.endIP + " " + link + " " + fileOut
            threads.deferToThread(self.runCommand, cmdString)  

    def fileDownloaded(self, input):
        dt = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        success, link, file, wgetError = input
        if success:
            if self.cfg.get('txtlog', 'enabled') == 'true':
                txtlog.log(self.txtlog_file, "Finished Downloading file - %s %s" % (link, file))
            if self.cfg.get('database_mysql', 'enabled') == 'true':
                self.dbLog.handleFileDownload(self.sid, link, file)
                
            if self.cfg.has_option('app_hooks', 'download_finished'):
                cmdString = self.cfg.get('app_hooks', 'download_finished') + " DOWNLOAD_FINISHED " + dt + " " + self.endIP + " " + link + " " + file
                threads.deferToThread(self.runCommand, cmdString)  
        else:
            log.msg('[OUTPUT] FILE DOWNLOAD FAILED')
            log.msg('[OUTPUT] ' + wgetError)

    def input(self, data):
        ttylog.ttylog_write(self.ttylog_file, len(data), ttylog.TYPE_OUTPUT, time.time(), data)
    
    def openTTY(self):
        ttylog.ttylog_open(self.ttylog_file, time.time())
        
    def genericLog(self, message):
        self.makeSessionFolder()
        if self.cfg.get('txtlog', 'enabled') == 'true':
            txtlog.log(self.txtlog_file, message)
            
    def errLog(self, message):
        self.makeSessionFolder()
        txtlog.log(self.logLocation + "-err.log", message)
        
    def advancedLog(self, message):
        self.makeSessionFolder()
        txtlog.log(self.logLocation + "-adv.log", message)
    
    def makeSessionFolder(self):
        if not os.path.exists(os.path.join(self.cfg.get('folders', 'session_path') + '/' + self.endIP)):
            os.makedirs(os.path.join(self.cfg.get('folders', 'session_path') + '/' + self.endIP))
            os.chmod(os.path.join(self.cfg.get('folders', 'session_path') + '/' + self.endIP),0755)
            
    def makeDownloadsFolder(self):
        if not os.path.exists(self.cfg.get('folders', 'session_path') + '/' + self.endIP + '/downloads'):
            os.makedirs(self.cfg.get('folders', 'session_path') + '/' + self.endIP + '/downloads')
            os.chmod(self.cfg.get('folders', 'session_path') + '/' + self.endIP + '/downloads',0755)
    
    def email(self, subject, body, attachment=None):
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
            fp = open(attachment, 'rb')
            logdata = MIMEBase('application', "octet-stream")
            logdata.set_payload(fp.read())
            fp.close()
            Encoders.encode_base64(logdata)
            logdata.add_header('Content-Disposition', 'attachment', filename=os.path.basename(self.ttylog_file))
            msg.attach(logdata)
        s = smtplib.SMTP(self.cfg.get('email', 'host'), int(self.cfg.get('email', 'port')))
        if self.cfg.get('email', 'username') != '' and self.cfg.get('email', 'password') != '':
            s.ehlo()
            if self.cfg.get('email', 'use_tls') == 'true':
                s.starttls()
            s.login(self.cfg.get('email', 'username'), self.cfg.get('email', 'password'))
        s.sendmail(msg['From'], msg['To'].split(','), msg.as_string())
        s.quit() #End send mail code
        
    def wget(self, wgetCommand, link, fileOut):
        sp = subprocess.Popen(wgetCommand, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        result = sp.communicate()
        if sp.returncode == 0:
            return True, link, fileOut, None
        else:
            return False, link, None, result[0]
        
    def runCommand(self, command):
        log.msg('[APP-HOOKS] - ' + command)
        sp = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        sp.communicate()
