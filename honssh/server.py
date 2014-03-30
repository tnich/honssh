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
from twisted.conch.ssh import factory, transport, service
from twisted.conch.ssh.transport import SSHCiphers
from twisted.python import log
from twisted.internet import reactor
from honssh import client, txtlog, extras
from kippo.core import ttylog
from kippo.core.config import config
import datetime, time, os, struct, re, subprocess

class HonsshServerTransport(transport.SSHServerTransport):
    command = ''
    currUsername = ''
    currPassword = ''
    endIP = ''
    txtlog_file = ''
    ttylog_file = ''
    connectionString = ''
    tabPress = False
    upArrow = False
    isPty = False
    size = 0
    name = ''
    passwdDetected = False
    newPass = ''
    cfg = config()
    
    def connectionMade(self):
        self.interactors = []
        clientFactory = client.HonsshClientFactory()
        clientFactory.server = self

        self.factory.sessions[self.transport.sessionno] = self
             
        reactor.connectTCP(self.cfg.get('honeypot', 'honey_addr'), 22, clientFactory, bindAddress=(self.cfg.get('honeypot', 'client_addr'),self.transport.getPeer().port))
        
        self.endIP = self.transport.getPeer().host
        self.logLocation = self.cfg.get('honeypot', 'session_path') + "/" + self.endIP + "/" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.txtlog_file = self.logLocation + ".log"
        self.connectionString = "Incoming connection from: %s:%s" % (self.endIP,self.transport.getPeer().port)
        
        self.ttylog_file = self.logLocation + ".tty"

        transport.SSHServerTransport.connectionMade(self)
        
    def connectionLost(self, reason):
        try:
            self.client.loseConnection()       
        except:
            pass
        for i in self.interactors:
            i.sessionClosed()
        if self.transport.sessionno in self.factory.sessions:
            del self.factory.sessions[self.transport.sessionno]
        transport.SSHServerTransport.connectionLost(self, reason)
        log.msg("Lost connection with the attacker: %s" % self.endIP)
        txtlog.log(self.txtlog_file, "Lost connection with the attacker: %s" % self.endIP)

        if self.isPty:
            ttylog.ttylog_close(self.ttylog_file, time.time())
            if self.cfg.get('extras', 'mail_enable') == 'true': #Start send mail code - provided by flofrihandy, modified by peg
                log.msg("Sending email")
                import smtplib
                from email.mime.base import MIMEBase
                from email.mime.multipart import MIMEMultipart
                from email.mime.text import MIMEText
                from email import Encoders
                msg = MIMEMultipart()
                msg['Subject'] = 'HonSSH - Attack logged'
                msg['From'] = self.cfg.get('extras', 'mail_from')
                msg['To'] = self.cfg.get('extras', 'mail_to')
                fp = open(self.txtlog_file, 'rb')
                msg_text = MIMEText(fp.read())
                fp.close()
                msg.attach(msg_text)
                fp = open(self.ttylog_file, 'rb')
                logdata = MIMEBase('application', "octet-stream")
                logdata.set_payload(fp.read())
                fp.close()
                Encoders.encode_base64(logdata)
                logdata.add_header('Content-Disposition', 'attachment', filename=os.path.basename(self.ttylog_file))
                msg.attach(logdata)
                s = smtplib.SMTP(self.cfg.get('extras', 'mail_host'), int(self.cfg.get('extras', 'mail_port')))
                if self.cfg.get('extras', 'mail_username') != '' and self.cfg.get('extras', 'mail_password') != '':
                    s.ehlo()
                    if self.cfg.get('extras', 'mail_use_tls') == 'true':
                        s.starttls()
                    s.login(self.cfg.get('extras', 'mail_username'), self.cfg.get('extras', 'mail_password'))
                s.sendmail(msg['From'], msg['To'].split(','), msg.as_string())
                s.quit() #End send mail code
                log.msg("Finished sending email")
        
    def ssh_KEXINIT(self, packet):
        self.connectionString = self.connectionString + " - " + self.otherVersionString
        return transport.SSHServerTransport.ssh_KEXINIT(self, packet)
    
    def makeSessionFolder(self):
        if not os.path.exists(os.path.join('sessions/' + self.endIP)):
            os.makedirs(os.path.join('sessions/' + self.endIP))
            os.chmod(os.path.join('sessions/' + self.endIP),0755)
            
    def processCommand(self, theCommand):
        txtlog.log(self.txtlog_file, "Entered command: %s" % (theCommand))
        if self.cfg.get('extras', 'file_download') == 'true':
            match = re.finditer("wget .*?((?:http|ftp|https):\/\/[\w\-_]+(?:\.[\w\-_]+)+(?:[\w\-\.,@?^=%&amp:/~\+#]*[\w\-\@?^=%&amp/~\+#])?)", theCommand)
                            
            if not os.path.exists('downloads/' + self.endIP):
                os.makedirs('downloads/' + self.endIP)
                os.chmod('downloads/' + self.endIP,0755)  
                               
            args = ''                  
            for m in match:
                argMatch = re.search("--user=(.*?) ", m.group(0))
                if argMatch:
                    args = args + argMatch.group(0)
                argMatch = re.search("--password=(.*?) ", m.group(0))
                if argMatch:
                    args = args + argMatch.group(0)
                argMatch = re.search("--http-user=(.*?) ", m.group(0))
                if argMatch:
                    args = args + argMatch.group(0)
                argMatch = re.search("--http-password=(.*?) ", m.group(0))
                if argMatch:
                    args = args + argMatch.group(0)   
                argMatch = re.search("--ftp-user=(.*?) ", m.group(0))
                if argMatch:
                    args = args + argMatch.group(0)
                argMatch = re.search("--ftp-password=(.*?) ", m.group(0))
                if argMatch:
                    args = args + argMatch.group(0)
                
                txtlog.log(self.txtlog_file, "wget Download Detected - %s" % str(m.group(0)))
                filename = datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + "-" + str(m.group(1)).split("/")[-1]
                wgetCommand = "wget -O downloads/" + self.endIP + "/" + filename + " " + args + str(m.group(1))
                txtlog.log(self.txtlog_file, "wget Download Detected - Executing command: %s" % wgetCommand)
                subprocess.Popen(wgetCommand, shell=True)
    
    def dispatchMessage(self, messageNum, payload):
        if transport.SSHServerTransport.isEncrypted(self, "both"):
            self.sendOn = True
            self.tabPress = False
            self.upArrow = False

            if messageNum == 50: 
                p = 0
                num = int(payload[p:p+4].encode('hex'), 16)
                p = p+4
                self.currUsername = payload[p:p+num]
                p = p+num
                num = int(payload[p:p+4].encode('hex'), 16)
                p = p+4
                service = payload[p:p+num]
                p = p+num
                num = int(payload[p:p+4].encode('hex'), 16)
                p = p+4
                auth = payload[p:p+num]
                p = p+num+1
                if auth == 'password':
                    pos = p
                    num = int(payload[p:p+4].encode('hex'), 16)
                    p = p+4
                    self.currPassword = payload[p:p+num]
                    txtlog.otherLog(self.cfg.get('honeypot', 'log_path') + "/" + datetime.datetime.now().strftime("%Y%m%d"), self.endIP, self.currUsername, self.currPassword)
                    extras.attemptedLogin(self.currUsername, self.currPassword)
                    if(self.cfg.get('honeypot', 'spoof_login') == 'true'):
                        self.client.failedString = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " - Spoofing Login - Changing %s to %s\n" % (self.currPassword, self.cfg.get('honeypot', 'spoof_pass'))
                        payload = payload[0:pos]
                        b = self.cfg.get('honeypot', 'spoof_pass').encode('utf-8')
                        payload = payload + struct.pack('>L',len(b))
                        payload = payload + b
            elif messageNum == 98:
                num = int(payload[7:8].encode('hex'), 16)
                data = payload[8:8+num]
                if data == 'pty-req' or data == 'exec':
                    self.isPty = True
                    ttylog.ttylog_open(self.ttylog_file, time.time())
                    if data == 'exec':
                        self.processCommand(repr(payload[17:])[1:-1])
                        data = "INPUT: " + payload[17:] + "\n\n\n"
                        ttylog.ttylog_write(self.ttylog_file, len(data), ttylog.TYPE_OUTPUT, time.time(), data)
                elif data == 'subsystem' and 'sftp' in repr(payload):
                    log.msg("Detected SFTP - Disabling")
                    self.sendOn = False
                    self.sendPacket(100, '\x00\x00\x00\x00') #Might be OpenSSH specific replies - fingerprinting issue?
                    #TODO: Code proper handling of SFTP - capture commands and uploads etc.
                else:
                    if data != 'shell' and data != 'env':
                        txtlog.log(self.txtlog_file, "New message 98 type detected - Please raise a HonSSH issue on google code with the details: %s" % (data))
                        log.msg("SERVER: MessageNum: " + str(messageNum) + " Encrypted " + repr(payload))
            elif messageNum == 90:
                if 'direct-tcpip' in repr(payload) or 'forwarded-tcpip' in repr(payload):
                    log.msg("Detected Port Forwarding - disabling")
                    num = int(payload[0:4].encode('hex'), 16)
                    channel = int(payload[4+num:4+num+4].encode('hex'), 16)
                    self.sendOn = False
                    p = struct.pack('>L',channel)
                    self.sendPacket(92, p + '\x00\x00\x00\x01\x00\x00\x00\x0bopen failed\x00\x00\x00\x00')  #Might be OpenSSH specific replies - fingerprinting issue?
            elif messageNum == 80:
                if 'tcpip-forward' in repr(payload):
                    log.msg("Detected Remote Forwarding - disabling")
                    self.sendOn = False
                    self.sendPacket(4,'\x00\x00\x00\x00$Server has disabled port forwarding.\x00\x00\x00\x00')  #Might be OpenSSH specific replies - fingerprinting issue?
            elif messageNum == 97:
                log.msg("Disconnect received from the attacker: %s" % self.endIP)
            elif messageNum == 94 or messageNum == 95:
                data = payload[8:]
                if messageNum == 95:
                    data = payload[12:]
                    
                if self.isPty:
                    if data == '\x0d' or data == '\x03':  #if enter or ctrl+c
                        if data == '\x03':
                            self.command = self.command + "^C"
                        if self.cfg.get('honeypot', 'spoof_login') == 'true' and self.command == 'passwd':
                            self.passwdDetected = True
                        if self.passwdDetected == True:
                            self.newPass = self.command
                        log.msg("Entered command: %s" % (self.command))
                        self.processCommand(self.command)
                        self.command = ""
                    elif data == '\x7f':    #if backspace
                        self.command = self.command[:-1]
                    elif data == '\x09':    #if tab
                        self.tabPress = True
                    elif data == '\x1b\x5b\x41' or data == '\x1b\x5b\x42':    #up arrow or down arrow...
                        self.upArrow = True
                    else:
                        s = repr(data)
                        self.command = self.command + s[1:-1]
                else:
                    if self.size > 0:
                        if self.cfg.get('extras', 'file_download') == 'true':
                            f = open("downloads/" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + "-" + self.name, 'ab')
                            f.write(data)
                            f.close()
                        self.size = self.size - len(data)
                    elif data != '\x00' and data != '\x0a':
                        txtlog.log(self.txtlog_file, "RAW CLIENT-SERVER: %s" % (repr(data)))
                    
                    match = re.match('C\d{4} (\d*) (.*)', data)
                    if match:
                        txtlog.log(self.txtlog_file, "Uploading File via SCP: %s" % str(match.group(2)))
                        self.size = int(match.group(1))
                        self.name = str(match.group(2))
                    
            else:
                if self.cfg.get('extras', 'adv_logging') == 'false':
                    if messageNum not in [1,2,5,6,20,21,80,91,93] and messageNum not in range(30,49) and messageNum not in range(96,100):
                        self.makeSessionFolder()
                        txtlog.log(self.txtlog_file, "Unknown SSH Packet detected - Please raise a HonSSH issue on google code with the details: SERVER %s - %s" % (str(messageNum), repr(payload)))
                        log.msg("SERVER: MessageNum: " + str(messageNum) + " Encrypted " + repr(payload))
                    
            if self.cfg.get('extras', 'adv_logging') == 'true':
                self.makeSessionFolder()
                txtlog.log(self.txtlog_file[:self.txtlog_file.rfind('.')] + "-adv.log", "SERVER: MessageNum: " + str(messageNum) + " Encrypted " + repr(payload))
            
            #log.msg("SERVER: MessageNum: " + str(messageNum) + " Encrypted " + repr(payload))

            if self.sendOn:
                self.client.sendPacket(messageNum, payload)
        else:
            transport.SSHServerTransport.dispatchMessage(self, messageNum, payload)
    
    def addInteractor(self, interactor):
        self.interactors.append(interactor)

    def delInteractor(self, interactor):
        self.interactors.remove(interactor)
        
    def sendPacket(self, messageNum, payload):
        #log.msg("SERVER: MessageNum: " + str(messageNum) + " Encrypted " + repr(payload))
        transport.SSHServerTransport.sendPacket(self, messageNum, payload)



class HonsshServerFactory(factory.SSHFactory):
    cfg = config()      
    otherVersionString=''
    sessions = {}
    def __init__(self):
        clientFactory = client.HonsshSlimClientFactory()
        clientFactory.server = self
        reactor.connectTCP(self.cfg.get('honeypot', 'honey_addr'), 22, clientFactory)
    
    def buildProtocol(self, addr):
        t = HonsshServerTransport()
        
        t.ourVersionString = self.otherVersionString
        t.factory = self
        t.supportedPublicKeys = self.privateKeys.keys()
        if not self.primes:
            log.msg('disabling diffie-hellman-group-exchange because we cannot find moduli file')
            ske = t.supportedKeyExchanges[:]
            ske.remove('diffie-hellman-group-exchange-sha1')
            t.supportedKeyExchanges = ske
        return t
