from honssh import config

from honssh import log

import smtplib
import os
import time
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email import Encoders

class Plugin():

    def __init__(self, cfg):
        self.cfg = cfg
        
    def connection_made(self, sensor):
        self.login_success = False
        self.ttyFiles = []
        
    def login_successful(self, sensor):
        self.login_success = True
        session = sensor['session']
        self.log_file = session['log_location'] + session['start_time'] + '.log'
        if self.cfg.get('output-email', 'login') == 'true':
            self.email(sensor['sensor_name'] + ' - Login Successful', self.log_file)

    def connection_lost(self, sensor):
        if self.login_success:
            if self.cfg.get('output-email', 'attack') == 'true':
                self.ttyFiles = []
                session = sensor['session']
                for channel in session['channels']:
                    if 'ttylog_file' in channel:
                        self.ttyFiles.append(channel['ttylog_file'])
                self.email(sensor['sensor_name'] + ' - Attack logged', self.log_file)

    def email(self, subject, body):
        try:
            #Start send mail code - provided by flofrihandy, modified by peg
            msg = MIMEMultipart()
            msg['Subject'] = subject
            msg['From'] = self.cfg.get('output-email', 'from')
            msg['To'] = self.cfg.get('output-email', 'to')
            file_found = False
            timeout = 0
            while not file_found:
                if not os.path.isfile(body):
                    timeout = timeout + 1
                    time.sleep(1)
                else:
                    file_found = True
                if timeout == 30:
                    break
            if file_found:
                time.sleep(2)
                fp = open(body, 'rb')
                msg_text = MIMEText(fp.read())
                fp.close()
                msg.attach(msg_text)
                for tty in self.ttyFiles:
                    fp = open(tty, 'rb')
                    logdata = MIMEBase('application', "octet-stream")
                    logdata.set_payload(fp.read())
                    fp.close()
                    Encoders.encode_base64(logdata)
                    logdata.add_header('Content-Disposition', 'attachment', filename=os.path.basename(tty))
                    msg.attach(logdata)
                s = smtplib.SMTP(self.cfg.get('output-email', 'host'), int(self.cfg.get('output-email', 'port')))
                if self.cfg.get('output-email', 'username') != '' and self.cfg.get('output-email', 'password') != '':
                    s.ehlo()
                    if self.cfg.get('output-email', 'use_tls') == 'true':
                        s.starttls()
                    if self.cfg.get('output-email', 'use_smtpauth') == 'true':
                        s.login(self.cfg.get('output-email', 'username'), self.cfg.get('output-email', 'password'))
                s.sendmail(msg['From'], msg['To'].split(','), msg.as_string())
                s.quit() #End send mail code
        except Exception, ex:
            log.msg(log.LRED, '[PLUGIN][EMAIL][ERR]', str(ex))

        
    def validate_config(self):
        props = [['output-email','enabled'], ['output-email','login'], ['output-email','attack']]
        for prop in props:
            if not config.checkExist(self.cfg,prop) or not config.checkValidBool(self.cfg, prop):
                return False

        #If email is enabled check it's config
        if self.cfg.get('output-email','login') == 'true' or self.cfg.get('output-email','login') == 'attack':
            if self.cfg.get('output-txtlog','enabled') == 'true':
                prop = ['output-email','port']
                if not config.checkExist(self.cfg,prop) or not config.checkValidPort(self.cfg,prop):
                    return False
                props = [['output-email','use_tls'], ['output-email','use_smtpauth']]
                for prop in props:
                    if not config.checkExist(self.cfg,prop) or not config.checkValidBool(self.cfg,prop):
                        return False
                if self.cfg.get('output-email','use_smtpauth') == 'true':
                    props = [['output-email','username'], ['output-email','password']]
                    for prop in props:
                        if not config.checkExist(self.cfg,prop):
                            return False
                props = [['output-email','host'], ['output-email','from'], ['output-email','to']]
                for prop in props:
                    if not config.checkExist(self.cfg,prop):
                        return False
            else:
                print '[output-txtlog][enabled] must be set to true for email support to work'
                return False
        
        return True