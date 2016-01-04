from honssh import config

from twisted.python import log

import smtplib
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email import Encoders

class Plugin():

    def __init__(self, cfg):
        self.cfg = cfg
        
    def connection_made(self, sensor):
        self.login_success = False
        
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
                threads.deferToThread(self.email, self.sensor_name + ' - Attack logged', self.txtlog_file, self.ttyFiles)

    def email(self, subject, body, attachment=None):
        try:
            #Start send mail code - provided by flofrihandy, modified by peg
            msg = MIMEMultipart()
            msg['Subject'] = subject
            msg['From'] = self.cfg.get('output-email', 'from')
            msg['To'] = self.cfg.get('output-email', 'to')
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
            log.msg('[PLUGIN][EMAIL][ERR] - ' + str(ex))

        
    def validate_config(self):
        props = [['output-email','enabled'], ['output-email','login'], ['output-email','attack']]
        for prop in props:
            if not config.checkExist(self.cfg,prop) or not config.checkValidBool(self.cfg, prop):
                return False

        #If email is enabled check it's config
        if self.cfg.get('output-email','login') == 'true' or self.cfg.get('output-email','login') == 'attack':
            if self.cfg.get('txtlog','enabled') == 'true':
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
                print '[txtlog][enabled] must be set to true for email support to work'
                return False
        
        return True