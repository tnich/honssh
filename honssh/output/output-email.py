#!/usr/bin/env python

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

from honssh.config import Config

from honssh import log

import smtplib
import os
import time
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email import Encoders

class Plugin():

    def __init__(self):
        self.cfg = Config.getInstance()
        
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
