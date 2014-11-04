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

import ConfigParser, os, re

def config():
    cfg = ConfigParser.ConfigParser()
    if os.path.exists('honssh.cfg'):
        cfg.read('honssh.cfg')
        return cfg
    return None

def validateConfig(cfg):
    validConfig = True
    
    #Check prop exists and is an IP address
    props = [['honeypot','ssh_addr'], ['honeypot','client_addr'], ['honeypot','honey_addr']]
    for prop in props:
        if not checkExist(cfg,prop) or not checkValidIP(cfg,prop):
            validConfig = False
        
    #Check prop exists and is a port number
    prop = ['honeypot','ssh_port']
    if not checkExist(cfg,prop) or not checkValidPort(cfg,prop):
        validConfig = False
        
    #Check prop exists
    props = [['honeypot','sensor_name'],['honeypot','public_key'], ['honeypot','private_key'], ['folders','log_path'], ['folders','session_path']]
    for prop in props:
        if not checkExist(cfg,prop):
            validConfig = False
            
    #Check prop exists and is true/false
    props = [['advNet','enabled'], ['interact','enabled'], ['spoof','enabled'], ['txtlog','enabled'], ['database_mysql','enabled'], ['email','login'], ['email','attack'], ['hpfeeds','enabled'], ['download','passive'], ['download','active'], ['packets','enabled'], ['hp-restrict', 'disable_publicKey'], ['hp-restrict', 'disable_x11'], ['hp-restrict', 'disable_sftp'], ['hp-restrict', 'disable_exec'], ['hp-restrict', 'disable_port_forwarding']]
    for prop in props:
        if not checkExist(cfg,prop) or not checkValidBool(cfg, prop):
            validConfig = False
    
    #If interact is enabled check it's config
    if cfg.get('interact','enabled') == 'true':
        prop = ['interact','interface']
        if not checkExist(cfg,prop) or not checkValidIP(cfg,prop):
            validConfig = False            
        prop = ['interact','port']
        if not checkExist(cfg,prop) or not checkValidPort(cfg,prop):
            validConfig = False    
    
    #If spoof is enabled check it's config
    if cfg.get('spoof','enabled') == 'true':
        prop = ['spoof','users_conf']
        if not checkExist(cfg,prop):
            validConfig = False
    
    #If database_mysql is enabled check it's config
    if cfg.get('database_mysql','enabled') == 'true':
        prop = ['database_mysql','port']
        if not checkExist(cfg,prop) or not checkValidPort(cfg,prop):
            validConfig = False
        props = [['database_mysql','host'], ['database_mysql','database'], ['database_mysql','username'], ['database_mysql','password']]
        for prop in props:
            if not checkExist(cfg,prop):
                validConfig = False
                
    #If email is enabled check it's config            
    if cfg.get('email','login') == 'true' or cfg.get('email','login') == 'attack':
        if cfg.get('txtlog','enabled') == 'true':
            prop = ['email','port']
            if not checkExist(cfg,prop) or not checkValidPort(cfg,prop):
                validConfig = False
            props = [['email','use_tls'], ['email','use_smtpauth']]
            for prop in props:
                if not checkExist(cfg,prop) or not checkValidBool(cfg,prop):
                    validConfig = False
            if cfg.get('email','use_smtpauth') == 'true':
                props = [['email','username'], ['email','password']]
                for prop in props:
                    if not checkExist(cfg,prop):
                        validConfig = False
            props = [['email','host'], ['email','from'], ['email','to']]
            for prop in props:
                if not checkExist(cfg,prop):
                    validConfig = False
        else:
            print '[txtlog][enabled] must be set to true for email support to work'
            validConfig = False
            
    #If hpfeeds is enabled check it's config
    if cfg.get('hpfeeds','enabled') == 'true':
        props = [['hpfeeds','server'], ['hpfeeds','identifier'], ['hpfeeds','secret']]
        for prop in props:
            if not checkExist(cfg,prop):
                validConfig = False
        prop = ['hpfeeds','port']
        if not checkExist(cfg,prop) or not checkValidPort(cfg,prop):
            validConfig = False
    

    return validConfig
    
def checkExist(cfg, property): 
    if cfg.has_option(property[0], property[1]):   
        if not cfg.get(property[0], property[1]) == '':
            return True
        else:
            print '[VALIDATION] - [' + property[0] + '][' + property[1] + '] must not be blank.'
            return False
    else:
        print '[VALIDATION] - [' + property[0] + '][' + property[1] + '] must exist.'
        return False
    
def checkValidIP(cfg, property):
    match = re.match('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', cfg.get(property[0], property[1]))
    if match:
        return True
    else:
        print '[VALIDATION] - [' + property[0] + '][' + property[1] + '] should be a valid IP address'
        return False
    
def checkValidPort(cfg, property):
    if checkValidNumber(cfg, property):
        if 1 <= int(cfg.get(property[0], property[1])) <= 65535:
            return True
        else:
            print '[VALIDATION] - [' + property[0] + '][' + property[1] + '] should be between 1 and 65535'
            return False 
def checkValidBool(cfg, property):
    if cfg.get(property[0], property[1]) in ['true', 'false']:
        return True
    else:
        print '[VALIDATION] - [' + property[0] + '][' + property[1] + '] must be either true or false (case sensitive)'
        return False
    
def checkValidNumber(cfg, property):
    if cfg.get(property[0], property[1]).isdigit():
        return True
    else:
        print '[VALIDATION] - [' + property[0] + '][' + property[1] + '] should be number.'
        return False
def checkValidChance(cfg, property):
    if checkValidNumber(cfg, property):
        if 1 <= int(cfg.get(property[0], property[1])):
            return True
        else:
            print '[VALIDATION] - [' + property[0] + '][' + property[1] + '] should be greater than 0'
            return False 