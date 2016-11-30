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
from honssh.config import Config
import ConfigParser
import os
import re
import random


def get_connection_details(conn_details):
    cfg = Config.getInstance()

    if cfg.getboolean(['spoof', 'enabled']):
        users = get_users(conn_details['username'])
        rand = 0

        if users is not None:
            for user in users:
                if user[1] == conn_details['password']:
                    rand = 1
                else:
                    if user[2] == 'fixed':
                        passwords = re.sub(r'\s', '', user[3]).split(',')
                        if conn_details['password'] in passwords:
                            rand = 1
                    elif user[2] == 'random':
                        if int(user[3]) > 0:
                            random_factor = (100 / int(user[3])) + 1
                            rand = random.randrange(1, random_factor)

                    logfile = cfg.get(['folders', 'log_path']) + "/spoof.log"

                    if os.path.isfile(logfile):
                        f = file(logfile, 'r')
                        creds = f.read().splitlines()
                        f.close()

                        for cred in creds:
                            cred = cred.strip().split(' - ')
                            if cred[0] == conn_details['username'] and cred[1] == conn_details['password']:
                                rand = 1
                                break
        if rand == 1:
            write_spoof_log(conn_details)
            return True, conn_details['username'], user[1]

    return False, '', ''


def get_users(username):
    cfg = Config.getInstance()
    user_cfg_path = cfg.get(['spoof', 'users_conf'])

    if os.path.exists(user_cfg_path):
        users_cfg = ConfigParser.ConfigParser()
        users_cfg.read(user_cfg_path)
        users = users_cfg.sections()

        retval = []

        for user in users:
            if user == username:
                if users_cfg.has_option(user, 'fake_passwords'):
                    retval.append([user, users_cfg.get(user, 'real_password'), 'fixed', users_cfg.get(user, 'fake_passwords')])

                if users_cfg.has_option(user, 'random_chance'):
                    retval.append([user, users_cfg.get(user, 'real_password'), 'random', users_cfg.get(user, 'random_chance')])

        return retval if len(retval) > 0 else None
    else:
        log.msg(log.LRED, '[SPOOF]', 'ERROR: users_conf does not exist')
    return None


def write_spoof_log(conn_details):
    cfg = Config.getInstance()

    logfile = cfg.get(['folders', 'log_path']) + '/spoof.log'
    username = conn_details['username']
    password = conn_details['password']
    ip = conn_details['peer_ip']

    set_permissions = False
    found = False

    if os.path.isfile(logfile):
        f = file(logfile, 'r')
        lines = f.readlines()
        f.close()

        for i in range(len(lines)):
            lines[i] = lines[i].strip().split(' - ')
            if lines[i][0] == username and lines[i][1] == password:
                found = True
                if ip not in lines[i][2:]:
                    lines[i].append(ip)

        f = file(logfile, 'w')

        for line in lines:
            f.write(' - '.join(line) + '\n')

        if not found:
            f.write("%s - %s - %s\n" % (username, password, ip))

        f.close()
    else:
        f = file(logfile, 'a')
        f.write("%s - %s - %s\n" % (username, password, ip))
        f.close()
        set_permissions = True

    if set_permissions:
        os.chmod(logfile, 0644)
