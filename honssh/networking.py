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
import subprocess


class Networking(object):
    def __init__(self):
        self.cfg = Config.getInstance()
        self.peer_ip = None
        self.fake_ip = None
        self.honey_port = None
        self.honey_ip = None

    def setup_networking(self, peer_ip, honey_ip, honey_port):
        if self.cfg.getboolean(['advNet', 'enabled']):
            self.peer_ip = peer_ip
            self.honey_port = str(honey_port)
            self.honey_ip = honey_ip

            self.fake_ip = self.get_fake_ip(self.peer_ip)

            sp = self.run_command('ip link add name honssh type dummy')
            result = sp.communicate()
            if sp.returncode != 0:
                if 'File exists' in result[0]:
                    log.msg(log.LPURPLE, '[ADV-NET]', 'HonSSH Interface already exists, not re-adding')
                    return self.add_fake_ip()
                else:
                    log.msg(log.LRED, '[ADV-NET]', 'Error creating HonSSH Interface - Using client_addr: ' + result[0])
                    return self.cfg.get(['honeypot', 'client_addr'])
            else:
                sp = self.run_command('ip link set honssh up')
                result = sp.communicate()
                if sp.returncode != 0:
                    log.msg(log.LRED, '[ADV-NET]',
                            'Error setting HonSSH Interface UP - Using client_addr: ' + result[0])
                    return self.cfg.get(['honeypot', 'client_addr'])
                else:
                    log.msg(log.LGREEN, '[ADV-NET]', 'HonSSH Interface created')
                    return self.add_fake_ip()
        else:
            log.msg(log.LPURPLE, '[ADV-NET]', 'Advanced Networking disabled - Using client_addr')
            return self.cfg.get(['honeypot', 'client_addr'])

    def add_fake_ip(self):
        sp = self.run_command('ip addr add ' + self.fake_ip + '/32 dev honssh')
        result = sp.communicate()
        if sp.returncode != 0:
            if 'File exists' in result[0]:
                log.msg(log.LPURPLE, '[ADV-NET]', 'Fake IP Address already exists, not re-adding')
                return self.fake_ip
            else:
                log.msg(log.LRED, '[ADV-NET]',
                        'Error adding IP address to HonSSH Interface - Using client_addr: ' + result[0])
                return self.cfg.get(['honeypot', 'client_addr'])
        else:
            sp = self.run_command(
                'iptables -t nat -A POSTROUTING -s ' + self.fake_ip + '/32 -d ' + self.honey_ip + '/32 -p tcp --dport '
                + self.honey_port + ' -j SNAT --to ' + self.peer_ip)

            result = sp.communicate()
            if sp.returncode != 0:
                log.msg(log.LRED, '[ADV-NET]', 'Error creating POSTROUTING Rule - Using client_addr: ' + result[0])
                return self.cfg.get(['honeypot', 'client_addr'])
            else:
                sp = self.run_command(
                    'iptables -t nat -A PREROUTING -s ' + self.honey_ip + '/32 -d ' + self.peer_ip + '/32 -p tcp --sport '
                    + self.honey_port + ' -j DNAT --to ' + self.fake_ip)

                result = sp.communicate()
                if sp.returncode != 0:
                    log.msg(log.LRED, '[ADV-NET]', 'Error creating PREROUTING Rule - Using client_addr: ' + result[0])
                    return self.cfg.get(['honeypot', 'client_addr'])
                else:
                    log.msg(log.LGREEN, '[ADV-NET]', 'HonSSH FakeIP and iptables rules added')
                    return self.fake_ip

    def remove_fake_ip(self):
        sp = self.run_command('ip addr del ' + self.fake_ip + '/32 dev honssh')
        result = sp.communicate()
        if sp.returncode != 0:
            log.msg(log.LRED, '[ADV-NET]', 'Error removing IP address to HonSSH Interface: ' + result[0])

        sp = self.run_command(
            'iptables -t nat -D POSTROUTING -s ' + self.fake_ip + '/32 -d ' + self.honey_ip + '/32 -p tcp --dport '
            + self.honey_port + ' -j SNAT --to ' + self.peer_ip)

        result = sp.communicate()
        if sp.returncode != 0:
            log.msg(log.LRED, '[ADV-NET]', 'Error removing POSTROUTING Rule: ' + result[0])

        sp = self.run_command(
            'iptables -t nat -D PREROUTING -s ' + self.honey_ip + '/32 -d ' + self.peer_ip + '/32 -p tcp --sport '
            + self.honey_port + ' -j DNAT --to ' + self.fake_ip)

        result = sp.communicate()
        if sp.returncode != 0:
            log.msg(log.LRED, '[ADV-NET]', 'Error removing PREROUTING Rule: ' + result[0])

    def remove_networking(self, connections):
        if self.cfg.getboolean(['advNet', 'enabled']):
            if len(connections) > 0:
                found = False
                for sensor in connections:
                    for session in sensor['sessions']:
                        if session['peer_ip'] == self.peer_ip:
                            found = True
                            break
                if not found:
                    self.remove_fake_ip()
            else:
                self.remove_fake_ip()
                sp = self.run_command('ip link del dev honssh')
                result = sp.communicate()
                if sp.returncode != 0:
                    log.msg(log.LRED, '[ADV-NET]', 'Error removing HonSSH Interface: ' + result[0])

    def get_fake_ip(self, peer_ip):
        ip_bits = peer_ip.split('.')
        for i in range(0, len(ip_bits)):
            ip_bits[i] = int(ip_bits[i]) + 1
            if ip_bits[i] >= 255:
                ip_bits[i] = 1

            ip_bits[i] = str(ip_bits[i])

        return '.'.join(ip_bits)

    def run_command(self, cmd):
        return subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
