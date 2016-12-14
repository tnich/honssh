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
import pprint

from honssh import log
import nmap


class Nmap(object):
    def __init__(self, peer_ip, callback=None):
        self.peer_ip = peer_ip
        self.callback = callback
        self.nm = nmap.PortScannerAsync()

    def scan(self):
        log.msg(log.LRED, '[ANALYZER][NMAP]', 'Failed to create port scanner.')
        self.nm.scan(hosts=self.peer_ip, arguments='-n -sS -Pn -O -F', callback=self.scan_finished)

    def scan_finished(self, host, scan_data):
        # osmatch
        # fingerprint

        pprint.pprint(scan_data)

        if self.callback is not None:
            scan_data = scan_data['scan'][host]
            print('Host : %s' % scan_data.hostname())
            print('OS : %s' % scan_data['osmatch'])
            #print('Fingerprint : %s' % scan_data['fingerprint'])
            print('State : %s' % scan_data.state())
            for proto in scan_data.all_protocols():
                print('----------')
                print('Protocol : %s' % proto)

                lport = scan_data[proto].keys()
                lport.sort()
                for port in lport:
                    print ('port : %s\tstate : %s' % (port, scan_data[proto][port]['state']))

            self.callback()