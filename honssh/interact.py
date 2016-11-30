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

import json   
import base64 

from twisted.internet import protocol
from honssh import log


class Interact(protocol.Protocol):
    def __init__(self):
        self.interact = None

    def connectionMade(self):
        pass
           
    def dataReceived(self, data):
        datagrams = data.split('_')
        for i in range(0, len(datagrams)/3):
            datagram = datagrams[3*i:(3*i)+3]
            if datagram[0] == 'honssh' and datagram[1] == 'c':
                self.parsePacket(datagram[2])
            else:
                log.msg('[INTERACT] - Bad packet received')
                self.loseConnection()

    def sendData(self, the_json):
        the_data = base64.b64encode(json.dumps(the_json))
        self.transport.write('honssh_s_' + the_data + '_')
        
    def sendKeystroke(self, data):
        self.sendData(data)

    def getData(self, theData):
        return json.loads(base64.b64decode(theData))

    def parsePacket(self, theData):
        the_json = self.getData(theData)
        
        if not self.interact:
            the_command = the_json['command']
            if the_command:
                if the_command == 'list':
                    the_list = self.factory.connections.return_connections()
                    num_sessions = 0

                    for sensor in the_list:
                        num_sessions += len(sensor['sessions'])

                    if num_sessions == 0:
                        the_list = {'msg':'INFO: No active sessions'}

                    self.sendData(the_list)
                elif the_command in ['view', 'interact', 'disconnect']:
                    the_uuid = the_json['uuid']
                    if the_uuid:
                        sensor, session, chan = self.factory.connections.get_channel(the_uuid)
                        if chan is not None:
                            if the_command in ['view', 'interact']:
                                if 'TERM' in chan['name']:
                                    chan['class'].addInteractor(self)
                                    if the_command == 'interact':
                                        self.interact = chan['class']
                                else:
                                    self.sendData({'msg':'ERROR: Cannot connect to a non-TERM session'})
                            elif the_command == 'disconnect':
                                chan['class'].inject_disconnect()
                                self.sendData({'msg':'SUCCESS: Disconnected session: ' + the_uuid})
                        else:
                            self.sendData({'msg':'ERROR: UUID does not exist'})
                    else:
                        self.sendData({'msg':'ERROR: Must specify a UUID'})                       
                else:
                    self.sendData({'msg':'ERROR: Unknown Command'})
            else:
                self.sendData({'msg':'ERROR: Must specify a command'})
        else:
            self.interact.inject(the_json)


def make_interact_factory(honeypot_factory):
    ifactory = protocol.Factory()
    ifactory.protocol = Interact
    ifactory.server = honeypot_factory
    ifactory.connections = honeypot_factory.connections

    return ifactory
