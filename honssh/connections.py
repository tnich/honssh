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

class Connections():
    connections = []
    
    def getSensor(self, theName, honeyIP='', honeyPort=''):
        sensor = {}
        for s in self.connections:
            if s['sensor_name'] == theName:
                sensor = s
        if not sensor:
            sensor = {'sensor_name':theName, 'honeyIP':honeyIP, 'honeyPort':honeyPort, 'sessions':[]}
            self.connections.append(sensor)
    
        return sensor
    
    def addConn(self, sensor, ip, port, dt, honeyIP, honeyPort):
       s = self.getSensor(sensor, honeyIP=honeyIP, honeyPort=honeyPort)
       s['sessions'].append({'peerIP':ip, 'peerPort':port, 'startTime':dt, 'channels':[]})
    
    def delConn(self, sensor, ip, port):
        s = self.getSensor(sensor)
        for session in s['sessions']:
            if session['peerIP'] == ip and session['peerPort'] == port:
                s['sessions'].remove(session)
                break
        if len(s['sessions']) == 0:
            self.connections.remove(s)
            
    def getConn(self, sensor, ip, port):
        s = self.getSensor(sensor)
        for session in s['sessions']:
            if session['peerIP'] == ip and session['peerPort'] == port:
                return session
        return None
    
    def addChannel(self, sensor, ip, port, name, dt, uuid):
        c = self.getConn(sensor, ip, port)
        c['channels'].append({'name': name, 'startTime': dt, 'uuid':uuid})
        
    def delChannel(self, sensor, ip, port, uuid):
        c = self.getConn(sensor, ip, port)
        for channel in c['channels']:
            if channel['uuid'] == uuid:
                c['channels'].remove(channel)
                break

    def getChan(self, uuid):
        for sensor in self.connections:
            for session in sensor['sessions']:
                for channel in session['channels']:
                    if channel['uuid'] == uuid:
                        return channel
        return None
    
    def setClient(self, sensor, ip, version):
        s = self.getSensor(sensor)
        for session in s['sessions']:
            if session['peerIP'] == ip:
                session['version'] = version
                break