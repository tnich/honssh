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

import copy


class Connections(object):
    connections = []

    def return_connections(self):
        connections_copy = copy.deepcopy(self.connections)
        return connections_copy

    def get_sensor(self, sensor_name, honey_ip='', honey_port=''):
        sensor = {}
        for s in self.connections:
            if s['sensor_name'] == sensor_name:
                sensor = s

        if not sensor:
            sensor = {'sensor_name': sensor_name, 'honey_ip': honey_ip, 'honey_port': honey_port, 'sessions': []}
            self.connections.append(sensor)
        return sensor

    def add_session(self, sensor, peer_ip, peer_port, dt, honey_ip, honey_port, session_id, log_location, country):
        sensor = self.get_sensor(sensor, honey_ip=honey_ip, honey_port=honey_port)
        if sensor:
            session = {'session_id': session_id, 'peer_ip': peer_ip, 'peer_port': peer_port, 'start_time': dt,
                       'log_location': log_location, 'country': country, 'channels': [], 'auths': []}
            sensor['sessions'].append(session)
            return self.return_session(sensor, session)
        return None

    def set_session_close(self, session_id, dt):
        sensor, session = self.get_session(session_id)
        if sensor and session:
            session['end_time'] = dt
            return self.return_session(sensor, session)
        return None

    def return_session(self, sensor, session):
        sensor_copy = copy.deepcopy(sensor)
        sensor_copy.pop('sessions')
        sensor_copy['session'] = copy.deepcopy(session)
        return sensor_copy

    def del_session(self, session_id):
        sensor, session = self.get_session(session_id)
        if sensor and session:
            sensor['sessions'].remove(session)

            if len(sensor['sessions']) == 0:
                self.connections.remove(sensor)

    def get_session(self, session_id):
        for sensor in self.connections:
            for session in sensor['sessions']:
                if session['session_id'] == session_id:
                    return sensor, session
        return None, None

    def add_auth(self, session_id, date_time, username, password, success, spoofed):
        sensor, session = self.get_session(session_id)
        if session:
            auth = {'date_time': date_time, 'username': username, 'password': password, 'success': success,
                    'spoofed': spoofed}
            session['auths'].append(auth)
            return self.return_auth(sensor, session, auth)
        return None

    def return_auth(self, sensor, session, auth):
        session_copy = copy.deepcopy(session)
        session_copy.pop('channels')
        session_copy.pop('auths')
        session_copy['auth'] = copy.deepcopy(auth)
        return self.return_session(sensor, session_copy)

    def set_client(self, session_id, version):
        sensor, session = self.get_session(session_id)
        if session:
            session['version'] = version
            return self.return_session(sensor, session)
        return None

    def get_passwords_attempted(self, session_id):
        sensor, session = self.get_session(session_id)
        if session:
            if len(session['auths']) > 0:
                return True
            else:
                return False
        return None

    def get_login_successful(self, session_id):
        sensor, session = self.get_session(session_id)
        if session:
            for auth in session['auths']:
                if auth['success']:
                    return True
            return False
        return None

    def add_channel(self, session_id, name, dt, channel_id):
        sensor, session = self.get_session(session_id)
        if session:
            channel = {'name': name, 'start_time': dt, 'uuid': channel_id, 'commands': [], 'downloads': []}
            session['channels'].append(channel)
            return self.return_channel(sensor, session, channel)
        return None

    def set_channel_close(self, channel_id, dt):
        sensor, session, channel = self.get_channel(channel_id)
        if sensor and session and channel:
            channel['end_time'] = dt
            return self.return_channel(sensor, session, channel)
        return None

    def return_channel(self, sensor, session, channel):
        session_copy = copy.deepcopy(session)
        session_copy.pop('channels')
        session_copy.pop('auths')
        session_copy['channel'] = copy.deepcopy(channel)
        return self.return_session(sensor, session_copy)

    def del_channel(self, channel_id):
        sensor, session, channel = self.get_channel(channel_id)
        if sensor and session and channel:
            session['channels'].remove(channel)

    def get_channel(self, channel_id):
        for sensor in self.connections:
            for session in sensor['sessions']:
                for channel in session['channels']:
                    if channel['uuid'] == channel_id:
                        return sensor, session, channel
        return None, None, None

    def get_channels(self, session_id):
        sensor, session = self.get_session(session_id)
        if sensor and session:
            return session['channels']
        return None

    def add_ttylog_file(self, channel_id, ttylog_file):
        for sensor in self.connections:
            for session in sensor['sessions']:
                for channel in session['channels']:
                    if channel['uuid'] == channel_id:
                        channel['ttylog_file'] = ttylog_file

    def add_command(self, channel_id, dt, command_string, blocked):
        sensor, session, channel = self.get_channel(channel_id)
        if channel:
            if blocked:
                success = False
            else:
                success = True

            command = {'command': command_string, 'date_time': dt, 'success': success}
            channel['commands'].append(command)
            return self.return_command(sensor, session, channel, command)
        return None

    def return_command(self, sensor, session, channel, command):
        channel_copy = copy.deepcopy(channel)
        channel_copy.pop('commands')
        channel_copy.pop('downloads')
        channel_copy['command'] = copy.deepcopy(command)
        return self.return_channel(sensor, session, channel_copy)

    def add_download(self, channel_id, dt, link):
        sensor, session, channel = self.get_channel(channel_id)
        if channel:
            download = {'start_time': dt, 'link': link, 'file': '', 'success': False}
            channel['downloads'].append(download)
            return self.return_download(sensor, session, channel, download)
        return None

    def set_download_close(self, channel_id, dt, link, file, success, sha256, size):
        sensor, session, channel = self.get_channel(channel_id)
        for download in channel['downloads']:
            if download['link'] == link and download['success'] == False:
                download['file'] = file
                download['end_time'] = dt
                download['success'] = success
                download['sha256'] = sha256
                download['size'] = size
                return self.return_download(sensor, session, channel, download)
        return None

    def return_download(self, sensor, session, channel, download):
        channel_copy = copy.deepcopy(channel)
        channel_copy.pop('commands')
        channel_copy.pop('downloads')
        channel_copy['download'] = copy.deepcopy(download)
        return self.return_channel(sensor, session, channel_copy)
