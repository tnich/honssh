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

from honssh.protocols import baseProtocol, sftp, term, execTerm, portForward
from honssh import log
from honssh.config import Config
import struct
import uuid


class SSH(baseProtocol.BaseProtocol):
    packetLayout = {
        1: 'SSH_MSG_DISCONNECT',  # ['uint32', 'reason_code'], ['string', 'reason'], ['string', 'language_tag']
        2: 'SSH_MSG_IGNORE',  # ['string', 'data']
        3: 'SSH_MSG_UNIMPLEMENTED',  # ['uint32', 'seq_no']
        4: 'SSH_MSG_DEBUG',  # ['boolean', 'always_display']
        5: 'SSH_MSG_SERVICE_REQUEST',  # ['string', 'service_name']
        6: 'SSH_MSG_SERVICE_ACCEPT',  # ['string', 'service_name']
        20: 'SSH_MSG_KEXINIT',  # ['string', 'service_name']
        21: 'SSH_MSG_NEWKEYS',  #
        50: 'SSH_MSG_USERAUTH_REQUEST', # ['string', 'username'], ['string', 'service_name'], ['string', 'method_name']
        51: 'SSH_MSG_USERAUTH_FAILURE',  # ['name-list', 'authentications'], ['boolean', 'partial_success']
        52: 'SSH_MSG_USERAUTH_SUCCESS',  #
        53: 'SSH_MSG_USERAUTH_BANNER',  # ['string', 'message'], ['string', 'language_tag']
        60: 'SSH_MSG_USERAUTH_INFO_REQUEST',  # ['string', 'name'], ['string', 'instruction'], ['string', 'language_tag'], ['uint32', 'num-prompts'], ['string', 'prompt[x]'], ['boolean', 'echo[x]']
        61: 'SSH_MSG_USERAUTH_INFO_RESPONSE',  # ['uint32', 'num-responses'], ['string', 'response[x]']
        80: 'SSH_MSG_GLOBAL_REQUEST',  # ['string', 'request_name'], ['boolean', 'want_reply']  #tcpip-forward
        81: 'SSH_MSG_REQUEST_SUCCESS',  #
        82: 'SSH_MSG_REQUEST_FAILURE',  #
        90: 'SSH_MSG_CHANNEL_OPEN', # ['string', 'channel_type'], ['uint32', 'sender_channel'], ['uint32', 'initial_window_size'], ['uint32', 'maximum_packet_size'],
        91: 'SSH_MSG_CHANNEL_OPEN_CONFIRMATION', # ['uint32', 'recipient_channel'], ['uint32', 'sender_channel'], ['uint32', 'initial_window_size'], ['uint32', 'maximum_packet_size'],
        92: 'SSH_MSG_CHANNEL_OPEN_FAILURE', # ['uint32', 'recipient_channel'], ['uint32', 'reason_code'], ['string', 'reason'], ['string', 'language_tag']
        93: 'SSH_MSG_CHANNEL_WINDOW_ADJUST',  # ['uint32', 'recipient_channel'], ['uint32', 'additional_bytes']
        94: 'SSH_MSG_CHANNEL_DATA',  # ['uint32', 'recipient_channel'], ['string', 'data']
        95: 'SSH_MSG_CHANNEL_EXTENDED_DATA', # ['uint32', 'recipient_channel'], ['uint32', 'data_type_code'], ['string', 'data']
        96: 'SSH_MSG_CHANNEL_EOF',  # ['uint32', 'recipient_channel']
        97: 'SSH_MSG_CHANNEL_CLOSE',  # ['uint32', 'recipient_channel']
        98: 'SSH_MSG_CHANNEL_REQUEST', # ['uint32', 'recipient_channel'], ['string', 'request_type'], ['boolean', 'want_reply']
        99: 'SSH_MSG_CHANNEL_SUCCESS',  #
        100: 'SSH_MSG_CHANNEL_FAILURE'  #
    }

    def __init__(self, server, out):
        super(SSH, self).__init__()

        self.channels = []
        self.username = ''
        self.password = ''
        self.auth_type = ''

        self.cfg = Config.getInstance()

        self.sendOn = False
        self.expect_password = 0
        self.out = out
        self.server = server
        self.channels = []
        self.client = None

    def set_client(self, client):
        self.client = client

    def parse_packet(self, parent, message_num, payload):
        self.data = payload
        self.packetSize = len(payload)
        self.sendOn = True

        try:
            packet = self.packetLayout[message_num]
        except:
            packet = 'UNKNOWN_%s' % message_num

        if not self.server.post_auth_started:
            if parent == '[SERVER]':
                direction = 'CLIENT -> SERVER'
            else:
                direction = 'SERVER -> CLIENT'
        else:
            if parent == '[SERVER]':
                direction = 'HONSSH -> SERVER'
            else:
                direction = 'SERVER -> HONSSH'

        self.out.packet_logged(direction, packet, payload)

        if self.cfg.has_option('devmode', 'enabled') and self.cfg.getboolean(['devmode', 'enabled']):
                log.msg(log.LBLUE, '[SSH]', direction + ' - ' + packet.ljust(37) + ' - ' + repr(payload))

        # - UserAuth
        if packet == 'SSH_MSG_USERAUTH_REQUEST':
            self.username = self.extract_string()
            service = self.extract_string()
            self.auth_type = self.extract_string()

            if self.auth_type == 'password':
                self.extract_bool()
                self.password = self.extract_string()
                self.start_post_auth()

            elif self.auth_type == 'publickey':
                if self.cfg.getboolean(['hp-restrict', 'disable_publicKey']):
                    self.sendOn = False
                    self.server.sendPacket(51, self.string_to_hex('password') + chr(0))

        elif packet == 'SSH_MSG_USERAUTH_FAILURE':
            auth_list = self.extract_string()

            if 'publickey' in auth_list:
                if self.cfg.getboolean(['hp-restrict', 'disable_publicKey']):
                    log.msg(log.LPURPLE, '[SSH]', 'Detected Public Key Auth - Disabling!')
                    payload = self.string_to_hex('password') + chr(0)

            if not self.server.post_auth_started:
                if self.username != '' and self.password != '':
                    self.out.login_failed(self.username, self.password)
                    self.server.login_failed(self.username, self.password)

        elif packet == 'SSH_MSG_USERAUTH_SUCCESS':
            if len(self.username) > 0 and len(self.password) > 0:
                self.out.login_successful(self.username, self.password, self.server.spoofed)
                self.server.login_successful(self.username, self.password)

        elif packet == 'SSH_MSG_USERAUTH_INFO_REQUEST':
            self.auth_type = 'keyboard-interactive'
            self.extract_string()
            self.extract_string()
            self.extract_string()
            num_prompts = self.extract_int(4)
            for i in range(0, num_prompts):
                request = self.extract_string()
                self.extract_bool()

                if 'password' in request.lower():
                    self.expect_password = i

        elif packet == 'SSH_MSG_USERAUTH_INFO_RESPONSE':
            num_responses = self.extract_int(4)
            for i in range(0, num_responses):
                response = self.extract_string()
                if i == self.expect_password:
                    self.password = response
                    self.start_post_auth()

        # - End UserAuth
        # - Channels
        elif packet == 'SSH_MSG_CHANNEL_OPEN':
            channel_type = self.extract_string()
            id = self.extract_int(4)

            if channel_type == 'session':
                self.create_channel(parent, id, channel_type)
            elif channel_type == 'x11':
                if self.cfg.getboolean(['hp-restrict', 'disable_x11']):
                    log.msg(log.LPURPLE, '[SSH]', 'Detected X11 Channel - Disabling!')
                    self.sendOn = False
                    self.send_back(parent, 92, self.int_to_hex(id))
                else:
                    # LOG X11 Channel opened - not logging
                    the_uuid = uuid.uuid4().hex
                    the_name = '[X11-' + str(id) + ']'
                    self.create_channel(parent, id, channel_type,
                                        session=baseProtocol.BaseProtocol(uuid=the_uuid, name=the_name, ssh=self))
                    channel = self.get_channel(id, '[CLIENT]')
                    channel['name'] = the_name
                    self.out.channel_opened(the_uuid, channel['name'])
            elif channel_type == 'direct-tcpip' or channel_type == 'forwarded-tcpip':
                if self.cfg.getboolean(['hp-restrict', 'disable_port_forwarding']):
                    log.msg(log.LPURPLE, '[SSH]', 'Detected Port Forwarding Channel - Disabling!')
                    self.sendOn = False
                    self.send_back(parent, 92, self.int_to_hex(id) + self.int_to_hex(1) + self.string_to_hex(
                        'open failed') + self.int_to_hex(0))
                else:
                    # LOG PORT FORWARDING Channel opened
                    self.extract_int(4)
                    self.extract_int(4)

                    conn_details = {'dstIP': self.extract_string(), 'dstPort': self.extract_int(4),
                                    'srcIP': self.out.end_ip, 'srcPort': self.extract_int(4)}
                    the_uuid = uuid.uuid4().hex
                    self.create_channel(parent, id, channel_type)

                    if parent == '[SERVER]':
                        other_parent = '[CLIENT]'
                        the_name = '[LPRTF' + str(id) + ']'
                    else:
                        other_parent = '[SERVER]'
                        the_name = '[RPRTF' + str(id) + ']'

                    channel = self.get_channel(id, other_parent)
                    channel['name'] = the_name
                    self.out.channel_opened(the_uuid, channel['name'])
                    channel['session'] = portForward.PortForward(self.out, the_uuid, channel['name'],
                                                                 self, conn_details, parent, other_parent)
            else:
                # UNKNOWN CHANNEL TYPE
                if channel_type not in ['exit-status']:
                    log.msg(log.LRED, '[SSH]', 'Unknown Channel Type Detected - ' + channel_type)

        elif packet == 'SSH_MSG_CHANNEL_OPEN_CONFIRMATION':
            channel = self.get_channel(self.extract_int(4), parent)
            # SENDER
            sender_id = self.extract_int(4)

            if parent == '[SERVER]':
                channel['serverID'] = sender_id
            elif parent == '[CLIENT]':
                channel['clientID'] = sender_id
                # CHANNEL OPENED

        elif packet == 'SSH_MSG_CHANNEL_OPEN_FAILURE':
            channel = self.get_channel(self.extract_int(4), parent)
            self.out.channel_closed(channel['session'])
            self.channels.remove(channel)
            # CHANNEL FAILED TO OPEN

        elif packet == 'SSH_MSG_CHANNEL_REQUEST':
            channel = self.get_channel(self.extract_int(4), parent)
            channel_type = self.extract_string()
            the_uuid = uuid.uuid4().hex

            if channel_type == 'shell':
                channel['name'] = '[TERM' + str(channel['serverID']) + ']'
                self.out.channel_opened(the_uuid, channel['name'])
                channel['session'] = term.Term(self.out, the_uuid, channel['name'], self, channel['clientID'])
            elif channel_type == 'exec':
                if self.cfg.get(['hp-restrict', 'disable_exec']):
                    log.msg(log.LPURPLE, '[SSH]', 'Detected EXEC Channel Request - Disabling!')
                    self.sendOn = False
                    self.send_back(parent, 100, self.int_to_hex(channel['serverID']))
                    blocked = True
                else:
                    blocked = False

                channel['name'] = '[EXEC' + str(channel['serverID']) + ']'
                self.extract_bool()
                command = self.extract_string()
                self.out.channel_opened(the_uuid, channel['name'])
                channel['session'] = execTerm.ExecTerm(self.out, the_uuid, channel['name'], command, self, blocked)

                if blocked:
                    channel['session'].channel_closed()
                    self.out.channel_closed(channel['session'])
                    self.channels.remove(channel)
            elif channel_type == 'subsystem':
                self.extract_bool()
                subsystem = self.extract_string()

                if subsystem == 'sftp':
                    if self.cfg.getboolean(['hp-restrict', 'disable_sftp']):
                        log.msg(log.LPURPLE, '[SSH]', 'Detected SFTP Channel Request - Disabling!')
                        self.sendOn = False
                        self.send_back(parent, 100, self.int_to_hex(channel['serverID']))
                    else:
                        channel['name'] = '[SFTP' + str(channel['serverID']) + ']'
                        self.out.channel_opened(the_uuid, channel['name'])
                        channel['session'] = sftp.SFTP(self.out, the_uuid, channel['name'], self)
                else:
                    # UNKNOWN SUBSYSTEM
                    log.msg(log.LRED, '[SSH]', 'Unknown Subsystem Type Detected - ' + subsystem)
            elif channel_type == 'x11-req':
                if self.cfg.getboolean(['hp-restrict', 'disable_x11']):
                    self.sendOn = False
                    self.send_back(parent, 82, '')
            else:
                # UNKNOWN CHANNEL REQUEST TYPE
                if channel_type not in ['window-change', 'env', 'pty-req', 'exit-status', 'exit-signal']:
                    log.msg(log.LRED, '[SSH]', 'Unknown Channel Request Type Detected - ' + channel_type)

        elif packet == 'SSH_MSG_CHANNEL_FAILURE':
            pass

        elif packet == 'SSH_MSG_CHANNEL_CLOSE':
            channel = self.get_channel(self.extract_int(4), parent)
            # Is this needed?!
            channel[parent] = True

            if '[SERVER]' in channel and '[CLIENT]' in channel:
                # CHANNEL CLOSED
                if channel['session'] is not None:
                    channel['session'].channel_closed()
                    self.out.channel_closed(channel['session'])

                self.channels.remove(channel)
        # - END Channels
        # - ChannelData
        elif packet == 'SSH_MSG_CHANNEL_DATA':
            channel = self.get_channel(self.extract_int(4), parent)
            channel['session'].parse_packet(parent, self.extract_string())

        elif packet == 'SSH_MSG_CHANNEL_EXTENDED_DATA':
            channel = self.get_channel(self.extract_int(4), parent)
            self.extract_int(4)
            channel['session'].parse_packet(parent, self.extract_string())
        # - END ChannelData

        elif packet == 'SSH_MSG_GLOBAL_REQUEST':
            channel_type = self.extract_string()
            if channel_type == 'tcpip-forward':
                if self.cfg.getboolean(['hp-restrict', 'disable_port_forwarding']):
                    self.sendOn = False
                    self.send_back(parent, 82, '')

        if self.server.post_auth_started:
            if parent == '[CLIENT]':
                self.server.post_auth.send_next()
                self.sendOn = False

        if self.sendOn:
            if parent == '[SERVER]':
                self.client.sendPacket(message_num, payload)
            else:
                self.server.sendPacket(message_num, payload)

    def send_back(self, parent, message_num, payload):
        packet = self.packetLayout[message_num]

        if parent == '[SERVER]':
            direction = 'HONSSH -> CLIENT'
        else:
            direction = 'HONSSH -> SERVER'

        self.out.packet_logged(direction, packet, payload)

        if self.cfg.has_option('devmode', 'enabled') and self.cfg.getboolean(['devmode', 'enabled']):
                log.msg(log.LBLUE, '[SSH]', direction + ' - ' + packet.ljust(37) + ' - ' + repr(payload))

        if parent == '[SERVER]':
            self.server.sendPacket(message_num, payload)
        elif parent == '[CLIENT]':
            self.client.sendPacket(message_num, payload)

    def create_channel(self, parent, id, channel_type, session=None):
        if parent == '[SERVER]':
            self.channels.append({'serverID': id, 'type': channel_type, 'session': session})
        elif parent == '[CLIENT]':
            self.channels.append({'clientID': id, 'type': channel_type, 'session': session})

    def get_channel(self, channel_num, parent):
        the_channel = None
        for channel in self.channels:
            if parent == '[CLIENT]':
                search = 'serverID'
            else:
                search = 'clientID'

            if channel[search] == channel_num:
                the_channel = channel
                break
        return the_channel
        
    def start_post_auth(self):
        if self.password != "":
            if not self.server.post_auth_started:
                self.server.start_post_auth(self.username, self.password, self.auth_type)
                self.sendOn = False

    def inject_key(self, server_id, message):
        payload = self.int_to_hex(server_id) + self.string_to_hex(message)
        self.inject(94, payload)

    def inject_disconnect(self):
        self.server.loseConnection()

    def inject(self, packet_num, payload):
        direction = 'INTERACT -> SERVER'
        packet = self.packetLayout[packet_num]

        self.out.packet_logged(direction, packet, payload)

        if self.cfg.has_option('devmode', 'enabled') and self.cfg.getboolean(['devmode', 'enabled']):
                log.msg(log.LBLUE, '[SSH]', direction + ' - ' + packet.ljust(37) + ' - ' + repr(payload))

        self.client.sendPacket(packet_num, payload)

    def string_to_hex(self, message):
        b = message.encode('utf-8')
        size = struct.pack('>L', len(b))
        return size + b

    def int_to_hex(self, value):
        return struct.pack('>L', value)
