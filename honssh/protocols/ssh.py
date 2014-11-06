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

from honssh.protocols import baseProtocol, sftp, term, execTerm
from twisted.python import log
from kippo.core.config import config
import struct, uuid, random, os, ConfigParser, re

class SSH(baseProtocol.BaseProtocol):
    
    channels = []
    username = ''
    password = ''

    cfg = config()

    packetLayout = {
                1 : 'SSH_MSG_DISCONNECT',                   #['uint32', 'reason_code'], ['string', 'reason'], ['string', 'language_tag']
                2 : 'SSH_MSG_IGNORE',                       #['string', 'data']
                3 : 'SSH_MSG_UNIMPLEMENTED',                #['uint32', 'seq_no']
                4 : 'SSH_MSG_DEBUG',                        #['boolean', 'always_display']
                5 : 'SSH_MSG_SERVICE_REQUEST',              #['string', 'service_name']
                6 : 'SSH_MSG_SERVICE_ACCEPT',               #['string', 'service_name']
                20 : 'SSH_MSG_KEXINIT',                     #['string', 'service_name']
                21 : 'SSH_MSG_NEWKEYS',                     #
                50 : 'SSH_MSG_USERAUTH_REQUEST',            #['string', 'username'], ['string', 'service_name'], ['string', 'method_name']
                51 : 'SSH_MSG_USERAUTH_FAILURE',            #['name-list', 'authentications'], ['boolean', 'partial_success']
                52 : 'SSH_MSG_USERAUTH_SUCCESS',            #
                53 : 'SSH_MSG_USERAUTH_BANNER',             #['string', 'message'], ['string', 'language_tag']
                80 : 'SSH_MSG_GLOBAL_REQUEST',              #['string', 'request_name'], ['boolean', 'want_reply']  #tcpip-forward
                81 : 'SSH_MSG_REQUEST_SUCCESS',             #
                82 : 'SSH_MSG_REQUEST_FAILURE',             #
                90 : 'SSH_MSG_CHANNEL_OPEN',                #['string', 'channel_type'], ['uint32', 'sender_channel'], ['uint32', 'initial_window_size'], ['uint32', 'maximum_packet_size'],
                91 : 'SSH_MSG_CHANNEL_OPEN_CONFIRMATION',   #['uint32', 'recipient_channel'], ['uint32', 'sender_channel'], ['uint32', 'initial_window_size'], ['uint32', 'maximum_packet_size'],
                92 : 'SSH_MSG_CHANNEL_OPEN_FAILURE',        #['uint32', 'recipient_channel'], ['uint32', 'reason_code'], ['string', 'reason'], ['string', 'language_tag']
                93 : 'SSH_MSG_CHANNEL_WINDOW_ADJUST',       #['uint32', 'recipient_channel'], ['uint32', 'additional_bytes']
                94 : 'SSH_MSG_CHANNEL_DATA',                #['uint32', 'recipient_channel'], ['string', 'data']
                95 : 'SSH_MSG_CHANNEL_EXTENDED_DATA',       #['uint32', 'recipient_channel'], ['uint32', 'data_type_code'], ['string', 'data']
                96 : 'SSH_MSG_CHANNEL_EOF',                 #['uint32', 'recipient_channel']
                97 : 'SSH_MSG_CHANNEL_CLOSE',               #['uint32', 'recipient_channel']
                98 : 'SSH_MSG_CHANNEL_REQUEST',             #['uint32', 'recipient_channel'], ['string', 'request_type'], ['boolean', 'want_reply']
                99 : 'SSH_MSG_CHANNEL_SUCCESS',             #
                100 : 'SSH_MSG_CHANNEL_FAILURE'             #
                }
                
    def __init__(self, server, out):
        self.out = out
        self.server = server
        self.channels = []
        
    def setClient(self, client):
        self.client = client            
                
    def parsePacket(self, parent, messageNum, payload):
        self.data = payload
        self.packetSize = len(payload)
        self.sendOn = True
        
        packet = self.packetLayout[messageNum]
            
        if self.cfg.get('packets', 'enabled') == 'true':
            if parent == '[SERVER]':
                direction = 'CLIENT -> SERVER'
            else:
                direction = 'SERVER -> CLIENT'
            self.out.advancedLog(direction + ' - ' + packet.ljust(33) + ' - ' + repr(payload))
        
        # - UserAuth            
        if packet == 'SSH_MSG_USERAUTH_REQUEST':
            self.username = self.extractString()
            service = self.extractString()
            authType = self.extractString()
            if authType == 'password':
                self.extractBool()
                psize = self.packetSize
                self.password = self.extractString()
                if self.password != "":
                    if self.cfg.get('spoof', 'enabled') == 'true':
                        user = self.getUsers(self.username)
                        rand = 0
                        if user != None:
                            if user[2] == 'fixed':
                                passwords = re.sub(r'\s', '', user[3]).split(',')
                                if self.password in passwords:
                                    rand = 1
                            elif user[2] == 'random':
                                randomFactor = (100 / int(user[3])) + 1
                                rand = random.randrange(1, randomFactor)
                    
                            found = False
                            logfile = self.cfg.get('folders', 'log_path') + "/spoof.log"
                            if os.path.isfile(logfile):
                                f = file(logfile, 'r')
                                creds = f.read().splitlines()
                                f.close()
                                for cred in creds:
                                    cred = cred.strip().split(' - ')
                                    if cred[0] == self.username and cred[1] == self.password:
                                        rand = 1
                                        self.out.writePossibleLink(cred[2:])
                                        break

                        if rand == 1:
                            payload = payload[:0-psize] + self.stringToHex(user[1])
                            self.out.addConnectionString("[SSH  ] Spoofing Login - Changing %s to %s" % (self.password, user[1]))
                            self.out.writeSpoofPass(self.username, self.password) 

            elif authType == 'publickey':
                if self.cfg.get('hp-restrict', 'disable_publicKey') == 'true':
                    self.sendOn = False
                    self.server.sendPacket(51, self.stringToHex('password') + chr(0))

        elif packet == 'SSH_MSG_USERAUTH_FAILURE':
            authList = self.extractString()
            if 'publickey' in authList:
                if self.cfg.get('hp-restrict', 'disable_publicKey') == 'true':
                    log.msg("[SSH] - Detected Public Key Auth - Disabling!")
                    payload = self.stringToHex('password') + chr(0)
            if self.username != ''  and self.password != '':
                self.out.loginFailed(self.username, self.password)
                    
        elif packet == 'SSH_MSG_USERAUTH_SUCCESS':
            if self.username != ''  and self.password != '':
                self.out.loginSuccessful(self.username, self.password)
                
        # - End UserAuth
        # - Channels
        elif packet == 'SSH_MSG_CHANNEL_OPEN':
            type = self.extractString()
            id = self.extractInt(4)
            if type == 'session':
                self.createChannel(parent, id, type)
            elif type == 'x11':
                if self.cfg.get('hp-restrict', 'disable_x11') == 'true':
                    log.msg("[SSH] - Detected X11 Channel - Disabling!")
                    self.sendOn = False
                    self.sendBack(parent, 92, self.intToHex(id))
                else:
                    ##LOG X11 Channel opened - not logging
                    self.createChannel(parent, id, type, session=baseProtocol.BaseProtocol())
            elif type == 'direct-tcpip':
                if self.cfg.get('hp-restrict', 'disable_port_forwarding') == 'true':
                    log.msg("[SSH] - Detected Port Forwarding Channel - Disabling!")
                    self.sendOn = False
                    self.sendBack(parent, 92, self.intToHex(id) + self.intToHex(1) + self.stringToHex('open failed') + self.intToHex(0))
                else:
                    ##LOG PORT FORWARDING Channel opened - not logging
                    self.createChannel(parent, id, type, session=baseProtocol.BaseProtocol())
            else:
                ##UNKNOWN CHANNEL TYPE
                if type not in ['exit-status']:
                    log.msg("[SSH] - Unknown Channel Type Detected - " + type)              

        elif packet == 'SSH_MSG_CHANNEL_OPEN_CONFIRMATION':
            channel = self.getChannel(self.extractInt(4), parent)
            senderID = self.extractInt(4) #SENDER
            
            if parent == '[SERVER]':
                channel['serverID'] = senderID
            elif parent == '[CLIENT]':
                channel['clientID'] = senderID
            ##CHANNEL OPENED
        
        elif packet == 'SSH_MSG_CHANNEL_OPEN_FAILURE':
            channel = self.getChannel(self.extractInt(4), parent)
            self.channels.remove(channel)
            ##CHANNEL FAILED TO OPEN
            
        elif packet == 'SSH_MSG_CHANNEL_REQUEST':
            channel = self.getChannel(self.extractInt(4), parent)
            type = self.extractString()
            theUUID = uuid.uuid4().hex
            if type == 'pty-req':
                channel['name'] = '[TERM' + str(channel['serverID']) + ']'
                self.out.channelOpened(theUUID, channel['name'])
                channel['session'] = term.Term(self.out, theUUID, channel['name'])
            elif type == 'exec':
                if self.cfg.get('hp-restrict','disable_exec') == 'true':
                    log.msg("[SSH] - Detected EXEC Channel Request - Disabling!")
                    self.sendOn = False
                    self.sendBack(parent, 100, self.intToHex(channel['serverID']))
                else:
                    channel['name'] = '[EXEC' + str(channel['serverID']) + ']'
                    self.extractBool()
                    command = self.extractString()
                    self.out.channelOpened(theUUID, channel['name'])
                    channel['session'] = execTerm.ExecTerm(self.out, theUUID, channel['name'], command)
            elif type == 'subsystem':
                self.extractBool()
                subsystem = self.extractString()
                if subsystem == 'sftp':
                    if self.cfg.get('hp-restrict','disable_sftp') == 'true':
                        log.msg("[SSH] - Detected SFTP Channel Request - Disabling!")
                        self.sendOn = False
                        self.sendBack(parent, 100, self.intToHex(channel['serverID']))
                    else:
                        channel['name'] = '[SFTP' + str(channel['serverID']) + ']'
                        self.out.channelOpened(theUUID, channel['name'])
                        channel['session'] = sftp.SFTP(self.out, theUUID, channel['name'])
                else:
                    ##UNKNOWN SUBSYSTEM
                    log.msg("[SSH] - Unknown Subsystem Type Detected - " + subsystem) 
            elif type == 'x11-req':
                if self.cfg.get('hp-restrict', 'disable_x11') == 'true':
                    self.sendOn = False
                    self.sendBack(parent, 82, '')
            else:
                ##UNKNOWN CHANNEL REQUEST TYPE
                if type not in ['window-change', 'env', 'shell', 'exit-status']:
                    log.msg("[SSH] - Unknown Channel Request Type Detected - " + type) 
                
        elif packet == 'SSH_MSG_CHANNEL_FAILURE':
            pass
                
        elif packet == 'SSH_MSG_CHANNEL_CLOSE':
            channel = self.getChannel(self.extractInt(4), parent)
            channel[parent] = True
            if '[SERVER]' in channel and '[CLIENT]' in channel:
                ##CHANNEL CLOSED
                if channel['session'] != None:
                    channel['session'].channelClosed()
                self.out.channelClosed(channel['session'])
                self.channels.remove(channel)
        # - END Channels
        # - ChannelData
        elif packet == 'SSH_MSG_CHANNEL_DATA':
            channel = self.getChannel(self.extractInt(4), parent)
            channel['session'].parsePacket(parent, self.extractString())
                        
        elif packet == 'SSH_MSG_CHANNEL_EXTENDED_DATA':
            channel = self.getChannel(self.extractInt(4), parent)
            self.extractInt(4)
            channel['session'].parsePacket(parent, self.extractString())
        # - END ChannelData
        
        elif packet == 'SSH_MSG_GLOBAL_REQUEST':
            type = self.extractString()
            if type == 'tcpip-forward':
                if self.cfg.get('hp-restrict', 'disable_port_forwarding') == 'true':
                    self.sendOn = False
                    self.sendBack(parent, 82, '')

        if self.sendOn:    
            if parent == '[SERVER]':
                self.client.sendPacket(messageNum, payload)
            else:
                self.server.sendPacket(messageNum, payload)
    
    def sendBack(self, parent, messageNum, payload):
        if self.cfg.get('packets', 'enabled') == 'true':
            packet = self.packetLayout[messageNum]
            if parent == '[SERVER]':
                direction = 'HONSSH -> CLIENT'
            else:
                direction = 'HONSSH -> SERVER'
            self.out.advancedLog(direction + ' - ' + packet.ljust(33) + ' - ' + repr(payload))
            
            
        if parent == '[SERVER]':
            self.server.sendPacket(messageNum, payload)
        elif parent == '[CLIENT]':
            self.client.sendPacket(messageNum, payload)
    
    def createChannel(self, parent, id, type, session=None):
        if parent == '[SERVER]':
            self.channels.append({'serverID':id, 'type': type, 'session':session})
        elif parent == '[CLIENT]':
            self.channels.append({'clientID':id, 'type': type, 'session':session})
    
    def getChannel(self, channelNum, parent):
        theChannel = None
        for channel in self.channels:
            if parent == '[CLIENT]':
                search = 'serverID'
            else:
                search = 'clientID'
    
            if channel[search] == channelNum:
                theChannel = channel
                break
        return channel
    
    def getUsers(self, username):
        usersCfg = ConfigParser.ConfigParser()
        if os.path.exists(self.cfg.get('spoof','users_conf')):
            usersCfg.read(self.cfg.get('spoof','users_conf'))
            users = usersCfg.sections()
            for user in users:
                if user == username:
                    if usersCfg.has_option(user, 'fake_passwords'):
                        return [user, usersCfg.get(user, 'real_password'), 'fixed', usersCfg.get(user, 'fake_passwords')]
                    if usersCfg.has_option(user, 'random_chance'):
                        return [user, usersCfg.get(user, 'real_password'), 'random', usersCfg.get(user, 'random_chance')]
        else:
            log.msg("ERROR: users_conf does not exist")
        
        return None
    
    def stringToHex(self, message):
        b = message.encode('utf-8')
        size = struct.pack('>L',len(b))
        return size + b
    
    def intToHex(self, int):
        return struct.pack('>L', int)