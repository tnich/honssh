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
import struct, uuid

class SSH(baseProtocol.BaseProtocol):
    
    channels = []
    username = ''
    password = ''

    cfg = Config.getInstance()

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
                60 : 'SSH_MSG_USERAUTH_PK_OK',              #['string', 'algorithm'], ['string', 'blob']
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
            
        if self.cfg.has_option('devmode', 'enabled'):   
            if self.cfg.get('devmode', 'enabled') == 'true':
                log.msg(log.LBLUE, '[SSH]', direction + ' - ' + packet.ljust(37) + ' - ' + repr(payload))
        
        # - UserAuth            
        if packet == 'SSH_MSG_USERAUTH_REQUEST':
            self.username = self.extractString()
            service = self.extractString()
            authType = self.extractString()

            if authType == 'password':
                self.extractBool()
                self.password = self.extractString()

                if self.password != "":
                    if not self.server.post_auth_started:
                        self.server.start_post_auth(self.username, self.password)
                        self.sendOn = False
                    
            elif authType == 'publickey':
                if self.cfg.get('hp-restrict', 'disable_publicKey') == 'true':
                    self.sendOn = False
                    self.server.sendPacket(51, self.stringToHex('password') + chr(0))

        elif packet == 'SSH_MSG_USERAUTH_FAILURE':
            authList = self.extractString()
            if 'publickey' in authList:
                if self.cfg.get('hp-restrict', 'disable_publicKey') == 'true':
                    log.msg(log.LPURPLE, '[SSH]','Detected Public Key Auth - Disabling!')
                    payload = self.stringToHex('password') + chr(0)
            if not self.server.post_auth_started:
                if self.username != '' and self.password != '':
                    self.out.login_failed(self.username, self.password)
                    self.server.login_failed(self.username, self.password)
                    
        elif packet == 'SSH_MSG_USERAUTH_SUCCESS':
            if self.username != ''  and self.password != '':
                self.out.login_successful(self.username, self.password, self.server.spoofed)
                self.server.login_successful(self.username, self.password)

        # - End UserAuth
        # - Channels
        elif packet == 'SSH_MSG_CHANNEL_OPEN':
            type = self.extractString()
            id = self.extractInt(4)
            if type == 'session':
                self.createChannel(parent, id, type)
            elif type == 'x11':
                if self.cfg.get('hp-restrict', 'disable_x11') == 'true':
                    log.msg(log.LPURPLE, '[SSH]', 'Detected X11 Channel - Disabling!')
                    self.sendOn = False
                    self.sendBack(parent, 92, self.intToHex(id))
                else:
                    ##LOG X11 Channel opened - not logging
                    theUUID = uuid.uuid4().hex
                    theName = '[X11-' + str(id) + ']'
                    self.createChannel(parent, id, type, session=baseProtocol.BaseProtocol(uuid=theUUID, name=theName, ssh=self))
                    channel = self.getChannel(id, '[CLIENT]')
                    channel['name'] = theName
                    self.out.channelOpened(theUUID, channel['name'])
            elif type == 'direct-tcpip' or type == 'forwarded-tcpip':
                if self.cfg.get('hp-restrict', 'disable_port_forwarding') == 'true':
                    log.msg(log.LPURPLE, '[SSH]', 'Detected Port Forwarding Channel - Disabling!')
                    self.sendOn = False
                    self.sendBack(parent, 92, self.intToHex(id) + self.intToHex(1) + self.stringToHex('open failed') + self.intToHex(0))
                else:
                    ##LOG PORT FORWARDING Channel opened
                    self.extractInt(4)
                    self.extractInt(4)
                    
                    connDetails = {'dstIP':self.extractString(), 'dstPort':self.extractInt(4), 'srcIP':self.extractString(), 'srcPort':self.extractInt(4)}
                    connDetails['srcIP'] = self.out.end_ip
                    theUUID = uuid.uuid4().hex
                    self.createChannel(parent, id, type)
                    
                    if parent == '[SERVER]':
                        otherParent = '[CLIENT]'
                        theName = '[LPRTF' + str(id) + ']'
                    else:
                        otherParent = '[SERVER]'
                        theName = '[RPRTF' + str(id) + ']'
                        
                    channel = self.getChannel(id, otherParent)
                    channel['name'] = theName
                    self.out.channelOpened(theUUID, channel['name'])
                    channel['session'] = portForward.PortForward(self.out, theUUID, channel['name'], self, connDetails, parent, otherParent)
            else:
                ##UNKNOWN CHANNEL TYPE
                if type not in ['exit-status']:
                    log.msg(log.LRED, '[SSH]', 'Unknown Channel Type Detected - ' + type)              

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
            self.out.channelClosed(channel['session'])
            self.channels.remove(channel)
            ##CHANNEL FAILED TO OPEN
            
        elif packet == 'SSH_MSG_CHANNEL_REQUEST':
            channel = self.getChannel(self.extractInt(4), parent)
            type = self.extractString()
            theUUID = uuid.uuid4().hex
            if type == 'shell':
                channel['name'] = '[TERM' + str(channel['serverID']) + ']'
                self.out.channelOpened(theUUID, channel['name'])
                channel['session'] = term.Term(self.out, theUUID, channel['name'], self, channel['clientID'])
            elif type == 'exec':
                if self.cfg.get('hp-restrict','disable_exec') == 'true':
                    log.msg(log.LPURPLE, '[SSH]', 'Detected EXEC Channel Request - Disabling!')
                    self.sendOn = False
                    self.sendBack(parent, 100, self.intToHex(channel['serverID']))
                    blocked = True
                else:
                    blocked = False
                channel['name'] = '[EXEC' + str(channel['serverID']) + ']'
                self.extractBool()
                command = self.extractString()
                self.out.channelOpened(theUUID, channel['name'])
                channel['session'] = execTerm.ExecTerm(self.out, theUUID, channel['name'], command, self, blocked)
                if blocked:
                    channel['session'].channelClosed()
                    self.out.channelClosed(channel['session'])
                    self.channels.remove(channel)
            elif type == 'subsystem':
                self.extractBool()
                subsystem = self.extractString()
                if subsystem == 'sftp':
                    if self.cfg.get('hp-restrict','disable_sftp') == 'true':
                        log.msg(log.LPURPLE, '[SSH]', 'Detected SFTP Channel Request - Disabling!')
                        self.sendOn = False
                        self.sendBack(parent, 100, self.intToHex(channel['serverID']))
                    else:
                        channel['name'] = '[SFTP' + str(channel['serverID']) + ']'
                        self.out.channelOpened(theUUID, channel['name'])
                        channel['session'] = sftp.SFTP(self.out, theUUID, channel['name'], self)
                else:
                    ##UNKNOWN SUBSYSTEM
                    log.msg(log.LRED, '[SSH]', 'Unknown Subsystem Type Detected - ' + subsystem) 
            elif type == 'x11-req':
                if self.cfg.get('hp-restrict', 'disable_x11') == 'true':
                    self.sendOn = False
                    self.sendBack(parent, 82, '')
            else:
                ##UNKNOWN CHANNEL REQUEST TYPE
                if type not in ['window-change', 'env', 'pty-req', 'exit-status', 'exit-signal']:
                    log.msg(log.LRED, '[SSH]', 'Unknown Channel Request Type Detected - ' + type) 
                
        elif packet == 'SSH_MSG_CHANNEL_FAILURE':
            pass
                
        elif packet == 'SSH_MSG_CHANNEL_CLOSE':
            channel = self.getChannel(self.extractInt(4), parent)
            channel[parent] = True #Is this needed?!
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
         
        if self.server.post_auth_started:
            if parent == '[CLIENT]':
                self.server.post_auth.send_next()   
                self.sendOn = False
                           
        if self.sendOn: 
            if parent == '[SERVER]':
                self.client.sendPacket(messageNum, payload)
            else:
                self.server.sendPacket(messageNum, payload)
    
    def sendBack(self, parent, messageNum, payload):
        packet = self.packetLayout[messageNum]
        
        if parent == '[SERVER]':
            direction = 'HONSSH -> CLIENT'
        else:
            direction = 'HONSSH -> SERVER'
            
        self.out.packet_logged(direction, packet, payload)

        if self.cfg.has_option('devmode', 'enabled'):   
            if self.cfg.get('devmode', 'enabled') == 'true':
                log.msg(log.LBLUE, '[SSH]', direction + ' - ' + packet.ljust(37) + ' - ' + repr(payload))
            
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
        return theChannel
    
    def injectKey(self, serverID, message):
        payload = self.intToHex(serverID) + self.stringToHex(message)
        self.inject(94, payload)
    
    def injectDisconnect(self):
        self.server.loseConnection()
        
    def inject(self, packetNum, payload):
        direction = 'INTERACT -> SERVER'
        packet = self.packetLayout[packetNum]
        
        self.out.packet_logged(direction, packet, payload)

        if self.cfg.has_option('devmode', 'enabled'):   
            if self.cfg.get('devmode', 'enabled') == 'true':
                log.msg(log.LBLUE, '[SSH]', direction + ' - ' + packet.ljust(37) + ' - ' + repr(payload))   
        
        self.client.sendPacket(packetNum, payload)

    
    def stringToHex(self, message):
        b = message.encode('utf-8')
        size = struct.pack('>L',len(b))
        return size + b
    
    def intToHex(self, int):
        return struct.pack('>L', int)
