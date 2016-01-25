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

# Inspiration and code snippets used from:
# http://www.codeproject.com/Tips/612847/Generate-a-quick-and-easy-custom-pcap-file-using-P

from honssh.protocols import baseProtocol 
from honssh import log
import binascii
import socket
import datetime
import os
import socket

class PortForward(baseProtocol.BaseProtocol):  
    
    pcapGlobalHeader = 'D4C3B2A1020004000000000000000000FFFF000001000000'
   
    def __init__(self, out, uuid, chanName, ssh, connDetails, parent, otherParent):
        self.name = chanName
        self.out = out
        self.ssh = ssh
        self.uuid = uuid
        self.out.registerSelf(self)  
        self.baseParent = parent
        self.otherBaseParent = otherParent
        
        self.connDetails = connDetails
        self.connDetails['dstIP'] = socket.gethostbyname_ex(self.connDetails['dstIP'])[2][0]
        self.connDetails['srcIP'] = socket.gethostbyname_ex(self.connDetails['srcIP'])[2][0]
            
        self.out.portForwardLog(self.name, self.connDetails)
            
        self.pcapFile = self.out.logLocation + datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f") + '_' + self.name[1:-1] + '.pcap'
        self.writeToPCAP(self.pcapGlobalHeader)  
        self.doAcksNow = False

        self.serverSeq = 1          
        self.clientSeq = 0
        self.doTCPHandshake() 
    
    def parsePacket(self, parent, payload): 
        self.parent = parent
        self.payload = payload
        thePacket = self.createPacket()
        self.writeToPCAP(thePacket)
        if self.doAcksNow:
            self.doAck()
        self.tcpFlags = '018'  
        
    def channelClosed(self):
        self.doAcksNow = False
        self.doFin()
        
    def createPacket(self):
        self.payload = self.payload.encode('hex')
        tcpHeader = self.createTCPHeader()
        ipHeader = self.createIPHeader(tcpHeader)
        macHeader = self.createMACHeader()
        pcapHeader = self.createPCAPHeader(macHeader, ipHeader, tcpHeader)
        return pcapHeader + macHeader + ipHeader + tcpHeader + self.payload
    
    def doTCPHandshake(self):
        self.tcpFlags = '002'
        self.serverSeq = self.serverSeq + 1
        self.clientSeq = self.clientSeq + 1
        self.tcpFlags = '012'
        self.clientSeq = self.clientSeq + 1
        self.tcpFlags = '010'
        self.doAcksNow = True
        
    def doAck(self):
        self.payload = ''
        self.tcpFlags = '010'
        if self.parent == '[SERVER]':
            self.parent = '[CLIENT]'
        elif self.parent == '[CLIENT]':
            self.parent = '[SERVER]'
        thePacket = self.createPacket()
        self.writeToPCAP(thePacket)
        
    def doFin(self):
        self.tcpFlags = '011'
        self.clientSeq = self.clientSeq + 1
        self.tcpFlags = '011'
        self.serverSeq = self.serverSeq + 1
        self.tcpFlags = '010'
    
    def createTCPHeader(self):
        tcpHeader = 'AAAABBBBCCCCCCCCDDDDDDDD5EEE1000FFFF0000'
        
        if self.parent == self.baseParent:
            srcPort = self.connDetails['srcPort']
            dstPort = self.connDetails['dstPort']
            theSeq = self.serverSeq
            theAck = self.clientSeq
        else:
            srcPort = self.connDetails['dstPort']
            dstPort = self.connDetails['srcPort'] 
            theSeq = self.clientSeq
            theAck = self.serverSeq 
            
        tcpHeader = tcpHeader.replace('AAAA', '%04x' % int(srcPort))
        tcpHeader = tcpHeader.replace('BBBB', '%04x' % int(dstPort))  
              
        tcpHeader = tcpHeader.replace('CCCCCCCC', '%08x' % theSeq)        
        tcpHeader = tcpHeader.replace('DDDDDDDD', '%08x' % theAck)   
        
        if self.parent == '[SERVER]':
            self.serverSeq = self.serverSeq + (len(self.payload) / 2)
        elif self.parent == '[CLIENT]':
            self.clientSeq = self.clientSeq + (len(self.payload) / 2)
        
        tcpHeader = tcpHeader.replace('EEE', self.tcpFlags)
        tcpHeader = tcpHeader.replace('FFFF', '%04x' % 0)
        
        return tcpHeader        
    
    def createIPHeader(self, tcpHeader):
        ipHeader = '4500AAAA0000400040BBCCCCDDDDDDDDEEEEEEEE' # A = LENGTH, B = PROTOCOL, C = CHECKSUM, D = SRC IP, E = DST IP
        
        if self.parent == '[SERVER]':
            srcIP = self.connDetails['srcIP']
            dstIP = self.connDetails['dstIP']
        elif self.parent == '[CLIENT]':
            srcIP = self.connDetails['dstIP']
            dstIP = self.connDetails['srcIP']        

        ipHeader = ipHeader.replace('EEEEEEEE', binascii.hexlify(socket.inet_aton(dstIP)))
        ipHeader = ipHeader.replace('DDDDDDDD', binascii.hexlify(socket.inet_aton(srcIP)))
        ipHeader = ipHeader.replace('BB', '06')
        ipLength = (len(ipHeader) + len(tcpHeader) + len(self.payload)) / 2
        ipHeader = ipHeader.replace('AAAA', '%04x' % int(ipLength))
        ipHeader = ipHeader.replace('CCCC', '0000')
        return ipHeader
    
    def createIPChecksum(self, iph):
        words = self.splitN(iph,4)
    
        csum = 0;
        for word in words:
            csum += int(word, base=16)
    
        csum += (csum >> 16)
        csum = csum & 0xFFFF ^ 0xFFFF
    
        return csum

    def createMACHeader(self):
        macHeader = 'AAAAAAAAAAAABBBBBBBBBBBB0800' # A = SRC MAC, B = DST MAC
        
        if self.parent == '[SERVER]':
            srcMac = '0A1122334455'
            dstMac = '0A5544332211'
        elif self.parent == '[CLIENT]':
            srcMac = '0A5544332211'
            dstMac = '0A1122334455'
            
        macHeader = macHeader.replace('AAAAAAAAAAAA', srcMac)
        macHeader = macHeader.replace('BBBBBBBBBBBB', dstMac)
        return macHeader

    def createPCAPHeader(self, macHeader, ipHeader, tcpHeader):
        pcapPacketHeader = 'AA779F4790A20400AAAAAAAABBBBBBBB' # A/B = FRAME SIZE (Little Endian)

        pcapLength = (len(macHeader) + len(ipHeader) + len(tcpHeader) + len(self.payload)) / 2
        pcapLength = '%08x' % pcapLength
        reverseLength = pcapLength[6:] + pcapLength[4:6] + pcapLength[2:4] + pcapLength[:2]
        
        pcapPacketHeader = pcapPacketHeader.replace('AAAAAAAA', reverseLength)
        pcapPacketHeader = pcapPacketHeader.replace('BBBBBBBB', reverseLength)
        return pcapPacketHeader
        
    def writeToPCAP(self, theBytes):
        setPermissions = False
    
        if(os.path.isfile(self.pcapFile) == False):
            setPermissions = True

        bytes = binascii.a2b_hex(theBytes)
        f = open(self.pcapFile, 'ab')
        f.write(bytes)
        f.close()

        if(setPermissions):
            os.chmod(self.pcapFile, 0644)        
        

    def splitN(self, str1, n):
        return [str1[start:start+n] for start in range(0, len(str1), n)]
