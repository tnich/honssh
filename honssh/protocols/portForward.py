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

import binascii
import socket
import datetime
import os


class PortForward(baseProtocol.BaseProtocol):
    pcapGlobalHeader = 'D4C3B2A1020004000000000000000000FFFF000001000000'

    def __init__(self, out, uuid, chan_name, ssh, conn_details, parent, otherParent):
        super(PortForward, self).__init__(uuid, chan_name, ssh)

        self.out = out
        self.out.register_self(self)
        self.baseParent = parent
        self.otherBaseParent = otherParent

        self.connDetails = conn_details
        self.connDetails['dstIP'] = socket.gethostbyname_ex(self.connDetails['dstIP'])[2][0]
        self.connDetails['srcIP'] = socket.gethostbyname_ex(self.connDetails['srcIP'])[2][0]

        self.out.port_forward_log(self.name, self.connDetails)

        self.pcapFile = self.out.logLocation + datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f") + '_' \
                        + self.name[1:-1] + '.pcap'
        self.write_to_pcap(self.pcapGlobalHeader)
        self.doAcksNow = False
        self.tcpFlags = ''

        self.serverSeq = 1
        self.clientSeq = 0
        self.do_tcp_handshake()

        self.parent = None
        self.payload = None

    def parse_packet(self, parent, payload):
        self.parent = parent
        self.payload = payload
        packet = self.create_packet()
        self.write_to_pcap(packet)

        if self.doAcksNow:
            self.doAck()
        self.tcpFlags = '018'

    def channel_closed(self):
        self.doAcksNow = False
        self.do_fin()

    def create_packet(self):
        self.payload = self.payload.encode('hex')
        tcp_header = self.create_tcp_header()
        ip_header = self.create_ip_header(tcp_header)
        mac_header = self.create_mac_header()
        pcap_header = self.create_pcap_header(mac_header, ip_header, tcp_header)
        return pcap_header + mac_header + ip_header + tcp_header + self.payload

    def do_tcp_handshake(self):
        self.tcpFlags = '002'
        self.serverSeq += 1
        self.clientSeq += 1
        self.tcpFlags = '012'
        self.clientSeq += 1
        self.tcpFlags = '010'
        self.doAcksNow = True

    def doAck(self):
        self.payload = ''
        self.tcpFlags = '010'

        if self.parent == '[SERVER]':
            self.parent = '[CLIENT]'
        elif self.parent == '[CLIENT]':
            self.parent = '[SERVER]'

        packet = self.create_packet()
        self.write_to_pcap(packet)

    def do_fin(self):
        self.tcpFlags = '011'
        self.clientSeq += 1
        self.tcpFlags = '011'
        self.serverSeq += 1
        self.tcpFlags = '010'

    def create_tcp_header(self):
        tcp_header = 'AAAABBBBCCCCCCCCDDDDDDDD5EEE1000FFFF0000'

        if self.parent == self.baseParent:
            src_port = self.connDetails['srcPort']
            dst_port = self.connDetails['dstPort']
            the_seq = self.serverSeq
            the_ack = self.clientSeq
        else:
            src_port = self.connDetails['dstPort']
            dst_port = self.connDetails['srcPort']
            the_seq = self.clientSeq
            the_ack = self.serverSeq

        tcp_header = tcp_header.replace('AAAA', '%04x' % int(src_port))
        tcp_header = tcp_header.replace('BBBB', '%04x' % int(dst_port))

        tcp_header = tcp_header.replace('CCCCCCCC', '%08x' % the_seq)
        tcp_header = tcp_header.replace('DDDDDDDD', '%08x' % the_ack)

        if self.parent == '[SERVER]':
            self.serverSeq += len(self.payload) / 2
        elif self.parent == '[CLIENT]':
            self.clientSeq += len(self.payload) / 2

        tcp_header = tcp_header.replace('EEE', self.tcpFlags)
        tcp_header = tcp_header.replace('FFFF', '%04x' % 0)

        return tcp_header

    def create_ip_header(self, tcpHeader):
        # A = LENGTH, B = PROTOCOL, C = CHECKSUM, D = SRC IP, E = DST IP
        ip_header = '4500AAAA0000400040BBCCCCDDDDDDDDEEEEEEEE'

        if self.parent == '[SERVER]':
            src_ip = self.connDetails['srcIP']
            dst_ip = self.connDetails['dstIP']
        elif self.parent == '[CLIENT]':
            src_ip = self.connDetails['dstIP']
            dst_ip = self.connDetails['srcIP']

        ip_header = ip_header.replace('EEEEEEEE', binascii.hexlify(socket.inet_aton(dst_ip)))
        ip_header = ip_header.replace('DDDDDDDD', binascii.hexlify(socket.inet_aton(src_ip)))
        ip_header = ip_header.replace('BB', '06')
        ip_length = (len(ip_header) + len(tcpHeader) + len(self.payload)) / 2
        ip_header = ip_header.replace('AAAA', '%04x' % int(ip_length))
        ip_header = ip_header.replace('CCCC', '0000')
        return ip_header

    def create_ip_checksum(self, iph):
        words = self.split_n(iph, 4)

        csum = 0;
        for word in words:
            csum += int(word, base=16)

        csum += (csum >> 16)
        csum = csum & 0xFFFF ^ 0xFFFF

        return csum

    def create_mac_header(self):
        # A = SRC MAC, B = DST MAC
        mac_header = 'AAAAAAAAAAAABBBBBBBBBBBB0800'

        if self.parent == '[SERVER]':
            src_mac = '0A1122334455'
            dst_mac = '0A5544332211'
        elif self.parent == '[CLIENT]':
            src_mac = '0A5544332211'
            dst_mac = '0A1122334455'

        mac_header = mac_header.replace('AAAAAAAAAAAA', src_mac)
        mac_header = mac_header.replace('BBBBBBBBBBBB', dst_mac)
        return mac_header

    def create_pcap_header(self, mac_header, ip_header, tcp_header):
        # A/B = FRAME SIZE (Little Endian)
        pcap_packet_header = 'AA779F4790A20400AAAAAAAABBBBBBBB'

        pcap_length = (len(mac_header) + len(ip_header) + len(tcp_header) + len(self.payload)) / 2
        pcap_length = '%08x' % pcap_length
        reverse_length = pcap_length[6:] + pcap_length[4:6] + pcap_length[2:4] + pcap_length[:2]

        pcap_packet_header = pcap_packet_header.replace('AAAAAAAA', reverse_length)
        pcap_packet_header = pcap_packet_header.replace('BBBBBBBB', reverse_length)
        return pcap_packet_header

    def write_to_pcap(self, pcap_bytes):
        set_permissions = False

        if not os.path.isfile(self.pcapFile):
            set_permissions = True

        bts = binascii.a2b_hex(pcap_bytes)
        f = open(self.pcapFile, 'ab')
        f.write(bts)
        f.close()

        if set_permissions:
            os.chmod(self.pcapFile, 0644)

    def split_n(self, str1, n):
        return [str1[start:start + n] for start in range(0, len(str1), n)]
