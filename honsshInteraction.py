#!/usr/bin/env python

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

from twisted.internet import reactor, protocol, threads

import json
import sys
import time
import base64
import argparse
import re
import datetime
import tty
import termios


class HonsshProtocol(protocol.Protocol):
    lost = False

    def getch(self):
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch

    def connectionMade(self):
        if self.factory.command == 'list':
            self.cmdList()
        elif self.factory.command == 'view':
            self.cmdView()
        elif self.factory.command == 'disconnect':
            self.cmdDisconnect()

    def connectionLost(self, message):
        self.lost = True
        if not self.factory.command == 'list':
            print '\rConnection lost\n\r'
        try:
            reactor.stop()
        except:
            pass

    def cmdList(self):
        self.sendData({'command': 'list'})

    def cmdView(self):
        self.sendData({'command': 'view', 'uuid': self.factory.uuid})
        escCheck = threads.deferToThread(self.escapeCheck, False)
        escCheck.addCallback(self.escaped)

    def cmdDisconnect(self):
        self.sendData({'command': 'disconnect', 'uuid': self.factory.uuid})

    def escapeCheck(self, sendOn):
        print
        print('Connecting to ' + self.factory.uuid + ' - Press Ctrl+A + D to quit')
        print
        test = True
        while test and not self.lost:
            k = self.getch()
            if k == '\x01':
                k2 = self.getch()
                if k2 == 'd':
                    test = False
            elif sendOn:
                self.sendData(k)
        return test

    def escaped(self, input):
        print('\rEscape sequence detected - Disconnecting')
        reactor.stop()

    def dataReceived(self, data):
        datagrams = data.split('_')
        for i in range(0, len(datagrams) / 3):
            datagram = datagrams[3 * i:(3 * i) + 3]
            if datagram[0] == 'honssh' and datagram[1] == 's':
                self.theData = datagram[2]
                self.parsePacket()
            else:
                print('Received incorrect packet - Disconnecting')
                reactor.stop()

    def sendData(self, theJson):
        theData = base64.b64encode(json.dumps(theJson))
        self.transport.write('honssh_c_' + theData + '_')

    def getData(self, theData):
        return json.loads(base64.b64decode(theData))

    def parsePacket(self):
        theJson = self.getData(self.theData)
        if isinstance(theJson, dict):
            if theJson['msg']:
                print theJson['msg']
                reactor.stop()
        else:
            if self.factory.command == 'list':
                if self.factory.style in ['pretty', 'plain']:
                    self.printPrettyTable(theJson)
                elif self.factory.style == 'json':
                    print json.dumps(theJson, indent=4)
                reactor.stop()
            elif self.factory.command in ['view']:
                sys.stdout.write(theJson)
                sys.stdout.flush()

    def printPrettyTable(self, theJson):
        sensorLength = 10
        for sensor in theJson:
            i = len(sensor['sensor_name'])
            if i > sensorLength:
                sensorLength = i
        if self.factory.style == 'pretty':
            print "UUID".ljust(34) + "Sensor Name".ljust(sensorLength + 2) + "PeerIP".ljust(17) + "Name".ljust(
                9) + "Uptime"
        for sensor in theJson:
            for session in sensor['sessions']:
                if len(session['channels']) == 0:
                    print 'AUTHENTICATING'.ljust(34) + sensor['sensor_name'].ljust(sensorLength + 2) + session[
                        'peer_ip'].ljust(17)
                else:
                    for channel in session['channels']:
                        if 'end_time' not in channel:
                            dt = datetime.datetime.strptime(channel['start_time'], "%Y%m%d_%H%M%S_%f")
                            now = datetime.datetime.now()
                            totalTime = time.gmtime((now - dt).total_seconds())
                            print channel['uuid'].ljust(34) + sensor['sensor_name'].ljust(sensorLength + 2) + \
                                  session['peer_ip'].ljust(17) + channel['name'].ljust(9) + time.strftime("%H:%M:%S",
                                                                                                          totalTime)


class HonSSHInteractFactory(protocol.ClientFactory):
    protocol = HonsshProtocol

    def clientConnectionFailed(self, connector, reason):
        print "Failed to connect"
        reactor.stop()


def portType(input):
    if not input.isdigit():
        raise argparse.ArgumentTypeError('Port must be a number between 0 and 65535')
    input = int(input)
    if 0 <= input <= 65535:
        return input
    else:
        raise argparse.ArgumentTypeError('Port must be a number between 0 and 65535')


def ipType(input):
    m = re.match('(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', input)
    if m:
        return input
    else:
        raise argparse.ArgumentTypeError('IP Must be a valid IP address')


def uuidType(input):
    m = re.match('^[a-z0-9]{32}$', input)
    if m:
        return input
    else:
        raise argparse.ArgumentTypeError('UUID must be 32 Lower Alphanumeric Characters')


def parse_args():
    """Defines the command line arguments. """
    parser = argparse.ArgumentParser('HonSSH Interaction Utility', usage='''
    List connections
        -c list [-o]
    View a connection
        -c view -u <uuid>
    Disconnect a connection
        -c disconnect -u <uuid>
''')

    fmt = 'pretty'
    ipa = '127.0.0.1'
    cop = '5123'

    conn = parser.add_argument_group('Connection Options')
    conn.add_argument(
        '-i',
        dest='ip',
        help='The HonSSH Interaction IP address to connect to (default: {0})'.format(ipa),
        type=ipType,
        default=ipa
    )
    conn.add_argument(
        '-p',
        dest='port',
        help='The HonSSH Interaction port to connect to (default: {0})'.format(cop),
        type=portType,
        default=cop
    )

    command = parser.add_argument_group('Command Options')
    command.add_argument(
        '-c',
        choices=['list', 'view', 'disconnect'],
        dest='cmd',
        help='Command to execute',
        required=True
    )
    command.add_argument(
        '-u',
        dest='uuid',
        help='UUID of connection to interact with. Required for \'view\' and \'disconnect\' commands',
        type=uuidType
    )

    out = parser.add_argument_group('Output Options (Only for the \'list\' command)')
    out.add_argument(
        '-o',
        dest='format',
        choices=['pretty', 'plain', 'json'],
        help='pretty = table with headers. plain = table without headers. json = JSON formatted. (default: {0})'.format(
            fmt),
        default=fmt
    )

    args = parser.parse_args()
    return args


def process_args(args):
    """Process the command line arguments."""
    if not args.cmd == 'list':
        if not args.uuid:
            print('UUID required for selected command')
            sys.exit(1)

    ifactory = HonSSHInteractFactory()
    ifactory.command = args.cmd
    ifactory.style = args.format
    if args.cmd in ['view', 'disconnect']:
        ifactory.uuid = args.uuid

    reactor.connectTCP(args.ip, args.port, ifactory)
    reactor.run()


def main():
    args = parse_args()
    process_args(args)


if __name__ == '__main__':
    main()
