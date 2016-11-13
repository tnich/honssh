from honssh import log

import os
import struct
import hashlib
import json
import socket

BUFSIZ = 16384

OP_ERROR = 0
OP_INFO = 1
OP_AUTH = 2
OP_PUBLISH = 3
OP_SUBSCRIBE = 4

MAXBUF = 1024 ** 2
SIZES = {
    OP_ERROR: 5 + MAXBUF,
    OP_INFO: 5 + 256 + 20,
    OP_AUTH: 5 + 256 + 20,
    OP_PUBLISH: 5 + MAXBUF,
    OP_SUBSCRIBE: 5 + 256 * 2,
}

HONSSHAUTHCHAN = 'honssh.auth'
HONSSHSESHCHAN = 'honssh.sessions'


class BadClient(Exception):
    pass


# packs a string with 1 byte length field
def strpack8(x):
    if isinstance(x, str): x = x.encode('latin1')
    return struct.pack('!B', len(x)) + x


# unpacks a string with 1 byte length field
def strunpack8(x):
    l = x[0]
    return x[1:1 + l], x[1 + l:]


def msghdr(op, data):
    return struct.pack('!iB', 5 + len(data), op) + data


def msgpublish(ident, chan, data):
    return msghdr(OP_PUBLISH, strpack8(ident) + strpack8(chan) + data)


def msgsubscribe(ident, chan):
    if isinstance(chan, str): chan = chan.encode('latin1')
    return msghdr(OP_SUBSCRIBE, strpack8(ident) + chan)


def msgauth(rand, ident, secret):
    hash = hashlib.sha1(bytes(rand) + secret).digest()
    return msghdr(OP_AUTH, strpack8(ident) + hash)


class FeedUnpack(object):
    def __init__(self):
        self.buf = bytearray()

    def __iter__(self):
        return self

    def next(self):
        return self.unpack()

    def feed(self, data):
        self.buf.extend(data)

    def unpack(self):
        if len(self.buf) < 5:
            raise StopIteration('No message.')

        ml, opcode = struct.unpack('!iB', buffer(self.buf, 0, 5))
        if ml > SIZES.get(opcode, MAXBUF):
            raise BadClient('Not respecting MAXBUF.')

        if len(self.buf) < ml:
            raise StopIteration('No message.')

        data = bytearray(buffer(self.buf, 5, ml - 5))
        del self.buf[:ml]
        return opcode, data


class hpclient(object):
    def __init__(self, server, port, ident, secret):
        log.msg(log.LCYAN, '[PLUGIN][HPFEEDS]',
                'hpfeeds client init broker {0}:{1}, identifier {2}'.format(server, port, ident))
        self.server, self.port = server, int(port)
        self.ident, self.secret = ident.encode('latin1'), secret.encode('latin1')
        self.unpacker = FeedUnpack()
        self.state = 'INIT'

        self.connect()
        self.sendfiles = []
        self.filehandle = None
        self.s = None

    def connect(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(3)
        try:
            self.s.connect((self.server, self.port))
        except:
            log.msg(log.LCYAN, '[PLUGIN][HPFEEDS]', 'hpfeeds client could not connect to broker.')
            self.s = None
        else:
            self.s.settimeout(None)
            self.handle_established()

    def send(self, data):
        if not self.s: return
        self.s.send(data)

    def close(self):
        self.s.close()
        self.s = None

    def handle_established(self):
        log.msg(log.LCYAN, '[PLUGIN][HPFEEDS]', 'hpclient established')
        while self.state != 'GOTINFO':
            self.read()

        # quickly try to see if there was an error message
        self.s.settimeout(0.5)
        self.read()
        self.s.settimeout(None)

    def read(self):
        if not self.s: return
        try:
            d = self.s.recv(BUFSIZ)
        except socket.timeout:
            return

        if not d:
            self.close()
            return

        self.unpacker.feed(d)
        try:
            for opcode, data in self.unpacker:
                log.msg(log.LCYAN, '[PLUGIN][HPFEEDS]', 'hpclient msg opcode {0} data {1}'.format(opcode, data))
                if opcode == OP_INFO:
                    name, rand = strunpack8(data)
                    log.msg(log.LCYAN, '[PLUGIN][HPFEEDS]', 'hpclient server name {0} rand {1}'.format(name, rand))
                    self.send(msgauth(rand, self.ident, self.secret))
                    self.state = 'GOTINFO'

                elif opcode == OP_PUBLISH:
                    ident, data = strunpack8(data)
                    chan, data = strunpack8(data)
                    log.msg(log.LCYAN, '[PLUGIN][HPFEEDS]', 'publish to {0} by {1}: {2}'.format(chan, ident, data))

                elif opcode == OP_ERROR:
                    log.err('[PLUGIN][HPFEEDS] - errormessage from server: {0}'.format(data))
                else:
                    log.err('[PLUGIN][HPFEEDS] - unknown opcode message: {0}'.format(opcode))
        except BadClient:
            log.err('[PLUGIN][HPFEEDS] - unpacker error, disconnecting.')
            self.close()

    def publish(self, channel, **kwargs):
        try:
            self.send(msgpublish(self.ident, channel, json.dumps(kwargs).encode('latin1')))
        except Exception, e:
            log.err('[PLUGIN][HPFEEDS] - connection to hpfriends lost: {0}'.format(e))
            log.err('[PLUGIN][HPFEEDS] - connecting')
            self.connect()
            self.send(msgpublish(self.ident, channel, json.dumps(kwargs).encode('latin1')))

    def sendfile(self, filepath):
        # does not read complete binary into memory, read and send chunks
        if not self.filehandle:
            # FIXME: Where does 'i' come from??
            self.sendfileheader(i.file)
            self.sendfiledata()
        else:
            self.sendfiles.append(filepath)

    def sendfileheader(self, filepath):
        self.filehandle = open(filepath, 'rb')
        fsize = os.stat(filepath).st_size
        # FIXME: Where does 'UNIQUECHAN' come from??
        headc = strpack8(self.ident) + strpack8(UNIQUECHAN)
        headh = struct.pack('!iB', 5 + len(headc) + fsize, OP_PUBLISH)
        self.send(headh + headc)

    def sendfiledata(self):
        tmp = self.filehandle.read(BUFSIZ)
        if not tmp:
            if self.sendfiles:
                fp = self.sendfiles.pop(0)
                self.sendfileheader(fp)
            else:
                self.filehandle = None
                self.handle_io_in(b'')
        else:
            self.send(tmp)
