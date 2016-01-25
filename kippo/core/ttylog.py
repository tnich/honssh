# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
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

# Should be compatible with user mode Linux

import struct, os

OP_OPEN, OP_CLOSE, OP_WRITE, OP_EXEC = 1, 2, 3, 4
TYPE_INPUT, TYPE_OUTPUT, TYPE_INTERACT = 1, 2, 3

def ttylog_write(logfile, len, direction, stamp, data = None):
    f = file(logfile, 'ab')
    sec, usec = int(stamp), int(1000000 * (stamp - int(stamp)))
    f.write(struct.pack('<iLiiLL', 3, 0, len, direction, sec, usec))
    f.write(data)
    f.close()

def ttylog_open(logfile, stamp):
    f = file(logfile, 'ab')
    sec, usec = int(stamp), int(1000000 * (stamp - int(stamp)))
    f.write(struct.pack('<iLiiLL', 1, 0, 0, 0, sec, usec))
    f.close()
    
    os.chmod(logfile, 0644)

def ttylog_close(logfile, stamp):
    f = file(logfile, 'ab')
    sec, usec = int(stamp), int(1000000 * (stamp - int(stamp)))
    f.write(struct.pack('<iLiiLL', 2, 0, 0, 0, sec, usec))
    f.close()

