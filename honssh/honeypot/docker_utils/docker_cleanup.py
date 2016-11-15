#!/usr/bin/env python

# Copyright (c) 2015 Robert Putt (http://www.github.com/robputt796)
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

import sqlite3
import time
from twisted.internet import task
from docker import Client
from honssh import log


def start_cleanup_loop(ttl=1440, interval=30):
    # Check for valid values
    if ttl > 0 and interval > 0:
        # Convert to seconds
        secs = (interval * 60)
        # Create and start repeating cleanup timer
        t = task.LoopingCall(cleanup, ttl)
        t.start(secs)


def cleanup(ttl):
    # Get config
    from honssh.config import Config
    cfg = Config.getInstance()

    # Create client
    socket = cfg.get(['honeypot-docker', 'uri'])
    client = Client(socket)

    # Get all stopped containers
    containers = client.containers(quiet=False, all=True, filters={'status': ['exited']})

    # Get now
    now = int(time.time())

    # Convert to seconds
    ttl_secs = (ttl * 60)

    for c in containers:
        c_id = c['Id']

        # Get container info
        ins = client.inspect_container(c_id)
        # Extract date
        finished_at = convert_json_datetime(ins['State']['FinishedAt'])

        # Create time diff in minutes
        diff = now - finished_at

        # Check exceeds ttl and remove container if needed
        if diff > ttl_secs:
            log.msg(log.LYELLOW, '[PLUGIN][DOCKER][CLEANUP]', 'Removing container %s' % c_id)
            client.remove_container(c_id, force=True)


def convert_json_datetime(json_date):
    # We need to do this workaround as the datetime returned by docker '2015-01-08T22:57:31.547920715Z'
    # would need a third party lib
    db = sqlite3.connect(":memory:")
    curs = db.cursor()
    curs.execute("SELECT strftime('%s', ?)", (json_date,))
    return int(curs.fetchone()[0])