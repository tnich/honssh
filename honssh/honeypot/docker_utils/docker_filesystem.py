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

import os

from honssh import log
from twisted.python import filepath
from watchdog.events import FileSystemEventHandler


class DockerFileSystemEventHandler(FileSystemEventHandler):
    def __init__(self, overlay_folder, mount_dir, max_filesize, use_revisions):
        super(FileSystemEventHandler, self).__init__()
        self.overlay_folder = overlay_folder
        self.mount_dir = mount_dir
        self.max_filesize = max_filesize
        self.use_revisions = use_revisions

    def on_modified(self, event):
        # log.msg(log.LYELLOW, '[FS_WATCH][on_modified]', '%s' % repr(event))

        if not event.is_directory:
            self.process_event(event.src_path)

    def on_moved(self, event):
        # log.msg(log.LYELLOW, '[FS_WATCH][on_moved]', '%s' % repr(event))

        if not event.is_directory:
            self.process_event(event.dest_path)

    def process_event(self, file_path):
        file = filepath.FilePath(file_path)
        # log.msg(log.LYELLOW, '[FS_WATCH][process_event]', '%s' % str(file))

        if file.exists() and file.getsize() > 0:
            # Check max_filesize constraint
            if self.max_filesize == 0 or (self.max_filesize > 0 and (file.getsize() / 1024) <= self.max_filesize):
                # Construct src and dest path as string
                src_path = '%s/%s' % (file.dirname(), file.basename())
                dest_path = '%s/%s' % (self.overlay_folder, src_path.replace(self.mount_dir, ''))

                # Create dest file object
                d = filepath.FilePath(dest_path)

                # Check for revision constraint
                if self.use_revisions and d.exists():
                    c = 0
                    while True:
                        # Increment counter and construct new path
                        c += 1
                        dpath = dest_path + "-" + str(c)
                        d = filepath.FilePath(dpath)

                        # Check for new path
                        if not d.exists():
                            dest_path = dpath
                            break

                # log.msg(log.LBLUE, '[COPY]', '%s / %s' % (src_path, dest_path))

                try:
                    # Create directory tree
                    os.makedirs('%s%s' % (self.overlay_folder, file.dirname().replace(self.mount_dir, '')))
                except:
                    # Ignore exception
                    pass

                try:
                    # Do actual copy
                    file.copyTo(d)
                except Exception as exc:
                    log.msg(log.LRED, '[PLUGIN][DOCKER][FS_WATCH]', 'FAILED TO COPY "%s" - %s' % (src_path, str(exc)))