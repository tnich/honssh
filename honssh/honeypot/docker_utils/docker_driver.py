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
from docker import Client
from watchdog.observers import Observer
from .docker_filesystem import DockerFileSystemEventHandler


class DockerDriver(object):

    def __init__(self, uri, image, launch_cmd, hostname, pids_limit, mem_limit, memswap_limit, shm_size, cpu_period,
                 cpu_shares, cpuset_cpus, peer_ip, reuse_container):
        self.container_id = None
        self.container_ip = None
        self.connection = None
        self.uri = uri
        self.image = image
        self.hostname = hostname
        self.launch_cmd = launch_cmd
        self.pids_limit = pids_limit
        self.mem_limit = mem_limit
        self.memswap_limit = memswap_limit
        self.shm_size = shm_size
        self.cpu_period = cpu_period
        self.cpu_shares = cpu_shares
        self.cpuset_cpus = cpuset_cpus
        self.peer_ip = peer_ip
        self.reuse_container = reuse_container

        self.watcher = None
        self.overlay_folder = None
        self.mount_dir = None
        self.max_filesize = 0
        self.use_revisions = False

        self.make_connection()

    def make_connection(self):
        self.connection = Client(self.uri)

    def launch_container(self):
        if self.reuse_container:
            try:
                # Check for existing container
                container_data = self.connection.inspect_container(self.peer_ip)
                # Get container id
                self.container_id = container_data['Id']
                log.msg(log.LGREEN, '[PLUGIN][DOCKER]', 'Reusing container %s ' % self.container_id)
                # Restart container
                self.connection.restart(self.container_id)
            except:
                self.container_id = None
                pass

        if self.container_id is None:
            host_config = self.connection.create_host_config(pids_limit=self.pids_limit, mem_limit=self.mem_limit,
                                                             memswap_limit=self.memswap_limit, shm_size=self.shm_size,
                                                             cpu_period=self.cpu_period, cpu_shares=self.cpu_shares,
                                                             cpuset_cpus=self.cpuset_cpus)
            self.container_id = \
                self.connection.create_container(image=self.image, tty=True, hostname=self.hostname,
                                                 name=self.peer_ip, host_config=host_config)['Id']
            self.connection.start(self.container_id)

        exec_id = self.connection.exec_create(self.container_id, self.launch_cmd)['Id']
        self.connection.exec_start(exec_id, tty=True)
        container_data = self.connection.inspect_container(self.container_id)
        self.container_ip = container_data['NetworkSettings']['Networks']['bridge']['IPAddress']

        log.msg(log.LCYAN, '[PLUGIN][DOCKER]',
                'Launched container (%s, %s)' % (self.container_ip, self.container_id))

        return {"id": self.container_id, "ip": self.container_ip}

    def teardown_container(self, destroy_container):
        if self.watcher is not None:
            self.watcher.unschedule_all()
            log.msg(log.LCYAN, '[PLUGIN][DOCKER]', 'Filesystem watcher stopped')

        self.connection.stop(self.container_id)
        log.msg(log.LCYAN, '[PLUGIN][DOCKER]',
                'Stopped container (%s, %s)' % (self.container_ip, self.container_id))

        # Check for container reuse
        if not self.reuse_container or destroy_container:
            self.connection.remove_container(self.container_id, force=True)
            log.msg(log.LCYAN, '[PLUGIN][DOCKER]',
                    'Destroyed container (%s, %s)' % (self.container_ip, self.container_id))

    def _file_get_contents(self, filename):
        with open(filename) as f:
            return f.read()

    def start_watcher(self, dest_path, max_filesize, use_revisions):
        if self.watcher is None:
            self.overlay_folder = dest_path
            self.max_filesize = max_filesize
            self.use_revisions = use_revisions

            # Check if watching should be started
            if len(self.overlay_folder) > 0:
                # Create overlay folder if needed
                if not os.path.exists(self.overlay_folder):
                    os.makedirs(self.overlay_folder)
                    os.chmod(self.overlay_folder, 0755)

                self._start_inotify()

    def _start_inotify(self):
        docker_info = self.connection.info()
        docker_root = docker_info['DockerRootDir']
        storage_driver = docker_info['Driver']

        supported_storage = {
            'aufs': '%s/%s/mnt/%s',  # -> /var/lib/docker/aufs/mnt/<mount-id>
            'btrfs': '%s/%s/subvolumes/%s',  # -> /var/lib/docker/btrfs/subvolumes/<mount-id>
            'overlay': '%s/%s/%s/merged',  # -> /var/lib/docker/overlay/<mount-id>/merged
            'overlay2': '%s/%s/%s/merged'  # -> /var/lib/docker/overlay2/<mount-id>/merged
        }

        if storage_driver in supported_storage:
            # Get container mount id
            mount_id = self._file_get_contents(('%s/image/%s/layerdb/mounts/%s/mount-id' % (docker_root, storage_driver, self.container_id)))
            # construct mount path
            self.mount_dir = supported_storage[storage_driver] % (docker_root, storage_driver, mount_id)

            log.msg(log.LGREEN, '[PLUGIN][DOCKER]', 'Starting filesystem watcher at %s' % self.mount_dir)

            try:
                # Create watcher and start watching
                self.watcher = Observer()
                event_handler = DockerFileSystemEventHandler(self.overlay_folder, self.mount_dir,
                                                             self.max_filesize, self.use_revisions)
                self.watcher.schedule(event_handler, self.mount_dir, recursive=True)
                self.watcher.start()

                log.msg(log.LGREEN, '[PLUGIN][DOCKER]', 'Filesystem watcher started')
            except Exception as exc:
                log.msg(log.LRED, '[PLUGIN][DOCKER]', 'Failed to start filesystem watcher "%s"' % str(exc))
        else:
            log.msg(log.LRED, '[PLUGIN][DOCKER]',
                    'Filesystem watcher not supported for storage driver "%s"' % storage_driver)
