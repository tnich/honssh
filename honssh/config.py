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

import ConfigParser
import inspect

from honssh import plugins
from honssh.utils import validation


class Config(ConfigParser.ConfigParser):
    _instance = None

    @classmethod
    def getInstance(cls):
        if cls._instance is None:
            cls._instance = cls()

        return  cls._instance

    def __init__(self):
        stack = inspect.stack()

        if 'cls' in stack[1][0].f_locals and stack[1][0].f_locals['cls'] is self.__class__:
            ConfigParser.ConfigParser.__init__(self)

            plugin_list = plugins.get_plugin_list()
            cfg_files = plugins.get_plugin_cfg_files(plugin_list)
            cfg_files.append('honssh.cfg')
            self.read(cfg_files)
        else:
            raise Exception('This class cannot be instantiated from outside. Please use \'getInstance()\'')

    def validateConfig(self):
        plugin_list = plugins.get_plugin_list()
        loaded_plugins = plugins.import_plugins(plugin_list)
        # TODO: Is this right?
        valid = plugins.run_plugins_function(loaded_plugins, 'validate_config', False)

        # Check prop exists and is an IP address
        props = [['honeypot', 'ssh_addr'], ['honeypot', 'client_addr']]
        for prop in props:
            if not self.checkExist(prop) and validation.checkValidIP(prop, self.get(prop[0], prop[1])):
                valid = False

        # Check prop exists and is a port number
        props = [['honeypot', 'ssh_port']]
        for prop in props:
            if not self.checkExist(prop) or not validation.checkValidPort(prop, self.get(prop[0], prop[1])):
                valid = False

        # Check prop exists
        props = [['honeypot', 'public_key'], ['honeypot', 'private_key'], ['honeypot', 'public_key_dsa'],
                 ['honeypot', 'private_key_dsa'], ['folders', 'log_path'], ['folders', 'session_path']]
        for prop in props:
            if not self.checkExist(prop):
                valid = False

        # Check prop exists and is true/false
        props = [['advNet', 'enabled'], ['interact', 'enabled'], ['spoof', 'enabled'], ['download', 'passive'],
                 ['download', 'active'], ['hp-restrict', 'disable_publicKey'], ['hp-restrict', 'disable_x11'],
                 ['hp-restrict', 'disable_sftp'], ['hp-restrict', 'disable_exec'],
                 ['hp-restrict', 'disable_port_forwarding'],
                 ['packet_logging', 'enabled']]
        for prop in props:
            if not self.checkExist(prop) or not validation.checkValidBool(prop, self.get(prop[0], prop[1])):
                valid = False

        # If interact is enabled check it's config
        if self.get('interact', 'enabled') == 'true':
            prop = ['interact', 'interface']
            if not self.checkExist(prop) or not validation.checkValidIP(prop, self.get(prop[0], prop[1])):
                valid = False

            prop = ['interact', 'port']
            if not self.checkExist(prop) or not validation.checkValidPort(prop, self.get(prop[0], prop[1])):
                valid = False

        # If spoof is enabled check it's config
        if self.get('spoof', 'enabled') == 'true':
            prop = ['spoof', 'users_conf']
            if not self.checkExist(prop):
                valid = False

        return valid

    def checkExist(self, prop):
        if self.has_option(prop[0], prop[1]):
            if not self.get(prop[0], prop[1]) == '':
                return True
            else:
                print '[VALIDATION] - [' + prop[0] + '][' + prop[1] + '] must not be blank.'
                return False
        else:
            print '[VALIDATION] - [' + prop[0] + '][' + prop[1] + '] must exist.'
            return False

    def get(self, section, option, raw=False, vars=None, default=None):
        ret = ConfigParser.ConfigParser.get(self, section, option, raw, vars)

        if len(ret) == 0 and default is not None:
            ret = default

        return ret

    def _getconv(self, section, option, conv, checkfunction, default=None):
        ret = self.get(section, option, default=default)

        if len(ret) == 0 and default is not None:
            ret = default
        elif len(ret) > 0:
            if checkfunction([section, option], ret):
                ret = conv(ret)

        return ret

    def getport(self, section, option, default=None):
        return self._getconv(section, option, int, validation.checkValidNumber, default)

    def getip(self, section, option, default=None):
        return self._getconv(section, option, int, validation.checkValidNumber, default)

    def getint(self, section, option, default=None):
        return self._getconv(section, option, int, validation.checkValidNumber, default)

    def getfloat(self, section, option, default=None):
        return self._getconv(section, option, float, validation.checkValidNumber, default)

    def getboolean(self, section, option, default=None):
        return self._getconv(section, option, bool, validation.checkValidBool(), default)
