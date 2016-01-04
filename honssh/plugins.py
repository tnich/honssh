# Copyright (c) 2013 Thomas Nicholson <tnnich@googlemail.com>
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
import importlib
import inspect
import copy
from twisted.python import log
from twisted.internet import threads

output_plugin_folders = ['honssh/output', 'plugins/output']
honeypot_plugin_folders = ['honssh/honeypot', 'plugins/honeypot']

def get_plugin_list(type='all'):
    if type == 'all':
        plugin_folders = output_plugin_folders + honeypot_plugin_folders
    elif type == 'output':
        plugin_folders = output_plugin_folders
    elif type == 'honeypot':
        plugin_folders = honeypot_plugin_folders
    
    plugins = []
    for folder in plugin_folders:
        files = os.listdir(folder)
        for file in files:
            if file.endswith('.py'):
                if file != '__init__.py':
                    file = file.replace('.py', '')
                    plugins.append('%s/%s' % (folder, file))
    return plugins

def get_plugin_cfg_files(plugin_files):
    cfg_files = []
    for plugin_file in plugin_files:
        cfg_file = '%s.cfg' % (plugin_file)
        if os.path.exists(cfg_file):
            cfg_files.append(cfg_file)
    return cfg_files

def import_plugin(plugin, cfg):
    plugin = plugin.replace('/', '.')
    import_plugin = importlib.import_module(plugin)
    return import_plugin.Plugin(cfg)

def import_plugins(plugins, cfg, search=None):
    plugin_list = []
    for plugin in plugins:
        cfg_section = plugin.split('/')[-1]
        if cfg.get(cfg_section, 'enabled') == 'true':
            if search:
                if cfg.get(cfg_section, search) == 'true':
                    plugin_list.append(import_plugin(plugin, cfg))
            else:
                plugin_list.append(import_plugin(plugin, cfg))
    return plugin_list

def import_pre_auth_plugins(plugins, cfg):
    imported_plugins = import_plugins(plugins, cfg, 'pre-auth')
    if len(imported_plugins) > 0:
        return [imported_plugins[0]]
    return None

def import_post_auth_plugins(plugins, cfg):
    imported_plugins = import_plugins(plugins, cfg, 'post-auth')
    if len(imported_plugins) > 0:
        return [imported_plugins[0]]
    return None

def run_plugins_function(plugins, function, thread, *args, **kwargs):
    for plugin in plugins:
        return_value = False
        class_name = get_plugin_name(plugin).upper()
        try:
            func = getattr(plugin, function)
            log.msg('[PLUGIN][' + class_name +  '] - ' + function.upper())
            if thread:
                threads.deferToThread(func, *copy.deepcopy(args), **copy.deepcopy(kwargs))
            else:
                return_value = func(*args, **kwargs)
                if not return_value:
                    return return_value
        except AttributeError:
            pass
        except Exception, ex:
            log.msg('[PLUGIN][' + class_name +  '][ERR] - ' + str(ex))
            
    return return_value

def get_plugin_name(plugin):
    return inspect.getfile(plugin.__class__).split('/')[-1].split('.')[0]
    