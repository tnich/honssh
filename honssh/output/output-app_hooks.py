from honssh import config

from twisted.python import log
import subprocess

class Plugin():

    def __init__(self, cfg):
        self.cfg = cfg
  
    def connection_made(self, sensor):
        if self.cfg.has_option('output-app_hooks', 'connection_made'):
            if self.cfg.get('output-app_hooks', 'connection_made') != '':
                session = sensor['session']
                command = '%s CONNECTION_MADE %s %s %s %s %s %s' % (self.cfg.get('output-app_hooks', 'connection_made'), session['start_time'], session['peer_ip'], session['peer_port'], sensor['honey_ip'], sensor['honey_port'], session['session_id'])
                self.runCommand(command)
    
    def connection_lost(self, sensor):
        if self.cfg.has_option('output-app_hooks', 'connection_lost'):
            if self.cfg.get('output-app_hooks', 'connection_lost') != '':
                session = sensor['session']
                command = '%s CONNECTION_LOST %s %s %s %s %s %s' % (self.cfg.get('output-app_hooks', 'connection_lost'), session['end_time'], session['peer_ip'], session['peer_port'], sensor['honey_ip'], sensor['honey_port'], session['session_id'])
                self.runCommand(command)
  
    def login_successful(self, sensor):
        if self.cfg.has_option('output-app_hooks', 'login_successful'):
            if self.cfg.get('output-app_hooks', 'login_successful') != '':
                session = sensor['session']
                command = '%s LOGIN_SUCCESSFUL %s %s %s %s' % (self.cfg.get('output-app_hooks', 'login_successful'), session['auth']['date_time'], session['peer_ip'], session['auth']['username'], session['auth']['password'])
                self.runCommand(command)
    
    def login_failed(self, sensor):
        if self.cfg.has_option('output-app_hooks', 'login_failed'):
            if self.cfg.get('output-app_hooks', 'login_failed') != '':
                session = sensor['session']
                command = '%s LOGIN_FAILED %s %s %s %s' % (self.cfg.get('output-app_hooks', 'login_failed'), session['auth']['date_time'], session['peer_ip'], session['auth']['username'], session['auth']['password'])
                self.runCommand(command)
       
    def channel_opened(self, sensor):
        if self.cfg.has_option('output-app_hooks', 'channel_opened'):
            if self.cfg.get('output-app_hooks', 'channel_opened') != '':
                channel = sensor['session']['channel']
                command = '%s CHANNEL_OPENED %s %s %s' % (self.cfg.get('output-app_hooks', 'channel_opened'), channel['start_time'], channel['name'], channel['channel_id'])
                self.runCommand(command)
    
    def channel_closed(self, sensor):
        if self.cfg.has_option('output-app_hooks', 'channel_closed'):
            if self.cfg.get('output-app_hooks', 'channel_closed') != '':
                channel = sensor['session']['channel']
                command = '%s CHANNEL_CLOSED %s %s %s' % (self.cfg.get('output-app_hooks', 'channel_closed'), channel['end_time'], channel['name'], channel['channel_id'])
                self.runCommand(command)
    
    def command_entered(self, sensor):
        if self.cfg.has_option('output-app_hooks', 'command_entered'):
            if self.cfg.get('output-app_hooks', 'command_entered') != '':
                channel = sensor['session']['channel']
                command = '%s COMMAND_ENTERED %s %s \'%s\'' % (self.cfg.get('output-app_hooks', 'channel_closed'), channel['command']['date_time'], channel['channel_id'], channel['command']['command'])
                self.runCommand(command)

    def download_started(self, sensor):
        if self.cfg.has_option('output-app_hooks', 'download_started'):
            if self.cfg.get('output-app_hooks', 'download_started') != '':
                channel = sensor['session']['channel']
                download = channel['download']
                command = '%s DOWNLOAD_STARTED %s %s %s %s' % (self.cfg.get('output-app_hooks', 'download_started'), download['start_time'], channel['channel_id'], download['link'], download['file'])
                self.runCommand(command)

    def download_finished(self, sensor):
        if self.cfg.has_option('output-app_hooks', 'download_finished'):
            if self.cfg.get('output-app_hooks', 'download_finished') != '':
                channel = sensor['session']['channel']
                download = channel['download']
                command = '%s DOWNLOAD_FINISHED %s %s %s %s' % (self.cfg.get('output-app_hooks', 'download_finished'), download['end_time'], channel['channel_id'], download['link'], download['file'])
                self.runCommand(command)
       
    def validate_config(self):
        props = [['output-app_hooks','enabled']]
        for prop in props:
            if not config.checkExist(self.cfg,prop) or not config.checkValidBool(self.cfg, prop):
                return False
        return True

    def runCommand(self, command):
        sp = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        sp.communicate()
