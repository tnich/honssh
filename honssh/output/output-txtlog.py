from honssh import config

import os

class Plugin():

    def __init__(self, cfg):
        self.cfg = cfg

    def connection_made(self, sensor):
        self.auth_attempts = []
        self.login_success = False
        self.auth_log_file = self.cfg.get('folders', 'log_path') + "/" + sensor['session']['start_time'][:8]

    def login_successful(self, sensor):
        session = sensor['session']
        self.log_file = session['log_location'] + session['start_time'] + '.log'
    
        country = session['country']
        if country != '':
            country = ' - ' + country
    
        self.text_log(session['start_time'], '[POT  ] %s - %s:%s' % (sensor['sensor_name'], sensor['honey_ip'], sensor['honey_port']))
        self.text_log(session['start_time'], '[SSH  ] Incoming Connection from %s:%s%s' % (session['peer_ip'], session['peer_port'], country))
        self.auth_log(session['start_time'], session['peer_ip'], sensor['session']['auth']['username'], sensor['session']['auth']['password'], True)

        self.auth_attempts.append(sensor['session']['auth'])

        for auth in self.auth_attempts:
            if auth['success']:
                login = 'Successful'
            else:
                login = 'Failed'
            self.text_log(auth['date_time'], '[SSH  ] Login %s: %s:%s' % (login, auth['username'], auth['password']))
            if auth['spoofed']:
                self.text_log(auth['date_time'], '[SSH  ] Login was spoofed' %())
            
        self.login_success = True

    def login_failed(self, sensor):
        self.auth_attempts.append(sensor['session']['auth'])
        self.auth_log(sensor['session']['start_time'], sensor['session']['peer_ip'], sensor['session']['auth']['username'], sensor['session']['auth']['password'], False)

    def connection_lost(self, sensor):
        session = sensor['session']

        if self.login_success:
            self.text_log(session['end_time'], '[SSH  ] Lost Connection with %s' % (session['peer_ip']))
        if len(self.auth_attempts) == 0:
            self.auth_log(session['start_time'], session['peer_ip'], '', '', False)

    def channel_opened(self, sensor):
        channel = sensor['session']['channel']
        self.text_log(channel['start_time'], '%s Opened Channel' % (channel['name']))

    def channel_closed(self, sensor):
        channel = sensor['session']['channel']
        self.text_log(channel['end_time'], '%s Closed Channel' % (channel['name']))
        
    def command_entered(self, sensor):
        channel = sensor['session']['channel']
        command = channel['command']
        command_string = command['command'].replace('\n', '\\n')
        if command['success']:
            outcome = 'Executed'
        else:
            outcome = 'Blocked'
        self.text_log(command['date_time'], '%s Command %s: %s' % (channel['name'], outcome, command_string))
        
    def download_finished(self, sensor):
        channel = sensor['session']['channel']
        download = channel['download']
        self.text_log(download['end_time'], '%s Downloaded: %s - Saved: %s - Size: %s - SHA256: %s' % (channel['name'], download['link'], download['file'], str(download['size']), download['sha256']))
        self.download_log(download['end_time'], sensor['session']['peer_ip'], download['link'], download['size'], download['sha256'], download['file'])
        
    def validate_config(self):
        props = [['output-txtlog','enabled']]
        for prop in props:
            if not config.checkExist(self.cfg,prop) or not config.checkValidBool(self.cfg, prop):
                return False
        return True

    def text_log(self, dt, message):
        self.log_to_file(self.log_file, '%s - %s\n' % (dt, message))

    def auth_log(self, dt, ip, username, password, success): 
        self.log_to_file(self.auth_log_file, '%s,%s,%s,%s,%s\n' % (dt,ip,username,password,success))
            
    def download_log(self, dt, ip, link, size, sha256, file):
        download_log_file = self.cfg.get('folders', 'log_path') + '/downloads.log'
        self.log_to_file(download_log_file, '%s,%s,%s,%s,%s,%s\n' % (dt, ip, link, size, sha256, file))
        
    def log_to_file(self, the_file, string):
        setPermissions = False
        
        if(os.path.isfile(the_file) == False):
            setPermissions = True
        
        f = file(the_file, 'a')
        f.write(string)
        f.close()
    
        if(setPermissions):
            os.chmod(the_file, 0644)