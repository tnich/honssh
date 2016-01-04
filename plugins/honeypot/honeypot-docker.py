from honssh import config

from docker import Client

from twisted.python import log

class Plugin():
    
    def __init__(self, cfg):
        self.cfg = cfg
        
    def get_connection_details(self, conn_details):
        
        socket = self.cfg.get('honeypot-docker', 'uri')
        image = self.cfg.get('honeypot-docker', 'image')
        launch_cmd = self.cfg.get('honeypot-docker', 'launch_cmd')
        hostname = self.cfg.get('honeypot-docker', 'hostname')
        honey_port = int(self.cfg.get('honeypot-docker', 'honey_port'))

        self.docker_drive = docker_driver(socket, image, launch_cmd, hostname)
        log.msg(self.docker_drive)
        self.container = self.docker_drive.launch_container()

        log.msg("[PLUGIN][DOCKER] Launched container (%s, %s)" % (self.container['ip'], self.container['id']))
        sensor_name = self.container['id']
        honey_ip = self.container['ip']
        
        return {'success':True, 'sensor_name':sensor_name, 'honey_ip':honey_ip, 'honey_port':honey_port}
    
    def connection_lost(self, conn_details):
        log.msg("[PLUGIN][DOCKER] Stopping container (%s, %s)" % (self.container['ip'], self.container['id']))
        self.docker_drive.teardown_container()
        
    def validate_config(self):
        props = [['honeypot-docker','enabled'], ['honeypot-docker','pre-auth'], ['honeypot-docker','post-auth']]
        for prop in props:
            if not config.checkExist(self.cfg,prop) or not config.checkValidBool(self.cfg, prop):
                return False
            
        props = [['honeypot-docker','image'], ['honeypot-docker','uri'], ['honeypot-docker','hostname'], ['honeypot-docker','launch_cmd'], ['honeypot-docker','honey_port']]
        for prop in props:
            if not config.checkExist(self.cfg,prop):
                return False  

        return True    
    
    
class docker_driver():
    def __init__(self, socket, image, launch_cmd, hostname):
        self.socket = socket
        self.image = image
        self.hostname = hostname
        self.launch_cmd = launch_cmd
        self.make_connection()
    
    def make_connection(self):
        self.connection = Client(self.socket)
        
    def launch_container(self):
        self.container_id = self.connection.create_container(image=self.image, tty=True, hostname=self.hostname)['Id']
        self.connection.start(self.container_id)
        exec_id = self.connection.exec_create(self.container_id, self.launch_cmd)['Id']
        self.connection.exec_start(exec_id, tty=True)
        self.container_data = self.connection.inspect_container(self.container_id)
        return {"id": self.container_id,
                "ip": self.container_data['NetworkSettings']['Networks']['bridge']['IPAddress']}
              
    def teardown_container(self):
        self.connection.stop(self.container_id)