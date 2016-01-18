import ConfigParser
from twisted.python import log

PLAIN = '\033[0m'
RED = '\033[0;31m'
LRED = '\033[1;31m'
GREEN = '\033[0;32m'
LGREEN = '\033[1;32m'
YELLOW = '\033[0;33m'
LYELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
LBLUE = '\033[1;34m'
PURPLE = '\033[0;35m'
LPURPLE = '\033[1;35m'
CYAN = '\033[0;36m'
LCYAN = '\033[1;36m'

cfg = ConfigParser.ConfigParser()
cfg.read('honssh.cfg')

def msg(color, identifier, message):
    
    if not isinstance(message, basestring):
        message = repr(message)

    if cfg.has_option('devmode', 'enabled'):   
        if cfg.get('devmode', 'enabled') == 'true':
            log.msg(color + identifier +  ' - ' + message + '\033[0m')
    else:
        log.msg(identifier +  ' - ' + message)
