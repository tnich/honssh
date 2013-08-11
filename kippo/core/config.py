# Copyright (c) 2009 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import ConfigParser, os

def config():
    cfg = ConfigParser.ConfigParser()
    if os.path.exists('honssh.cfg'):
        cfg.read('honssh.cfg')
        return cfg
    return None
