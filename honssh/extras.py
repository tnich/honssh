# Copyright (c) 2013 Thomas Nicholson <tnnich@googlemail.com>
# See the COPYRIGHT file for more information
# Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.


from kippo.core.config import config


def attemptedLogin(username, password):
    cfg = config()
    if cfg.get('extras', 'voice') == 'true':
        from espeak import espeak
        espeak.synth("Attempted login using: %s and %s" % (username, password))

def successLogin(endIP):
    cfg = config()
    if cfg.get('extras', 'voice') == 'true':
        from espeak import espeak
        espeak.synth("Successful login from: %s" % endIP)
