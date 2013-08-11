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