
class my_globals_cls(object):
    # the issuer appears in introspection results, can be any string
    TOKEN_ISSUER = 'https://github.com/downtownallday/mailinabox-ldap'

    # instance of a Storage class for persisting codes and tokens
    storage = None


G = my_globals_cls()

def init_server_globals(storage_inst, issuer):
    G.storage = storage_inst
    G.TOKEN_ISSUER = issuer

