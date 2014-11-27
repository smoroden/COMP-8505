from itertools import izip, cycle

###################### USER DEFINED VARIABLE ##########################
DEFAULT_INTERFACE = 'em1'
DEFAULT_SRC_PORT = 443
DEFAULT_DST_PORT = 80
DEFAULT_LISTENER = 80
DEFAULT_SRC_IP = "192.168.0.5"

ENCRYPTION_KEY = "zdehjk"

FILENAME = "secrets.txt"
######################################################################

# Set Default Values for packet struct
packet = {
    'interface': DEFAULT_INTERFACE,
    'sport': DEFAULT_SRC_PORT,
    'dport': DEFAULT_DST_PORT,
    'src': DEFAULT_SRC_IP,
    'dest': None,
    'cmd': None
}


def usage():
    print("Usage: %s -d <Destination IP> -p [Destination Port] -b [Source IP] -s [Source Port] -i [Interface]")
    print("You must specify the destination IP!")
    return


def xor_crypt(data, ENCRYPTION_KEY=ENCRYPTION_KEY):
    message = ''.join(chr(ord(c) ^ ord(k)) for c, k in izip(data, cycle(ENCRYPTION_KEY)))
    return message
