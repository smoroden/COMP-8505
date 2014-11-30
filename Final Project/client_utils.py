# --------------------------------------------------------------------------------------------------------------------
#  SOURCE FILE:		   client_utils.py - Contains utility functions and default values used by client.py.
#
#  PROGRAM:		       client
#
#  LAST MODIFIED:	   November 27, 2014
#
#  DESIGNERS:	       Slade Solobay & Zach Smoroden
#
#  PROGRAMMERS:        Slade Solobay & Zach Smoroden
#
#
# --------------------------------------------------------------------------------------------------------------------
from itertools import izip, cycle


# ------------------- USER DEFINED VARIABLE --------------------------------------------------------------------------
DEFAULT_INTERFACE = 'em1'
DEFAULT_SRC_PORT = 443
DEFAULT_DST_PORT = 80
DEFAULT_LISTENER = 80
DEFAULT_SRC_IP = "192.168.0.5"

ENCRYPTION_KEY = "zdehjk"
# Name of file containing outputted packet data
FILENAME = "secrets.txt"
# --------------------------------------------------------------------------------------------------------------------

# Globals used for port knocking
KNOCKSEQUENCE = 0
PACKET_LEN = 0
PACKETS_RCVD = 0


# Set Default Values for packet struct
packet = {
    'interface': DEFAULT_INTERFACE,
    'sport': DEFAULT_SRC_PORT,
    'dport': DEFAULT_DST_PORT,
    'src': DEFAULT_SRC_IP,
    'dest': None,
    'cmd': None
}


# --------------------------------------------------------------------------------------------------------------------
#   FUNCTION:       usage
#
#   RETURNS:
#
#   LAST MODIFIED:  November 16, 2014
#
#   DESIGNERS:	    Slade Solobay & Zach Smoroden
#
#   PROGRAMMERS:    Slade Solobay & Zach Smoroden
#
#   NOTES:
#                   Will print and and display program usage message.
#
# --------------------------------------------------------------------------------------------------------------------
def usage():
    print("Usage: %s -d <Destination IP> -p [Destination Port] -b [Source IP] -s [Source Port] -i [Interface]")
    print("You must specify the destination IP!")
    print("You must provide a config file, 'port_conf', in the project root directory!")
    return


# --------------------------------------------------------------------------------------------------------------------
#   FUNCTION:       xor_crypt
#
#   INTERFACE:      xor_crypt(data, ENCRYPTION_KEY=ENCRYPTION_KEY)
#                   data:   The payload of the packet sent from the client that contains the
#                          command to execute
#                   ENCRYPTION_KEY:    The encryption ENCRYPTION_KEY.
#                                     Defaults to the user-defined variable ENCRYPTION_KEY
#
#   RETURNS:        The encoded or decoded data.
#
#   LAST MODIFIED:  October 6, 2014
#
#   DESIGNERS:	    Slade Solobay & Zach Smoroden
#
#   PROGRAMMERS:    Slade Solobay & Zach Smoroden
#
#   NOTES:
#                   Use this function for both encryption and decryption. only one of encode/decode needs to be
#          specified in the call.
#
# --------------------------------------------------------------------------------------------------------------------
def xor_crypt(data, ENCRYPTION_KEY=ENCRYPTION_KEY):
    message = ''.join(chr(ord(c) ^ ord(k)) for c, k in izip(data, cycle(ENCRYPTION_KEY)))
    return message
