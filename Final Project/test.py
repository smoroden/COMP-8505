
from scapy.all import *

command = 'this is a test'
dest_ip = '192.168.0.9'
CHANNEL = 80

send(IP(dst=dest_ip) / UDP(sport=4444, dport=CHANNEL) / "Somethign")




