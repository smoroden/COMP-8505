import logging
##Suppress annoying scapy warning about IPV6
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import*
from client_utils import*

def sniff_packets(destination):
    return

def knock_sequence(data):
    # Open file as file object and read to string
    ifile = open("port_conf", 'r')
    # Read file object to string
    text = ifile.read()
    # Close file object
    ifile.close()

    port_regex = re.compile(r'\d{1,5}(?=:)')
    password_regex = re.compile(r'(?<=:)\S{4}')
    ports = port_regex.findall(text)
    passwords = password_regex.findall(text)

    #count used with password list to match appropriate port
    count=0
    for port in ports:
        send(IP(dst=data['dest']) / UDP(sport=int(data['sport']), dport=int(port)) / xor_crypt(passwords[count]), verbose=0)
        count+=1
    return

def send_packet(data):
    knock_sequence(data)
    send(IP(dst=data['dest']) / UDP(sport=int(data['sport']), dport=int(packet['lport'])) / xor_crypt(packet['cmd']), verbose=0)
    return
