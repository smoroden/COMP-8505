#include "client.h"

int main (int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct AddrInfo *Addr_Ptr;
    PcapInfo *pcap_ptr;
    char *nic_dev = "em1";
    int arg, opt;
    bpf_u_int32 maskp;          // subnet mask

    memset(errbuf,0,PCAP_ERRBUF_SIZE);


    if (argc < 3)
    {
        usage(argv);
    }

    if ((Addr_Ptr = malloc (sizeof (struct AddrInfo))) == NULL)
    {
        perror ("malloc");
        exit (1);
    }

    // Set the default values
    Addr_Ptr->SrcHost = DEFAULT_SRC_IP;		// Deafult Source IP
    Addr_Ptr->DstHost = NULL;			    // Must be specified by user!
    Addr_Ptr->dport = DEFAULT_DST_PORT;		// Default Destination Port
    Addr_Ptr->sport = DEFAULT_SRC_PORT;		// Default Source Port
    Addr_Ptr->cmd = NULL;                   // Must be specified by user!

    // Process command line options
    while ((opt = getopt (argc, argv, OPTIONS)) != -1)
    {
    	switch (opt)
    	{
    	    case 'h':
    	        Addr_Ptr->SrcHost = optarg;
    	    break;

    	    case 'd':
    	        Addr_Ptr->DstHost = optarg;		// Destination Host name
    	    break;

    	    case 'p':
    	        Addr_Ptr->dport = atoi (optarg);
    	    break;

    	    case 's':
    	        Addr_Ptr->sport = atoi (optarg);
    	    break;

            case 'c':
                Addr_Ptr->cmd = optarg;
            break;

    	    default:
    	      case '?':
    	        usage (argv);
    	    break;
    	}
    }

    if (Addr_Ptr->DstHost == NULL || Addr_Ptr->cmd == NULL)
    	usage (argv);

    // set up the packet capture structure and thread
    if ((pcap_ptr = malloc (sizeof (PcapInfo))) == NULL)
    {
    	perror ("malloc");
    	exit (1);
    }

    // Use pcap to get the IP address and subnet mask of the device
    pcap_lookupnet (nic_dev, &pcap_ptr->netp, &maskp, errbuf);

    // open device for reading

    // set the device in promiscuous mode
    pcap_ptr->nic_descr = pcap_open_live (nic_dev, BUFSIZ, 1, -1, errbuf);
    if (pcap_ptr->nic_descr == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }

    // Compile the filter expression
    snprintf (pcap_ptr->cmd, sizeof(pcap_ptr->cmd), FILTER, Addr_Ptr->DstHost, Addr_Ptr->dport, Addr_Ptr->sport);

    //Create a raw socket
    Addr_Ptr->RawSocket = socket (PF_INET, SOCK_RAW, IPPROTO_UDP);

    // Set SO_REUSEADDR so that the port can be resused for further invocations of the application
    arg = 1;
    if (setsockopt (Addr_Ptr->RawSocket, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg)) == -1)
        perror("setsockopt");

    send_packet(Addr_Ptr);
    receive_packet(pcap_ptr);
    free (Addr_Ptr);
    free (pcap_ptr);
    return 0;
}

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
        printf("Packet Sent!\n");
    }
}

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
    pcap_loop (pcap_ptr->nic_descr, -1, pkt_callback, NULL);
}

void pkt_callback (u_char *ptr_null, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	static int count = 1;
	int len, size_payload;
	struct ethhdr *ethernet_header;
	struct iphdr *ip_header;
	struct udphdr *udp_header;
	char *payload;                    //packet payload

	fprintf(stdout,"\nPacket Number: %d\n", count);
	fflush(stdout);
    	count++;

	// Ensure that there are enough bytes to make up the complete set of headers

	if ((len = (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))) > 28)
	{
		/* Do all the checks: 1. Is it an IP pkt ? 2. is it UDP ? */

		ethernet_header = (struct ethhdr *)packet;

		if(ntohs(ethernet_header->h_proto) == ETH_P_IP)
		{
			ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));

			if(ip_header->protocol == IPPROTO_UDP)
			{
				udp_header = (struct udphdr*)(packet + sizeof(struct ethhdr) + ip_header->ihl*4);

                // define/compute udp payload (segment) offset
                payload = (u_char *)(packet + sizeof(struct ethhdr) + ip_header->ihl*4 + sizeof(struct udphdr));

                // compute udp payload (segment) size
                size_payload = ntohs(ip_header->tot_len) - (sizeof(struct iphdr) + sizeof(struct udphdr));

                //Print payload data; it might be binary, so don't just treat it as a string.
                if (size_payload > 0) {
                    printf("Payload (%d bytes):\n %d \n", size_payload, len);
                    //http://www.tcpdump.org/sniffex.c
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
}

//XOR Encryption
char* encrypt(char* key, char* string)
{
    int i,j = 0, string_length = strlen(string);
    for(i=0; i<string_length; i++, j++)
    {
        if(j == (strlen(key) - 1))
            j=0;
        string[i]=string[i]^key[j];
    }
    return string;
}

void usage (char **argv)
{
      fprintf(stderr, "Usage: %s -d <Destination IP> -p [Destination Port] -h [Source IP] -s [Source Port] -c [Command]\n", argv[0]);
      fprintf(stderr, "You must specify the destination address and a command!\n");
      exit(1);
}
