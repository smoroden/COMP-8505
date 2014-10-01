#include "client.h"

int main (int argc, char **argv)
{
    struct AddrInfo UserInfo;
    struct AddrInfo *Addr_Ptr;
    int arg, opt;

    if (argc < 3)
    {
        usage(argv);
    }

    Addr_Ptr = &UserInfo;
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

    //Create a raw socket
    Addr_Ptr->RawSocket = socket (PF_INET, SOCK_RAW, IPPROTO_UDP);

    // Set SO_REUSEADDR so that the port can be resused for further invocations of the application
    arg = 1;
    if (setsockopt (Addr_Ptr->RawSocket, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg)) == -1)
        perror("setsockopt");

    send_packet(Addr_Ptr);

    return 0;
}

void send_packet(struct AddrInfo *UserAddr)
{
    char datagram[PKT_SIZE], *data, *pseudogram;; 	// set the Datagram (packet) size
    struct iphdr *iph = (struct iphdr *) datagram;	 //IP header
    struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));	//UDP header
    struct sockaddr_in sin;
    pseudo_header psh;
    printf("%s\n", UserAddr->DstHost);
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

    int psize = sizeof(pseudo_header) + sizeof(struct udphdr) + strlen(data);
    pseudogram = malloc(psize);

    memcpy(pseudogram , (char*) &psh , sizeof (pseudo_header));
    memcpy(pseudogram + sizeof(pseudo_header) , udph , sizeof(struct udphdr) + strlen(data));

    udph->check = csum( (unsigned short*) pseudogram , psize);

    //Send the packet
    if (sendto (UserAddr->RawSocket, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
    	perror ("sendto");
    }
    else
    {
        printf("Packet Sent!\n");
    }
}

//XOR Encryption
char* encrypt(char* key, char* string)
{
    int i, string_length = strlen(string);
    for(i=0; i<string_length; i++)
    {
        string[i]=string[i]^key[i];
    }
    return string;
}

void usage (char **argv)
{
      fprintf(stderr, "Usage: %s -d <Destination IP> -p [Destination Port] -h [Source IP] -s [Source Port] -c [Command]\n", argv[0]);
      fprintf(stderr, "You must specify the destination address and a command!\n");
      exit(1);
}
