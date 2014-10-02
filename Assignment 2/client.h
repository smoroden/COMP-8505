#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/udp.h>   	// UDP Header definitions
#include <netinet/ip.h>    	// IP Header definitions
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#define PKT_SIZE		    4096
#define DEFAULT_DST_PORT	8080
#define DEFAULT_SRC_PORT	11234
#define DEFAULT_TTL		    255
#define DEFAULT_IP_ID		12345
#define MAXLINE			    80
#define DEFAULT_SRC_IP		"192.168.0.5"
#define OPTIONS 		    "?h:d:s:p:c:"
#define ENCRYPTION_KEY      "zdehjk"
#define FILTER              "udp and src host %s and src port %d and dst port %d"


// Globals
typedef struct    //needed for checksum calculation
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short udp_length;
    struct udphdr udp;
}pseudo_header;

struct AddrInfo
{
    int RawSocket;
    char *DstHost;
    char *SrcHost;
    int dport;
    int sport;
    char *cmd;
};

typedef struct
{
    pcap_t* nic_descr;
    bpf_u_int32 netp;
    char cmd[MAXLINE];
}PcapInfo;

// Function Prototypes
void send_packet(struct AddrInfo *UserAddr);
void receive_packet(PcapInfo *pcap_arg);
void pkt_callback (u_char *ptr_null, const struct pcap_pkthdr* pkthdr, const u_char *packet);
char* encrypt(char *key, char *string);
void usage (char **arg );
unsigned short csum (unsigned short *, int);

