#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/udp.h>   	// UDP Header definitions
#include <netinet/ip.h>    	// IP Header definitions
#include <sys/types.h>
#include <unistd.h>

#define PKT_SIZE		    4096
#define DEFAULT_DST_PORT	8080
#define DEFAULT_SRC_PORT	11234
#define DEFAULT_TTL		    255
#define DEFAULT_IP_ID		12345
#define DEFAULT_SRC_IP		"192.168.1.5"
#define OPTIONS 		    "?h:d:s:p:c:"
#define ENCRYPTION_KEY      "zdehjk"

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

// Function Prototypes
void send_packet(struct AddrInfo *UserAddr);
char* encrypt(char *key, char *string);
void usage (char **arg );
unsigned short csum (unsigned short *, int);
