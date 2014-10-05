/*--------------------------------------------------------------------------------------------------------------
--	SOURCE FILE:		utils.c - utility functions for the client program.
--
--	PROGRAM:		    client
--
--	FUNCTIONS:		    See function descriptions below
--
--	LAST MODIFIED:		October 6, 2014
--
--	DESIGNERS:	        Slade Solobay & Zach Smoroden
--
--	PROGRAMMERS:        Slade Solobay & Zach Smoroden
--
--------------------------------------------------------------------------------------------------------------*/

#include "client.h"

/*--------------------------------------------------------------------------------------------------------------
--	FUNCTION:		    csum
--
--	INTERFACE:	unsigned short csum (unsigned short *ptr, int nbytes)
--
--				unsigned short *ptr - a pointer to an array that contains the payload over which the checksum is
--                  calculated.
--				int nbytes - the total length of the header
--
--	RETURNS:	The calaculated checksum
--
--	DATE:		November 23, 2006
--
--	REVISIONS:	(Date and Description)
--
--	DESIGNER:	RFC 791
--
--	PROGRAMMER:	RFC 791
--
--	NOTES:
--	See RFC 791 for more information
--
--------------------------------------------------------------------------------------------------------------*/
unsigned short csum (unsigned short *ptr,int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}

/*--------------------------------------------------------------------------------------------------------------
--	FUNCTION:	    encrypt
--
--	INTERFACE:	    char* encrypt(char* key, char* string)
--
--				    char* key - a string containing the encryption key used for XOR
--				    char* string - the string to be encrypted
--
--	RETURNS:	    The encrypted string
--
--	LAST MODIFIED:		    October 6, 2014
--
--	DESIGNERS:	    Slade Solobay & Zach Smoroden
--
--	PROGRAMMERS:	Slade Solobay & Zach Smoroden
--
--	NOTES:
--	Encypts and decryptes data send over a packet.
--
--------------------------------------------------------------------------------------------------------------*/
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

//Displays usage message
void usage (char **argv)
{
      fprintf(stderr, "Usage: %s -d <Destination IP> -p [Destination Port] -h [Source IP] -s [Source Port] -i [Interface]\n", argv[0]);
      fprintf(stderr, "You must specify the destination address!\n");
      exit(1);
}