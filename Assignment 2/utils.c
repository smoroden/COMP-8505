#include "client.h"

// Public doman checksum function as per RFC 791
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

void usage (char **argv)
{
      fprintf(stderr, "Usage: %s -d <Destination IP> -p [Destination Port] -h [Source IP] -s [Source Port] -i [Interface]\n", argv[0]);
      fprintf(stderr, "You must specify the destination address!\n");
      exit(1);
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