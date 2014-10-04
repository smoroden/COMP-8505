# Makefile for client

CC=gcc -Wall -ggdb
CLIB=-lpcap

client: client.o utils.o packet.o
	$(CC) -o client client.o utils.o packet.o $(CLIB)

clean:
	rm -f *.o core.* client

client.o:
	$(CC) -c client.c

chksum.o: 
	$(CC) -c utils.c

packet.o:
	$(CC) -c packet.c