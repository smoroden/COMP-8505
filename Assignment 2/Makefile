# Makefile for client

CC=gcc -Wall -ggdb
CLIB=-lpcap

client: client.o chksum.o
	$(CC) -o client client.o chksum.o $(CLIB)

clean:
	rm -f *.o core.* client

client.o:
	$(CC) -c client.c

chksum.o: 
	$(CC) -c chksum.c