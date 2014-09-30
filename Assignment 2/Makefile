# Makefile for client

CC=gcc -Wall -ggdb

client: client.o chksum.o
	$(CC) -o client client.o chksum.o

clean:
	rm -f *.o core.* client

client.o:
	$(CC) -c client.c

chksum.o: 
	$(CC) -c chksum.c