CC = gcc
LD = gcc

CFLAGS = -g -std=c11 -pedantic -Wall -Wextra -lpcap -D_BSD_SOURCE -D_DEFAULT_SOURCE
all: ipk-sniffer 

##########################################################################
ipk-sniffer: args.o ipk-sniffer.h ipk-sniffer.c
	gcc $(CFLAGS) args.o ipk-sniffer.c -o ipk-sniffer

args.o: args.c args.h 
	gcc $(CFLAGS) -c args.c -o args.o

clean:
	rm *.o main

run: ipk-sniffer
	./ipk-sniffer