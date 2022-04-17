CC = gcc
LD = gcc

CFLAGS = -g -std=c11 -pedantic -Wall -Wextra -lpcap -D_BSD_SOURCE -D_DEFAULT_SOURCE
all: ipk-sniffer 

##########################################################################

ipk-sniffer: interfaces.o args.o ipk-sniffer.o
	gcc $(CFLAGS) interfaces.o args.o ipk-sniffer.o -o ipk-sniffer

ipk-sniffer.o: ipk-sniffer.c ipk-sniffer.h interfaces.h
	gcc $(CFLAGS) -c ipk-sniffer.c -o ipk-sniffer.o

args.o: args.c args.h 
	gcc $(CFLAGS) -c args.c -o args.o

interfaces.o: interfaces.c interfaces.h 
	gcc $(CFLAGS) -c interfaces.c -o interfaces.o

clean:
	rm *.o ipk-sniffer

run: ipk-sniffer
	./ipk-sniffer