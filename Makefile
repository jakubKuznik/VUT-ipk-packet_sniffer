CC = gcc
LD = gcc

CFLAGS = -g -std=c11 -pedantic -Wall -Wextra -D_BSD_SOURCE -D_DEFAULT_SOURCE 
all: ipk-sniffer 

##########################################################################

ipk-sniffer: interfaces.o args.o ipk-sniffer.o frame.o
	gcc $(CFLAGS) interfaces.o args.o frame.o ipk-sniffer.o -o ipk-sniffer -lpcap

ipk-sniffer.o: ipk-sniffer.c ipk-sniffer.h 
	gcc $(CFLAGS) -c ipk-sniffer.c -o ipk-sniffer.o -lpcal

args.o: args.c args.h 
	gcc $(CFLAGS) -c args.c -o args.o -lpcap

interfaces.o: interfaces.c interfaces.h 
	gcc $(CFLAGS) -c interfaces.c -o interfaces.o -lpcap

frame.o: frame.c frame.h 
	gcc $(CFLAGS) -c frame.c -o frame.o -lpcap

clean:
	rm *.o ipk-sniffer

run: ipk-sniffer
	./ipk-sniffer