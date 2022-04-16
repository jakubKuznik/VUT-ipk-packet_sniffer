CC = gcc
LD = gcc

CFLAGS = -g -std=c11 -pedantic -Wall -Wextra
all: ipk-sniffer 

##########################################################################
ipk-sniffer: second.o ipk-sniffer.h ipk-sniffer.c
	gcc $(CFLAGS) second.o ipk-sniffer.c -o ipk-sniffer

second.o: second.c second.h 
	gcc $(CFLAGS) -c second.c -o second.o

clean:
	rm *.o main

run: ipk-sniffer
	./ipk-sniffer