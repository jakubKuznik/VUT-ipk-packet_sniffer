// Solution for IPK-packet-sniffer, 16.4.2022
// File:        second.c
// Author:      Jakub Kuzník, FIT
// Compiled:    gcc 9.9.3.0
// File description

#pragma once
// normal libraries 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>

// network libraries
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> //ethernet and arp frame 
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// struct typedef  
typedef struct settings settings;

#include "args.h"
#include "interfaces.h"
#include "frame.h"

#define INTERFACE_NAME_MAX 256


/**
 * Setting struct declare how'll program behave 
 */
struct settings{

    int n;               // number of packet that will be shown
    bool arp;            // arp enable
    bool icmp;           // icmp enable 
    bool udp;            // udp enable 
    bool tcp;            // tcp enable 
                // name of interface where packet will be sniffed 
    char interface[INTERFACE_NAME_MAX]; 
    int port;            // Accept packet only on given port
                         // -1 if all ports 
};

// todo smazat 
void debug_sett(settings *sett);


/**
 * Free resource after signal SIGINT  
 */
void free_resources(int sig_num);
  