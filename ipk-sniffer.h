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

// network libraries
#include <pcap.h>
#include <arpa/inet.h>

// struct typedef  
typedef struct settings settings;


#include "args.h"

/**
 * Setting struct declare how'll program behave 
 */
struct settings{

    int n;               // number of packet that will be shown
    int packet_counter;  // number of packets that has been shown 
    bool arp;            // arp enable
    bool icmp;           // icmp enable 
    bool udp;            // udp enable 
    bool tcp;            // tcp enable 
    char interface[255]; // name of interface where packet will be sniffed 
    int port;            // Accept packet only on given port
                         // -1 if all ports 
};

// todo smazat 
void debug_sett(settings *sett);