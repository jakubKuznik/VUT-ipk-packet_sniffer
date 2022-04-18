// Solution for IPK-packet-sniffer, 16.4.2022
// File:        interfaces.c
// Author:      Jakub Kuzník, FIT
// Compiled:    gcc 9.9.3.0
// Functions for working with network interfaces  

#include "interfaces.h"

/**
 * Print all interfaces in system
 * exit with -3 if error 
 */
void print_interfaces(){
    pcap_if_t *inter_list;
    char error_message[PCAP_ERRBUF_SIZE];

    // returns 0 on succes PCAP_ERROR on failure 
    if(pcap_findalldevs(&inter_list, error_message) == PCAP_ERROR){
        fprintf(stderr,"%s",error_message);
        exit(3);
    } 
    // get throught all interfaces 
    while (inter_list != NULL){
        printf("%s\n",inter_list->name);
        inter_list = inter_list->next;
    }

    pcap_freealldevs(inter_list);
}

/**
 * Check if interface exist 
 *  return true if yes 
 *  return false if not or error  
 */
bool interface_exist(char *int_name){
    pcap_if_t *inter_list;
    char error_message[PCAP_ERRBUF_SIZE];

    // returns 0 on succes PCAP_ERROR on failure 
    if(pcap_findalldevs(&inter_list, error_message) == PCAP_ERROR){
        fprintf(stderr,"%s",error_message);
        pcap_freealldevs(inter_list);
        return false;
    } 
    
    // get throught all interfaces 
    while (inter_list != NULL){
        // interface find 
        if(strcmp(inter_list->name, int_name) == 0){
            pcap_freealldevs(inter_list);
            return true;
        }  
        inter_list = inter_list->next;
    }

    pcap_freealldevs(inter_list);
    return false;
}

/**
 * Open interface and set *err as erro message 
 * if open fail exit(2)
 * if interface does not support ethernet frame exit(2) 
 */
pcap_t *open_int(char *err, char *name){

    pcap_t *sniff_int; // interface where packet will be sniffed 

    // set promiscuous mode - all network data packets can be accessed
    // --- and viewed by all network adapters operating in this mode.
    sniff_int = pcap_open_live(name, MAX_FRAME_SIZE, true, TIMEOUT, err);
    if (sniff_int == NULL)
        goto error_interface;
    
    if(pcap_datalink(sniff_int) != DLT_EN10MB)
        goto error_ether_frame;



    return sniff_int;


error_interface:
    fprintf(stderr, "Cannot open interface\n");
    fprintf(stderr, "%s\n",err);
    exit(2);
error_ether_frame:
    fprintf(stderr, "Interface does not support Ethernet frame \n");
    exit(2);
}