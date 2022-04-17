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
        return false;
    } 
    
    // get throught all interfaces 
    while (inter_list != NULL){
        // interface find 
        if(strcmp(inter_list->name, int_name) == 0){
            return true;
        }  
        inter_list = inter_list->next;
    }

    pcap_freealldevs(inter_list);
    return false;
}