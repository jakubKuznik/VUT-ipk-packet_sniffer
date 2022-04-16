// Solution for IPK-packet-sniffer, 16.4.2022
// File:        args.c
// Author:      Jakub Kuzník, FIT
// Compiled:    gcc 9.9.3.0
// Read file arguments 

#include "args.h"

void parse_args(int argc, char *argv[]){
    
    for (int i = 0; i < argc; i++){
        
        // help message 
        if ((strcmp(argv[i], "-h") == 0 ) || (strcmp(argv[i], "--help") == 0)) {
            printf("./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port}");
            printf("{[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n");
        }
        // interface 
        else if ((strcmp(argv[i], "-i") == 0) || (strcmp(argv[i], "--interface") == 0)) {
            printf("interface");
        }
        // port
        // -p port 
        else if (strcmp(argv[i], "-p") == 0) {
            printf("port");
        }
        // protocol tcp 
        else if ((strcmp(argv[i], "--tcp") == 0) || (strcmp(argv[i], "-t") == 0)) {
            printf("tcp");
        }
        // protocol udp 
        else if ((strcmp(argv[i], "--udp") == 0) || (strcmp(argv[i], "-u") == 0)) {
            printf("udp");
        }
        // protocol arp
        else if (strcmp(argv[i], "--arp") == 0) {
            printf("arp");
        }
        // protocol icmp 
        else if (strcmp(argv[i], "--icmp") == 0) {
            printf("icmp");
        }
        // number of packets
        // -n num 
        else if (strcmp(argv[i], "-n") == 0) {
            printf("icmp");
        }
        // unknown 
        else {
            fprintf(stderr, "Unknown parram");
        }
    }
}