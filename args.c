// Solution for IPK-packet-sniffer, 16.4.2022
// File:        args.c
// Author:      Jakub Kuzník, FIT
// Compiled:    gcc 9.9.3.0
// Read file arguments 

#include "args.h"

/**
 * Get throught arguments and store them to settings struct  
 * ./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} 
 *               {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}
 * 
 * ! if invalid exit program with exit code 2 
 * 
 */
void parse_args(int argc, char *argv[], settings *sett){
    
    bool i_once = false;
    bool p_once = false;
    bool n_once = false;
    
    // no arguments // just print interfaces  
    if (argc == 1){
        print_interfaces();
        exit(0);
    }

    for (int i = 1; i < argc; i++){
        
        // help message 
        if ((strcmp(argv[i], "-h") == 0 ) || (strcmp(argv[i], "--help") == 0)) {
            printf("./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port}");
            printf("{[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n");
            exit(0);
        }
        // interface 
        else if ((strcmp(argv[i], "-i") == 0) || (strcmp(argv[i], "--interface") == 0)) {
            if (i_once == true)
                goto error_args;

            if (i+1 < argc){ // store interface to settings struct
                 
                strncpy(sett->interface, argv[++i], INTERFACE_NAME_MAX);
                continue;
            }
            else{ // just print interfaces 
                //printf("d");
                print_interfaces();
                exit(0);
            }
        }
        // port
        // -p port 
        else if (strcmp(argv[i], "-p") == 0) {
            fprintf(stderr,"port\n");
        }
        // protocol tcp 
        else if ((strcmp(argv[i], "--tcp") == 0) || (strcmp(argv[i], "-t") == 0)) {
            fprintf(stderr,"tcp\n");
        }
        // protocol udp 
        else if ((strcmp(argv[i], "--udp") == 0) || (strcmp(argv[i], "-u") == 0)) {
            fprintf(stderr,"udp\n");
        }
        // protocol arp
        else if (strcmp(argv[i], "--arp") == 0) {
            fprintf(stderr,"arp\n");
        }
        // protocol icmp 
        else if (strcmp(argv[i], "--icmp") == 0) {
            fprintf(stderr,"icmp\n");
        }
        // number of packets
        // -n num 
        else if (strcmp(argv[i], "-n") == 0) {
            fprintf(stderr,"icmp\n");
        }
        // unknown 
        else {
            fprintf(stderr, "Unknown parram\n");
            exit(0);
        }
    }

    return;

error_args:
    fprintf(stderr, "Invalid args\n");
    exit(2);


}