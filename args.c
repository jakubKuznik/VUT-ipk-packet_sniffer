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

    // check if some args occure more than once  
    bool i_once = false;
    bool p_once = false;
    bool n_once = false;
    
    // set to true if icmp tcp udp or arp is in args 
    bool protocol_specified = false;

    // set default struct values 
    sett->port = -1;
    sett->n    = 1;


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
            
            i_once = true;

            if (i+1 < argc){ // store interface to settings struct
                // interface does not exist 
                if (interface_exist(argv[++i]) == false)
                    goto error_interface;

                strncpy(sett->interface, argv[i], INTERFACE_NAME_MAX);
                continue;
            }
            else{ // just print interfaces 
                print_interfaces();
                exit(0);
            }
        }
        // port
        // -p port 
        else if (strcmp(argv[i], "-p") == 0) {
            if (p_once == true)
                goto error_args;
            p_once = true;
            
            if (i+1 < argc){ // store port number to settings struct
                if(is_number(argv[++i]) == false)
                    goto error_port;
                sett->port = atoi(argv[i]);
                continue;
            }
            else{ // just print interfaces 
                goto error_args;
            }
        }
        // protocol tcp 
        else if ((strcmp(argv[i], "--tcp") == 0) || (strcmp(argv[i], "-t") == 0)) {
            protocol_specified = true;
            sett->tcp = true;
        }
        // protocol udp 
        else if ((strcmp(argv[i], "--udp") == 0) || (strcmp(argv[i], "-u") == 0)) {
            protocol_specified = true;
            sett->udp = true;
        }
        // protocol arp
        else if (strcmp(argv[i], "--arp") == 0) {
            protocol_specified = true;
            sett->arp = true;
        }
        // protocol icmp 
        else if (strcmp(argv[i], "--icmp") == 0) {
            protocol_specified = true;
            sett->icmp = true;
        }
        // number of packets
        // -n num 
        else if (strcmp(argv[i], "-n") == 0) {
            if (n_once == true)
                goto error_args;
            n_once = true;
            
            if (i+1 < argc){ // store port number to settings struct
                if(is_number(argv[++i]) == false)
                    goto error_port;
                sett->n = atoi(argv[i]);
                continue;
            }
            else{ // just print interfaces 
                goto error_args;
            }
        }
        // unknown 
        else {
            goto error_args;
        }
    }

    // if there is no protocol specified 
    if(protocol_specified == false){
        sett->arp  = true;
        sett->icmp = true;
        sett->tcp  = true;
        sett->udp  = true; 
    }

    

    return;

error_port:
    fprintf(stderr, "Expect an number\n");
    exit(2);

error_interface:
    fprintf(stderr, "Interface does not exist\n");
    exit(2);


error_args:
    fprintf(stderr, "Invalid args\n");
    exit(2);


}

/**
 * Check if string is digit  
 */
bool is_number(char *str){
    for (int i = 0; str[i] != '\0'; i++){
        if(isdigit(str[i]) == 0){
            return false;
        }
    }
    return true;
}