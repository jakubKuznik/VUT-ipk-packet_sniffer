// Solution for IPK-packet-sniffer, 16.4.2022
// File:        second.c
// Author:      Jakub Kuzník, FIT
// Compiled:    gcc 9.9.3.0
// Main file 

// Execution:
// ./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} 
//               {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}

#include "ipk-sniffer.h"


int main(int argc, char *argv[]) {

    settings sett;           // program settings structure  
    char error_message[PCAP_ERRBUF_SIZE];
    struct sigaction sigIntHandler;  // signal handler 

    // parse args and store them to settings struct 
    parse_args(argc, argv, &sett);
    debug_sett(&sett);

    // open interface for sniffing //exit program if error 
    sniff_int = open_int(error_message, sett.interface);

    // SIGINT signal handler
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_handler = free_resources;
    sigIntHandler.sa_flags = 0;

    // sniff n packet
    for (int i = 0; i < sett.n; i++){
        //create_filter();
        sigaction(SIGINT, &sigIntHandler, NULL);
        handle_frame(sniff_int); 
    }


    // close interface
    pcap_close(sniff_int);

        
    return 0;
}


/**
 * Free resource after signal SIGINT  
 */
void free_resources(int sig_num){
  
    // close socket etc.
    fprintf(stderr, "[signal %d] -> Process killed\n", sig_num);
    pcap_close(sniff_int);
    exit(1); 
}

// TODO smazat 
void debug_sett(settings *sett){
    fprintf(stderr,"...n:         %d\n",sett->n );
    fprintf(stderr,"...arp:       %d\n",sett->arp);
    fprintf(stderr,"...icmp:      %d\n",sett->icmp);
    fprintf(stderr,"...udp:       %d\n",sett->udp);
    fprintf(stderr,"...tcp        %d\n", sett->tcp);
    fprintf(stderr,"...interface: %s\n", sett->interface);
    fprintf(stderr,"...port:      %d\n", sett->port);
}
