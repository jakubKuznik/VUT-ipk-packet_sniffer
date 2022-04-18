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
    pcap_t *sniff_int;       // interface where packet will be sniffed 
    char error_message[PCAP_ERRBUF_SIZE];

    // parse args and store them to settings struct 
    parse_args(argc, argv, &sett);
    debug_sett(&sett);

    // open interface for sniffing //exit program if error 
    sniff_int = open_int(error_message, sett.interface);

    // create filter ------> sniff 
    
    // sniff n packet
    for (int i = 0; i < sett.n; i++){
        //create_filter();
        handle_frame(sniff_int); 
    }


    // close interface
    pcap_close(sniff_int);

        
    return 0;
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
