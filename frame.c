// Solution for IPK-packet-sniffer, 16.4.2022
// File:        frame.c
// Author:      Jakub Kuzník, FIT
// Compiled:    gcc 9.9.3.0
// Functions for working with network ethernet frames  

#include "frame.h"


/**
 * 
 * Read one frame and print it in 
 *
 * if error exit program  
 *
 * @sniff_int - interface
 *
 * timestamp: 2021-03-19T18:42:52.362+01:00
 * src MAC: 00:1c:2e:92:03:80
 * dst MAC: 00:1b:3f:56:8a:00
 * frame length: 512 bytes
 * src IP: 147.229.13.223
 * dst IP: 10.10.10.56
 * src port: 4093
 * dst port: 80

 * 0x0000:  00 19 d1 f7 be e5 00 04  96 1d 34 20 08 00 45 00  ........ ..4 ..
 * 0x0010:  05 a0 52 5b 40 00 36 06  5b db d9 43 16 8c 93 e5  ..R[@.6. [..C....
 * 0x0020:  0d 6d 00 50 0d fb 3d cd  0a ed 41 d1 a4 ff 50 18  .m.P..=. ..A...P.
 * 0x0030:  19 20 c7 cd 00 00 99 17  f1 60 7a bc 1f 97 2e b7  . ...... .`z.....
 * 0x0040:  a1 18 f4 0b 5a ff 5f ac 07 71 a8 ac 54 67 3b 39  ....Z._. .q..Tg;9
 * 0x0050:  4e 31 c5 5c 5f b5 37 ed  bd 66 ee ea b1 2b 0c 26  N1.\_.7. .f...+.&
 * 0x0060:  98 9d b8 c8 00 80 0c 57  61 87 b0 cd 08 80 00 a1  .......W a.......
 */
void handle_frame(pcap_t *sniff_int){
    const u_char        *frame;          // packet
    struct pcap_pkthdr  pac_header;      // packet header
    struct ether_header *eth_header;     // ethernet  
    struct arphdr       *arp_header;     // arp header 
    struct ip           *ip_header;    
    struct tcphdr       *tcp_header; 
    struct udphdr       *udp_header; 
    char                addres_string[INET_ADDRSTRLEN];

    frame = pcap_next(sniff_int, &pac_header);
    eth_header = (struct ether_header *)frame;

    printf("----- frame --------\n");
    print_timestap(pac_header.ts);
    print_mac(eth_header->ether_shost, SRC);
    print_mac(eth_header->ether_dhost, DST);
    printf("frame lenght: %d\n",pac_header.len);
    
    // check protocol IP include ICMP 
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP){
        printf(".... ip .....\n");
        ip_header = (struct ip*)(frame + ETH_HEAD);

        printf("tu: %s\n",frame);

        printf("src IP: xxx\n");
        printf("dst IP: xxx\n");
        printf("src port: xxx\n");
        printf("dst port: xxx\n");
    }
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP){
        printf(".... arp ...\n");
        arp_header = (struct arphdr*)(frame + ETH_HEAD);
        print_arp(arp_header);
    }
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6){
        printf(".... ipv6 ....\n");
        printf("src IP: xxx\n");
        printf("dst IP: xxx\n");
        printf("src port: xxx\n");
        printf("dst port: xxx\n");
    }
    else{
        fprintf(stderr,"... unknown ...\n");
    }

    print_frame_raw(frame, pac_header.len);

    // icmp arp ip ipv6
    

    printf("\noffset_vypsaných_bajtů:  výpis_bajtů_hexa výpis_bajtů_ASCII\n");

}

/**
 *  Print frame that has len_byte lenght
 * 
 * 0x0000:  00 19 d1 f7 be e5 00 04  96 1d 34 20 08 00 45 00  ........ ..4 ..
 * 0x0010:  05 a0 52 5b 40 00 36 06  5b db d9 43 16 8c 93 e5  ..R[@.6. [..C....
 * 0x0020:  0d 6d 00 50 0d fb 3d cd  0a ed 41 d1 a4 ff 50 18  .m.P..=. ..A...P.
 * 
 */
void print_frame_raw(u_char *frame, int len_byte){

    int count = 0; // count bytes
    int doubles = 0;
    printf("\n0x%04x:  ",count);
    for (int i = 0; i < len_byte; i++){
        doubles++;
        printf("%x",frame[i]);
        if(doubles == 1){
            printf(" ");
            doubles = 0;
        }

        count++;
        if (count % 16 == 0){
            printf("\n0x%04x:  ",count);
        }
    }
}

/**
 * print information about arp 
 */
void print_arp(struct arphdr *arp_header){
    printf("Message type: ");
    switch (ntohs(arp_header->ar_op)){
        case ARPOP_REQUEST:
            printf("ARP request\n"); break;
        case ARPOP_REPLY:
            printf("ARP reply\n"); break;
        case ARPOP_RREQUEST:
            printf("RARP request\n"); break;
        case ARPOP_RREPLY:
            printf("RARP reply\n"); break;
        case ARPOP_InREQUEST:
            printf("InARP request\n"); break;
        case ARPOP_InREPLY:
            printf("InARP reply\n"); break;
        case ARPOP_NAK:
            printf("(ARM)ARP NAK\n"); break;
        default:
            printf("UNKNOWN ARP MESSAGE\n");
    }
    printf("Protocol type: ");
    switch(ntohs(arp_header->ar_pro)){
        case ETHERTYPE_IP:
            printf("ipv4\n"); break;
        case ETHERTYPE_IPV6:
            printf("ipv6\n"); break;
        default:
            printf("Unknown protocol");
    }

}


/**
 * Print mac addres from u_char ether[6] 
 * set src_des to SRC or DST 
 */
void print_mac(u_char ether[6], int src_des){
    if (src_des == SRC){
        printf("src MAC: ");

    }
    else if (src_des == DST){
        printf("dst MAC: ");

    }
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
    (unsigned char) ether[0], (unsigned char) ether[1],
    (unsigned char) ether[2], (unsigned char) ether[3],
    (unsigned char) ether[4], (unsigned char) ether[5]);

}



/**
 * Print time in RFC
 *  inspiration from:
 *    https://gist.github.com/jedisct1/b7812ae9b4850e0053a21c922ed3e9dc 
 */
void print_timestap(struct timeval ts){
    time_t time = (time_t)ts.tv_sec; 

    struct tm *tm;
    int off_sign;
    int off;

    if ((tm = localtime(&time)) == NULL) {
        return;
    }

    off_sign = '+';
    off = (int) tm->tm_gmtoff;
    if (tm->tm_gmtoff < 0) {
        off_sign = '-';
        off = -off;
    }

    // get three milisecond digits
    int msec[100]; int i = 0;
    for (; ts.tv_usec; i++)
    {
        msec[i] = (int)ts.tv_usec % 10;
        ts.tv_usec /= 10;
    }

    printf("timestamp: ");
    if (tm->tm_mon > 9){
        printf("%d-%d-%dT%02d:%02d:%02d.%d%d%d%c%02d:%02d",
           tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
           tm->tm_hour, tm->tm_min, tm->tm_sec, msec[i-1], msec[i-2], msec[i-3],
           off_sign, off / 3600, off % 3600);
    }
    else{
        printf("%d-0%d-%dT%02d:%02d:%02d.%d%d%d%c%02d:%02d",
           tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
           tm->tm_hour, tm->tm_min, tm->tm_sec, msec[i-1], msec[i-2], msec[i-3],
           off_sign, off / 3600, off % 3600);
    }
        
    printf("\n");
}