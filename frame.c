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
 * 
 * return false if packet skip
 *
 * 0x0000:  00 19 d1 f7 be e5 00 04  96 1d 34 20 08 00 45 00  ........ ..4 ..
 * 0x0010:  05 a0 52 5b 40 00 36 06  5b db d9 43 16 8c 93 e5  ..R[@.6. [..C....
 * 0x0020:  0d 6d 00 50 0d fb 3d cd  0a ed 41 d1 a4 ff 50 18  .m.P..=. ..A...P.
 * 0x0030:  19 20 c7 cd 00 00 99 17  f1 60 7a bc 1f 97 2e b7  . ...... .`z.....
 * 0x0040:  a1 18 f4 0b 5a ff 5f ac 07 71 a8 ac 54 67 3b 39  ....Z._. .q..Tg;9
 * 0x0050:  4e 31 c5 5c 5f b5 37 ed  bd 66 ee ea b1 2b 0c 26  N1.\_.7. .f...+.&
 * 0x0060:  98 9d b8 c8 00 80 0c 57  61 87 b0 cd 08 80 00 a1  .......W a.......
 */
bool handle_frame(pcap_t *sniff_int, struct settings *sett){
    
    const u_char        *frame;             // packet
    struct pcap_pkthdr  pac_header;        // packet header
    struct ether_header *eth_header;        // ethernet  
    struct arphdr       *arp_header;        // arp header 


    frame = pcap_next(sniff_int, &pac_header);
    eth_header = (struct ether_header *)frame;


    // find frame type 
    switch (ntohs(eth_header->ether_type)){
        // ip + icmp
        case ETHERTYPE_IP:
            // filter check 
            if (filter(frame, sett, IP) == false)
                return false;

            basic_info_frame_print(&pac_header, eth_header);
            print_ip_header(frame);
            break;
        // arp        
        case ETHERTYPE_ARP:
            // filter check 
            if (sett->arp == false) // arp not enabled
                return false; 

            arp_header = (struct arphdr*)(frame + ETH_HEAD);
            basic_info_frame_print(&pac_header, eth_header);
            print_arp(arp_header);
            break;
        // ipv6
        case ETHERTYPE_IPV6:
            // filter check 
            if (filter(frame, sett, IPV6) == false)
                return false;

            basic_info_frame_print(&pac_header, eth_header);
            print_ipv6_header(frame);
            break;
        default: //skip unknown protocol 
            return false;

    }

    print_frame_raw(frame, pac_header.len);
    printf("\n");
    return true;
}



/**
 * print inforamation about ip and icmp frame 
 * 
 * calls: print_icmp_header()
 *        print_tcp_header()
 *        print_udp_header()
 * 
 */
void print_ip_header(const u_char *frame){
    // header structs 
    struct ip      *ip_header;    
    struct icmp    *icmp_header;    
    struct tcphdr  *tcp_header; 
    struct udphdr  *udp_header; 

    ip_header = (struct ip*)(frame + ETH_HEAD);

    printf("src IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("dst IP: %s\n", inet_ntoa(ip_header->ip_dst));

    switch (ip_header->ip_p){
        // icmp
        case ICMP:
            icmp_header = (struct icmp*)(frame + ETH_HEAD + IP_HEAD);
            print_icmp_header(icmp_header);
            break;
        // tcp
        case TCP:
            tcp_header = (struct tcphdr*)(frame + ETH_HEAD + IP_HEAD);
            print_tcp_header(tcp_header);
            break;
        // udp 
        case UDP:
            udp_header = (struct udphdr*)(frame + ETH_HEAD + IP_HEAD);
            print_udp_header(udp_header);
            break;
        default:
            break;
    }
}

/**
 * print information about icmp
 */
void print_icmp_header(struct icmp * icmp_header){

    printf("Message type: ");
    switch (icmp_header->icmp_type){
        case ICMP_ECHOREPLY:
            printf("ICMP Echo Reply\n"); break;
        case ICMP_DEST_UNREACH: 
            printf("ICMP Destination Unreachable\n"); break;
        case ICMP_SOURCE_QUENCH: 
            printf("ICMP Source Quench\n"); break;
        case ICMP_REDIRECT: 
            printf("ICMP Redirect (change route)\n"); break;
        case ICMP_ECHO: 
            printf("ICMP Echo Request\n"); break;
        case ICMP_TIME_EXCEEDED: 
            printf("ICMP Time Exceeded\n"); break;
        case ICMP_PARAMETERPROB: 
            printf("ICMP Parameter Problem\n"); break;
        case ICMP_TIMESTAMP: 
            printf("ICMP Timestamp Request\n"); break;
        case ICMP_TIMESTAMPREPLY: 
            printf("ICMP Timestamp Reply\n"); break;
        case ICMP_INFO_REQUEST: 
            printf("ICMP Information Request\n"); break;
        case ICMP_INFO_REPLY: 
            printf("ICMP Information Reply\n"); break;
        case ICMP_ADDRESS: 
            printf("ICMP Address Mask Request\n"); break;
        case ICMP_ADDRESSREPLY: 
            printf("ICMP Address Mask Reply\n"); break;
        default:
            printf("ICMP UNKNOWN MESSAGE TYPE\n"); break;
    }
    printf("Code: %d\n",icmp_header->icmp_code);
}

/**
 * print information about TCP
 */
void print_tcp_header(struct tcphdr *tcp_header){
    printf("src port: %d\n",ntohs(tcp_header->th_sport));
    printf("dst port: %d\n",ntohs(tcp_header->th_dport));
    printf("seq num raw: %u\n",ntohl(tcp_header->th_seq));
    printf("ack num raw: %u\n",ntohl(tcp_header->th_ack));
    printf("Protocol: TCP\n");
}

/**
 * print information about UDP
 */
void print_udp_header(struct udphdr *udp_header){
    printf("src port: %d\n",ntohs(udp_header->uh_sport));
    printf("dst port: %d\n",ntohs(udp_header->uh_dport));
    printf("Protocol: UDP\n");
}

/**
 * print inforamation about ip and icmp frame 
 */
void print_ipv6_header(const u_char *frame){

    // headers
    struct ip6_hdr *ipv6_header;    
    struct icmp    *icmp_header;    
    struct tcphdr  *tcp_header; 
    struct udphdr  *udp_header; 
    
    char addr[INET6_ADDRSTRLEN]; // string for ipv6 addres 
    //https://stackoverflow.com/questions/38848281/inet-ntop-printing-incorrect-ipv6-address
    
    ipv6_header = (struct ip6_hdr*)(frame + ETH_HEAD);
    
    // src ip 
    inet_ntop(AF_INET6, &ipv6_header->ip6_src, addr, INET6_ADDRSTRLEN);
    printf("src IP: %s\n", addr);
    
    // dst ip 
    inet_ntop(AF_INET6, &ipv6_header->ip6_dst, addr, INET6_ADDRSTRLEN);
    printf("dst IP: %s\n", addr);
    
    switch (ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt){
        // icmp
        case ICMP:
            icmp_header = (struct icmp*)(frame + ETH_HEAD + IPV6_HEAD);
            print_icmp_header(icmp_header);
            break;
        // tcp
        case TCP:
            tcp_header = (struct tcphdr*)(frame + ETH_HEAD + IPV6_HEAD);
            print_tcp_header(tcp_header);
            break;
        // udp 
        case UDP:
            udp_header = (struct udphdr*)(frame + ETH_HEAD + IPV6_HEAD);
            print_udp_header(udp_header);
            break;
        default:
            break;
    }
}

/**
 *  Print frame that has len_byte lenght in format below:
 * 
 * 0x0000:  00 19 d1 f7 be e5 00 04  96 1d 34 20 08 00 45 00  ........ ..4 ..
 * 0x0010:  05 a0 52 5b 40 00 36 06  5b db d9 43 16 8c 93 e5  ..R[@.6. [..C....
 * 0x0020:  0d 6d 00 50 0d fb 3d cd  0a ed 41 d1 a4 ff 50 18  .m.P..=. ..A...P.
 * 
 */
void print_frame_raw(const u_char *frame, int len_byte){

    int count = 0; // count bytes
    char real[16]; int j = 0;
    int space_counter = 0;


    // 0x0000:
    printf("\n0x%04x:  ",count);
    // 00 19 d1 f7 be e5 00 04  96 1d 34 20 08 00 45 00
    for (int i = 0; i < len_byte; i++){
        space_counter++;

        if(space_counter == 9){
            printf(" "); space_counter = 0;
        }

        printf("%02x ",frame[i]);
        real[j++] = frame[i];
        count++;

        // ........ ..4 ..
        if (count % 16 == 0 && count > 0){
            print_data(real, j);
            if(i+1 != len_byte){
                printf("\n0x%04x:  ",count);
                space_counter = 0;
            }
            j = 0; 
        }
    }
    if (len_byte % 16 != 0){
        int spaces = (16-j)*3;
        for (int i = 0; i < spaces; i++)
            printf(" ");
        if(j < 9)
            printf(" ");
        print_data(real, j-1);
    }
    printf("\n");

}

/**
 * Print array to <=j 
 * if non printable print .  
 */
void print_data(char *array ,int j){
    int space_counter = 0;

    for (int k = 0; k <= j; k++ ){
        space_counter++;

        if(space_counter == 9){
            printf(" "); space_counter = 0;
        }
        // non printable 
        if (array[k] < 32){
            printf(".");
        } 
        else{
            printf("%c",array[k]);
        }
    }
    return;
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

/**
 * Print basic info about frame all the frames use this function.
 */
void basic_info_frame_print(struct pcap_pkthdr *pac_header, 
                            struct ether_header *eth_header){
    
    print_timestap(pac_header->ts);
    print_mac(eth_header->ether_shost, SRC);
    print_mac(eth_header->ether_dhost, DST);
    printf("frame lenght: %d\n",pac_header->len);
}

/**
 * return TCP, UDP, ICMP or -1
 */
int get_ip_type(const u_char *frame){
    struct ip      *ip_header;    
    ip_header = (struct ip*)(frame + ETH_HEAD);
    
    switch (ip_header->ip_p){
        case ICMP:
            return ICMP;
        case TCP:
            return TCP;
        case UDP:
            return UDP;
        default:
            return -1;
    }
}

/**
 * return TCP, UDP, ICMP or -1
 */
int get_ipv6_type(const u_char *frame){
    struct ip6_hdr *ipv6_header;    
    ipv6_header = (struct ip6_hdr*)(frame + ETH_HEAD);
    
    switch (ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt){
        case ICMP:
            return ICMP;
        case TCP:
            return TCP;
        case UDP:
            return UDP;
        default:
            return -1;
    }
}

/**
 * return port number of TCP 
 * 
 *  direction could be DST or SRC 
 */
int get_port_tcp(struct tcphdr *tcp_header ,char direction){
    if (direction == SRC)
        return ntohs(tcp_header->th_sport);
    else if (direction == DST)
        return ntohs(tcp_header->th_dport);
    return -1;
}
 
/**
 * return port number of UDP
 *
 *  direction could be DST or SRC 
 */
int get_port_udp(struct udphdr *udp_header ,char direction){
    if (direction == SRC)
        return ntohs(udp_header->uh_sport);
    else if (direction == DST)
        return ntohs(udp_header->uh_dport);
    return -1;
}

/**
 * return true if packet can be processed 
 * return false if packet has to be skipped 
 * based on sett
 * 
 * version is IP or IPV6
 *  
 */
bool filter(const u_char *frame ,struct settings *sett, int version){
    int type = 0;   // could be icmp, tcp, udp, none 
    int port = 0;
    
    if (version == IP)
        type = get_ip_type(frame);
    else if (version == IPV6)
        type = get_ipv6_type(frame);

    switch (type){
        case ICMP:
            // icmp enabled 
            if (sett->icmp == false)
                return false;
            break;
        // ####################### TCP 
        case TCP:
            // tcp enabled
            if (sett->tcp == false)
                return false;
            // match port 
            if (sett->port == -1) //all ports enabled
                break;
            else{ // -p
                
                if (version == IP)
                    port = get_port_tcp((struct tcphdr*)(frame + ETH_HEAD + IP_HEAD), SRC);
                else if (version == IPV6)
                    port = get_port_tcp((struct tcphdr*)(frame + ETH_HEAD + IPV6_HEAD), SRC);

                // src port checking  
                if(sett->port == port)
                    break;
                
                if (version == IP)
                    port = get_port_tcp((struct tcphdr*)(frame + ETH_HEAD + IP_HEAD), DST);
                else if (version == IPV6)
                    port = get_port_tcp((struct tcphdr*)(frame + ETH_HEAD + IPV6_HEAD), DST);
                
                // dst port checking 
                if(sett->port == port)
                    break;

                return false; // no match --- skip packet  
            }
            break;
        // ################## UDP 
        case UDP:
            // udp enabled
            if (sett->udp == false)
                return false;
            
            // match port 
            if (sett->port == -1) //all ports enabled
                break;
            else{ // -p
                
                if (version == IP)
                    port = get_port_tcp((struct tcphdr*)(frame + ETH_HEAD + IP_HEAD), SRC);
                else if (version == IPV6)
                    port = get_port_tcp((struct tcphdr*)(frame + ETH_HEAD + IPV6_HEAD), SRC);

                // src port checking  
                if(sett->port == port)
                    break;
                
                if (version == IP)
                    port = get_port_udp((struct udphdr*)(frame + ETH_HEAD + IP_HEAD), DST);
                else if (version == IPV6)
                    port = get_port_udp((struct udphdr*)(frame + ETH_HEAD + IPV6_HEAD), DST);
                
                // dst port checking 
                if(sett->port == port)
                    break;

                return false; // no match --- skip packet  
            }
            

            break;
        default:
            return false;
    }
    return true;
}