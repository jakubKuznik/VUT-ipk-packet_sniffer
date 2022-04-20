// Solution for IPK-packet-sniffer, 16.4.2022
// File:        args.h
// Author:      Jakub Kuzník, FIT
// Compiled:    gcc 9.9.3.0
// frames.c header file 


#pragma once

#include "ipk-sniffer.h"

#define MAX_FRAME_SIZE 1518
#define ETH_HEAD 14
#define ARP_HEAD 28
#define IP_HEAD 20
#define IPV6_HEAD 40

#define IP 0
#define IPV6 1


#define SRC 0
#define DST 1
#define ICMP 1 // wiki ip paket sekce data 
#define TCP 6
#define UDP 17 

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
bool handle_frame(pcap_t *sniff_int, struct settings *sett);

/**
 * Print time in RFC
 */
void print_timestap(struct timeval ts);

/**
 * Print mac addres from u_char ether[6] 
 * set src_des to SRC or DST 
 */
void print_mac(u_char ether[6], int src_des);


/**
 * print information about arp 
 */
void print_arp(struct arphdr *arp_header);


/**
 *  Print frame that has len_byte lenght
 * 
 * 0x0000:  00 19 d1 f7 be e5 00 04  96 1d 34 20 08 00 45 00  ........ ..4 ..
 * 0x0010:  05 a0 52 5b 40 00 36 06  5b db d9 43 16 8c 93 e5  ..R[@.6. [..C....
 * 0x0020:  0d 6d 00 50 0d fb 3d cd  0a ed 41 d1 a4 ff 50 18  .m.P..=. ..A...P.
 * 
 */
void print_frame_raw(const u_char *frame, int len_byte);


/**
 * Print array to <=j 
 * if non printable print .  
 */
void print_data(char *array ,int j);

/**
 * print inforamation about ip and icmp frame 
 * 
 * calls: print_icmp_header()
 *        print_tcp_header()
 *        print_udp_header()
 * 
 */
void print_ip_header(const u_char *frame);

/**
 * print inforamation about ipv6 and icmp frame  
 * 
 * calls: print_icmp_header()
 *        print_tcp_header()
 *        print_udp_header()
 */
void print_ipv6_header(const u_char *frame);


/**
 * print information about icmp
 */
void print_icmp_header(struct icmp * icmp_header);


/**
 * print information about TCP
 */
void print_tcp_header(struct tcphdr *tcp_header);


/**
 * print information about UDP
 */
void print_udp_header(struct udphdr *udp_header);


/**
 * Print basic info about frame all the frames use this function.
 */
void basic_info_frame_print(struct pcap_pkthdr *pac_header, 
                            struct ether_header *eth_header);


/**
 * return TCP, UDP, ICMP or -1
 */
int get_ip_type(const u_char *frame);

/**
 * return TCP, UDP, ICMP or -1
 */
int get_ipv6_type(const u_char *frame);

/**
 * return port number of TCP 
 * 
 *  direction could be DST or SRC 
 */
int get_port_tcp(struct tcphdr *tcp_header ,char direction);

/**
 * return port number of UDP
 *
 *  direction could be DST or SRC 
 */
int get_port_udp(struct udphdr *udp_header ,char direction);

/**
 * return true if packet can be processed 
 * return false if packet has to be skipped 
 * based on sett
 * 
 * version is IP or IPV6
 *  
 */
bool filter(const u_char *frame ,struct settings *sett, int version);