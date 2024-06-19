#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include <time.h>
#include <stdlib.h>


#define SUCCESS 1
#define FAIL 0

#define MAC_SIZE 6
#define IP_SIZE 4

#define ETH_H 14
#define PRO_TCP 6

#define TH_RST 4
#define TH_FIN 1

typedef struct pseudo_hdr {
    uint8_t sip[IP_SIZE];
    uint8_t dip[IP_SIZE];
    uint8_t reserved;
    uint8_t proto;
    uint16_t tcp_len;
} pseudo_hdr;

typedef struct ethernet_hdr{
    uint8_t  dmac[MAC_SIZE];/* destination ethernet address */
    uint8_t  smac[MAC_SIZE];/* source ethernet address */
    uint16_t ether_type;                 /* protocol */
}ETHERNET;

typedef struct ipv4_hdr{
    uint8_t ip_hl:4,
            ip_v:4;  
    uint8_t ip_tos; 
    uint16_t ip_len;         /* total length */
    uint16_t ip_id;          /* identification */
    uint16_t ip_off;
    uint8_t ip_ttl;          /* time to live */
    uint8_t ip_p;            /* protocol */
    uint16_t ip_sum;         /* checksum */
    uint8_t ip_src[4], ip_dst[4];
}IPv4;

typedef struct tcp_hdr{
    uint16_t th_sport;       /* source port */
    uint16_t th_dport;       /* destination port */
    uint32_t th_seq;          /* sequence number */
    uint32_t th_ack;          /* acknowledgement number */
    uint8_t  th_x2:4,
             th_off:4;         /* (unused) */
    uint8_t  th_flags;       /* control flags */
    uint16_t th_win;         /* window */
    uint16_t th_sum;         /* checksum */
    uint16_t th_urp;         /* urgent pointer */
}TCP;
