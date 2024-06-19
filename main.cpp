#include "main.h"

void usage() {
    puts("syntax : tcp-block <interface> <pattern>");
    puts("sample : tcp-block ens33 \"Host: test.gilgil.net\"");
}

int get_attacker_mac(uint8_t *attacker_mac){
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1){
        return FAIL;
    };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
        close(sock);
        return FAIL;
    }

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else {
            close(sock);
            return FAIL;
        }
    }

    if (success){
        memcpy(attacker_mac, ifr.ifr_hwaddr.sa_data, MAC_SIZE);
        close(sock);
        return SUCCESS;
    }
    else{
        close(sock);
        return FAIL;
    }
}

char pattern[128];
int pat_len;
pcap_t* handle;
uint8_t attacker_mac[MAC_SIZE] = { 0 };

int is_block(unsigned char* buf, int size) {
	// Using KMP Algorithm
	int fail[128] = { 0 };
	for(int i=1,j=0;i<pat_len;i++){
		while(j>0&&pattern[i]!=pattern[j])	j = fail[j-1];
		if(pattern[i] == pattern[j])	fail[i] = ++j;
	}

	for(int off=0,j=0;off<size;off++){
		while(j>0 && buf[off] != pattern[j])	j = fail[j-1];
		if(buf[off] == pattern[j]){
			if(j==pat_len-1){
				printf("Pattern is founded!\n");
                return 1;
			}
			else	j++;
		}
	}
	return 0;
}

void tcp_checksum(IPv4 * ip, TCP * tcp) {
    pseudo_hdr * header = (pseudo_hdr *)malloc(sizeof(pseudo_hdr));
    memcpy(header->sip, ip->ip_src, IP_SIZE);
    memcpy(header->dip, ip->ip_dst, IP_SIZE);
    header->reserved = 0x00;
    header->proto = ip->ip_p;
    header->tcp_len = htons(ntohs(ip->ip_len) - sizeof(IPv4));
    tcp->th_sum = 0;

    uint32_t checksum = 0;
    for(int i=0; i<sizeof(pseudo_hdr)/sizeof(uint16_t); i++) {
        checksum += ntohs(*((uint16_t *)header+i));
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    for(int i=0; i<(tcp->th_off << 2)/sizeof(uint16_t); i++) {
        checksum += *((uint16_t *)tcp+i);
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    free(header);
    tcp->th_sum = (uint16_t)(~checksum);
    return;
}

void send_forward(const u_char* pkt_data, unsigned int length){
    u_char packet[length] = { 0 };
    memcpy(packet, pkt_data, length);
    ETHERNET *eth = (ETHERNET *) packet;
    IPv4 *ip = (IPv4 *)(packet+ETH_H);
    TCP *tcp = (TCP *)(packet+ETH_H+ip->ip_hl*4);

    // ETHERNET HEADER
    // smac <- attacker mac
    memcpy(eth->smac, attacker_mac, MAC_SIZE);
    
    // TCP HEADER
    tcp -> th_seq = htonl(ntohl(tcp->th_seq)+(ntohs(ip->ip_len) - ((ip->ip_hl*4)+((tcp->th_off) << 2))));
    tcp->th_flags |= TH_RST;

    // IP HEADER
    ip->ip_len = (ip->ip_hl*4)+((tcp->th_off) << 2);

    // TCP CHECKSUM
    tcp_checksum(ip, tcp);

    int res = pcap_sendpacket(handle, (const u_char*)packet, ETH_H+ip->ip_len);
    if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

void send_backward(const u_char* pkt_data, unsigned int length){
    u_char packet[length+0x10] = { 0 };
    memcpy(packet, pkt_data, length);
    ETHERNET *eth = (ETHERNET *) packet;
    IPv4 *ip = (IPv4 *)(packet+ETH_H);
    TCP *tcp = (TCP *)(packet+ETH_H+ip->ip_hl*4);
    // ETHERNET HEADER
    memcpy(eth->dmac, eth->smac, MAC_SIZE);
    memcpy(eth->smac, attacker_mac, MAC_SIZE);

    // TCP HEADER
    uint16_t port = tcp->th_sport;
    tcp->th_sport = tcp->th_dport;
    tcp->th_dport = port;

    int data_size = ntohs(ip->ip_len) - ((ip->ip_hl*4)+((tcp->th_off) << 2));
    tcp -> th_seq = htonl(ntohl(tcp->th_seq)+data_size);
    uint32_t val = ntohl(tcp->th_seq);
    tcp->th_seq = tcp->th_ack;
    tcp->th_ack = htonl(val);
    tcp->th_flags |= TH_FIN;

    // IP HEADER
    ip->ip_len = (ip->ip_hl*4)+((tcp->th_off) << 2) + 11;
    ip->ip_ttl = 128;
    uint8_t ip_addr[IP_SIZE] = { 0 };
    memcpy(ip_addr, ip->ip_src, IP_SIZE);
    memcpy(ip->ip_src, ip->ip_dst, IP_SIZE);
    memcpy(ip->ip_dst, ip_addr, IP_SIZE);

    // TCP CHECKSUM
    tcp_checksum(ip, tcp);

    // DATA
    u_char *data = (u_char *)(packet+ETH_H+ip->ip_hl*4+((tcp->th_off) << 2));
    const u_char block_str[11] = "BLOCKED!!!";
    memcpy(data, block_str, 10);

    int res = pcap_sendpacket(handle, (const u_char*)packet, length);
    if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

void send_block_packet(const u_char* pkt_data, unsigned int length){
    // First, get attacker mac address.
    get_attacker_mac(attacker_mac);

    // Send Forward Block Packet
    send_forward(pkt_data, length);

    // Send Backward Block Packet
    send_backward(pkt_data, length);
}

int analyze(const u_char* pkt_data, unsigned int length){
    u_char packet[length] = { 0 };
    memcpy(packet, pkt_data, length);

    ETHERNET *eth = (ETHERNET *) packet;
    IPv4 *ip = (IPv4 *)(packet+ETH_H);
    TCP *tcp = (TCP *)(packet+ETH_H+ip->ip_hl*4);
    int offset = ETH_H+ip->ip_hl * 4+((tcp->th_off) << 2);
    if(ip->ip_p != PRO_TCP){
        //printf("not tcp packet\n");
        return 0;
    }
    u_char *data = packet+offset;
    int data_size = length-offset;
    if(is_block(data, data_size)){
        printf("%d\n", offset);
        for(int i=0;i<length;i++){
            printf("%02x ", packet[i]);
        }
        send_block_packet(packet, length);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    memcpy(pattern, argv[2], sizeof(pattern));
    pat_len = strlen(pattern);

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        analyze(packet, header->caplen);
    }
    
    pcap_close(handle);
}
