#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <pthread.h>
#include <sys/ioctl.h>

typedef struct arp_hdr {
    u_int16_t htype;   
    u_int16_t ptype;  
    u_char hlen;    
    u_char plen;     
    u_int16_t oper;  
    u_char sha[6]; 
    u_char spa[4]; 
    u_char tha[6];    
    u_char tpa[4];    
} arpHdr;

typedef struct arpInfo {
    struct pcap_pkthdr header;
    pcap_t *handle;
    struct sockaddr_in sender;
    struct sockaddr_in target;
} arp_info;


typedef struct fullarp {
    struct ethhdr eth_hdr;
    struct arp_hdr arp_hdr;
} fullarphdr;

