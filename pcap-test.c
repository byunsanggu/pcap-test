#include <stdio.h>
#include "pcap.h" 
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "headrs.h"
#include <string.h>
#define SIZE_ETHERNET 14 

int main(int argc, char *argv[]) 
{

	const struct sniff_ethernet *ethernet; 
	const struct sniff_ip *ip; 
	const struct sniff_tcp *tcp; 
	const char *payload;

	u_int size_ip;
	u_int size_tcp;
    char *dev = argv[1]; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle; 
    struct in_addr adr; 
    
    if(argc != 2) 
    {
        printf("syntax : pacap_test <interface>\n");
        printf("sample : pcap_test dum0\n");
        return -1;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL)
    {
        printf("pcap_open_live(%s) return nullptr %s", dev, errbuf);
        return -1;
    }

    while(1) {
        printf("\n");  
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        char IP_add1[1024], IP_add2[1024];
        int payload_len;

        if(res == 0) continue;
        if(res == -1 || res == -1) {
            printf("error");
            return -1;
        }
    ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return -1;
	}
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return -1;
	}
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    
    printf("%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x,", ethernet->ether_shost[0] , ethernet->ether_shost[1], ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5], ethernet->ether_dhost[0], ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],ethernet->ether_dhost[5]);
    strcpy(IP_add1,inet_ntoa(ip->ip_src)); strcpy(IP_add2, inet_ntoa(ip->ip_dst));
    printf("%s:%d -> %s:%d",IP_add1, ntohs(tcp -> th_sport) , IP_add2 , ntohs(tcp -> th_dport));

    payload_len = ntohs(ip->ip_len) - (size_ip + size_tcp);
    
    if(payload_len == 0 ) {
        printf("\n-\n");
        printf("====================================================\n");
        continue; 
    }

    else
    {
        printf("\n");
        for(int i = 1; i <=16; i++) {
            printf("%02x|", payload[i-1]); 
        }
        printf("\n==================================================\n");
    }
     
    

}
    pcap_close(handle);
   
    return 0;
}
