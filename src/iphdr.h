#pragma once
#include "ip.h"

#pragma pack(push, 1)
struct IPv4_hdr final
{
    uint8_t version:4;
    uint8_t IHL:4; //IP 헤더의 크기/4, 4bit
    uint8_t Ip_tos;
    uint16_t Ip_total_length; //엔디언 주의
    uint8_t dummy[4];
    uint8_t TTL;
    uint8_t Protocol; // uint8_t  Protocol; //다음 레이어에 어떤 프로토콜이 오는지, 1byte
    uint8_t dummy2[2];
    Ip sip; //IP 헤더의 src address, 4byte
    Ip dip; //IP 헤더의 dst address, 4byte
};
#pragma pack(pop)
