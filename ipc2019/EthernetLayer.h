#pragma once
#include "BaseLayer.h"
#include "ArpProtocol.h"
class CARPLayer; class CIPLayer;
// One Ethernet layer per router interface; ARP and IP layers are shared by both interfaces.
class CEthernetLayer:public CBaseLayer {
public:
    CEthernetLayer(char* name,int port):CBaseLayer(name),port(port){}
    const int port;
    arp::Mac source{};
    CARPLayer* arpLayer=nullptr; CIPLayer* ipLayer=nullptr;
    BOOL SendArp(const arp::Mac& sender,const arp::Mac& destination,const arp::Bytes& payload);
    BOOL SendIp(const arp::Mac& destination,const unsigned char* packet,int length);
    BOOL Receive(unsigned char* data,int length) override;
};
