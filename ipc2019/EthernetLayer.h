#pragma once
#include "BaseLayer.h"
#include "ArpProtocol.h"
class CEthernetLayer:public CBaseLayer {
public:
    CEthernetLayer(char* name):CBaseLayer(name){}
    arp::Mac source{};
    BOOL SendArp(const arp::Mac& sender,const arp::Mac& destination,const arp::Bytes& payload);
    BOOL Receive(unsigned char* data,int length) override;
};
