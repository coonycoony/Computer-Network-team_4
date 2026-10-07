#pragma once
#include "BaseLayer.h"
#include "ArpProtocol.h"
#include <mutex>
class CARPLayer : public CBaseLayer {
public:
    CARPLayer():CBaseLayer((char*)"ARP"){}
    std::mutex mutex;
    arp::Engine engine;
    BOOL Receive(unsigned char* data,int length) override;
};
