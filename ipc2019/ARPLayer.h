#pragma once
#include "BaseLayer.h"
#include "ArpProtocol.h"
#include <mutex>
class CEthernetLayer;
// Next hop MAC resolution for both router interfaces. One ARP engine (cache, local IP/MAC) per interface.
class CARPLayer : public CBaseLayer {
public:
    enum class Delivery { Sent, Queued, Failed };
    struct Waiting { int port; arp::Ip nextHop; uint64_t queued; arp::Bytes packet; };
    CARPLayer():CBaseLayer((char*)"ARP"){}
    // Guards the engines, the waiting queue and the IP layer's routing state; receive threads and the UI share it.
    std::recursive_mutex mutex;
    arp::Engine engine[2];
    CEthernetLayer* ports[2]{};
    std::vector<Waiting> waiting; uint64_t waitDrops=0;
    BOOL Receive(int port,unsigned char* data,int length);
    Delivery Resolve(int port,const arp::Ip& nextHop,arp::Bytes packet);
    void Tick(uint64_t now);
private:
    void Flush(int port);
};
