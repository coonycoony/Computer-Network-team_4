#pragma once
#include "BaseLayer.h"
#include "ArpProtocol.h"
class CARPLayer;
// Static router IP layer: checks the destination of each received datagram and forwards it with the routing table.
class CIPLayer:public CBaseLayer {
public:
    enum Flag:unsigned { Up=1, Gateway=2, Host=4 };
    enum class Verdict { Forwarded, Queued, Local, NoRoute, PortDown, TtlExpired, TooBig, ArpFailed };
    // metric: hop count shown in the table (1 = directly connected, 2 = through one gateway).
    struct Route { arp::Ip destination{},mask{},gateway{}; int port=0; unsigned flags=Up,metric=1; };
    struct Port { arp::Ip ip{}; bool active=false; };
    struct Log { int in=0,out=-1; arp::Ip source{},destination{},nextHop{}; unsigned protocol=0,icmpType=256,ttl=0; Verdict verdict=Verdict::Forwarded; };
    CIPLayer():CBaseLayer((char*)"IP"){}
    CARPLayer* arpLayer=nullptr;
    // All members below are guarded by arpLayer->mutex.
    std::vector<Route> routes; Port ports[2];
    Log last; uint64_t logSeq=0;   // most recent datagram handled, for the UI
    uint64_t received=0,forwarded=0,local=0,noRoute=0,ttlExpired=0,badHeader=0,tooBig=0,arpFailed=0,broadcasts=0;
    void reset() { received=forwarded=local=noRoute=ttlExpired=badHeader=tooBig=arpFailed=broadcasts=0; last=Log{}; logSeq=0; }
    const Route* Lookup(const arp::Ip& destination) const;
    BOOL Receive(int port,unsigned char* data,int length);
private:
    void Note(Log& entry,Verdict verdict);
};
// Internet checksum (RFC 1071). A valid header sums to 0.
inline uint16_t IpChecksum(const unsigned char* p,size_t n) {
    uint32_t sum=0;
    for(size_t i=0;i+1<n;i+=2) sum+=(p[i]<<8)|p[i+1];
    if(n&1) sum+=p[n-1]<<8;
    while(sum>>16) sum=(sum&0xffff)+(sum>>16);
    return (uint16_t)~sum;
}
