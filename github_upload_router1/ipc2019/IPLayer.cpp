#include "pch.h"
#include "IPLayer.h"
#include "ARPLayer.h"
// (Destination IP & Netmask) == Destination of the entry. Host routes beat network routes, which beat the
// default route (0.0.0.0/0): the longest mask wins and the earlier entry wins a tie.
const CIPLayer::Route* CIPLayer::Lookup(const arp::Ip& destination) const {
    const Route* best=nullptr; const uint32_t dst=arp::toU32(destination);
    for(const auto& r:routes) {
        if(!(r.flags&Up)) continue;
        const uint32_t mask=arp::toU32(r.mask);
        if((dst&mask)!=arp::toU32(r.destination)) continue;
        if(!best||mask>arp::toU32(best->mask)) best=&r;
    }
    return best;
}
void CIPLayer::Note(Log& entry,Verdict verdict) {
    entry.verdict=verdict; last=entry; ++logSeq;
}
BOOL CIPLayer::Receive(int port,unsigned char* data,int length) {
    if(port<0||port>1||!data||!arpLayer) return FALSE;
    std::lock_guard<std::recursive_mutex> guard(arpLayer->mutex);
    const Port& in=ports[port]; if(!in.active) return FALSE;
    const unsigned ihl=length>=20?(data[0]&15)*4:0, total=length>=20?(data[2]<<8)|data[3]:0;
    if(length<20||(data[0]>>4)!=4||ihl<20||total<ihl||total>(unsigned)length||IpChecksum(data,ihl)) { ++badHeader; return FALSE; }
    ++received;
    Log entry; entry.in=port;
    std::copy_n(data+12,4,entry.source.begin()); std::copy_n(data+16,4,entry.destination.begin());
    entry.ttl=data[8]; entry.protocol=data[9]; if(entry.protocol==1&&total>ihl) entry.icmpType=data[ihl];
    // Limited and multicast broadcasts are never forwarded. They are frequent, so they are only counted.
    const uint32_t dst=arp::toU32(entry.destination);
    if(dst==0xffffffffu||entry.destination[0]>=224||entry.source==arp::Ip{}) { ++broadcasts; return FALSE; }
    // Addressed to the router itself: would go to an upper layer, which this assignment does not implement.
    for(const auto& p:ports) if(p.active&&p.ip==entry.destination) { ++local; Note(entry,Verdict::Local); return TRUE; }
    const Route* route=Lookup(entry.destination);
    if(!route) { ++noRoute; Note(entry,Verdict::NoRoute); return FALSE; }
    // Directed broadcast of a directly connected network (host bits all ones) is not forwarded either.
    const uint32_t mask=arp::toU32(route->mask);
    if(!(route->flags&Gateway)&&mask!=0xffffffffu&&(dst|mask)==0xffffffffu) { ++broadcasts; return FALSE; }
    // Flag U: destination is on a directly connected network. Flag UG: deliver to the entry's gateway.
    entry.out=route->port; entry.nextHop=(route->flags&Gateway)?route->gateway:entry.destination;
    if(!ports[route->port].active) { ++arpFailed; Note(entry,Verdict::PortDown); return FALSE; }
    if(data[8]<=1) { ++ttlExpired; Note(entry,Verdict::TtlExpired); return FALSE; }
    if(total>ETHER_MAX_DATA_SIZE) { ++tooBig; Note(entry,Verdict::TooBig); return FALSE; }
    // The destination IP never changes; only TTL is decremented and the header checksum recomputed.
    arp::Bytes packet(data,data+total);
    --packet[8]; packet[10]=packet[11]=0;
    const uint16_t sum=IpChecksum(packet.data(),ihl); packet[10]=(unsigned char)(sum>>8); packet[11]=(unsigned char)sum;
    switch(arpLayer->Resolve(route->port,entry.nextHop,std::move(packet))) {
    case CARPLayer::Delivery::Sent: ++forwarded; Note(entry,Verdict::Forwarded); return TRUE;
    case CARPLayer::Delivery::Queued: ++forwarded; Note(entry,Verdict::Queued); return TRUE;
    default: ++arpFailed; Note(entry,Verdict::ArpFailed); return FALSE;
    }
}
