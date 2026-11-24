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
// ICMP Echo Reply for a ping to one of the router's own interface IPs. The reply is routed like any other
// datagram: the routing table picks the output port and next hop (Flag U: the requester, Flag UG: the gateway).
BOOL CIPLayer::EchoReply(Log& entry,const unsigned char* data,unsigned ihl,unsigned total) {
    const bool fragment=(data[6]&0x3f)||data[7];
    const unsigned size=20+total-ihl;   // reply carries no IP options
    if(entry.protocol!=1||fragment||total<ihl+8||data[ihl]!=8||data[ihl+1]||IpChecksum(data+ihl,total-ihl)||size>ETHER_MAX_DATA_SIZE) {
        Note(entry,Verdict::Local); return TRUE;
    }
    const Route* route=Lookup(entry.source);
    if(!route) { ++noRoute; Note(entry,Verdict::NoRoute); return FALSE; }
    entry.out=route->port; entry.nextHop=(route->flags&Gateway)?route->gateway:entry.source;
    if(!ports[route->port].active) { ++arpFailed; Note(entry,Verdict::PortDown); return FALSE; }
    arp::Bytes reply(size,0);
    reply[0]=0x45; reply[2]=(unsigned char)(size>>8); reply[3]=(unsigned char)size; reply[4]=data[4]; reply[5]=data[5];
    reply[8]=128; reply[9]=1;
    std::copy(entry.destination.begin(),entry.destination.end(),reply.begin()+12);   // source = the pinged interface IP
    std::copy(entry.source.begin(),entry.source.end(),reply.begin()+16);
    uint16_t sum=IpChecksum(reply.data(),20); reply[10]=(unsigned char)(sum>>8); reply[11]=(unsigned char)sum;
    // Same identifier, sequence number and data; type 8 -> 0 and the ICMP checksum recomputed.
    std::copy(data+ihl,data+total,reply.begin()+20);
    reply[20]=0; reply[22]=reply[23]=0;
    sum=IpChecksum(reply.data()+20,size-20); reply[22]=(unsigned char)(sum>>8); reply[23]=(unsigned char)sum;
    if(arpLayer->Resolve(route->port,entry.nextHop,std::move(reply))==CARPLayer::Delivery::Failed) { ++arpFailed; Note(entry,Verdict::ArpFailed); return FALSE; }
    ++echoReplies; Note(entry,Verdict::EchoReplied); return TRUE;
}
static uint16_t Get16(const arp::Bytes& p,size_t at) { return (uint16_t)(p[at]<<8|p[at+1]); }
static void Put16(arp::Bytes& p,size_t at,uint16_t v) { p[at]=(unsigned char)(v>>8); p[at+1]=(unsigned char)v; }
// ICMP checksum covers the ICMP header and data only (no IP addresses): recomputed with the field set to 0.
static void IcmpChecksum(arp::Bytes& p,unsigned ihl) { Put16(p,ihl+2,0); Put16(p,ihl+2,IpChecksum(p.data()+ihl,p.size()-ihl)); }
// Unfragmented ICMP Echo message of the given type (8 = Request, 0 = Reply), code 0, with a valid ICMP checksum.
bool CIPLayer::EchoMessage(const arp::Bytes& p,unsigned ihl,unsigned type) const {
    const bool fragment=(p[6]&0x3f)||p[7];
    return p[9]==1&&!fragment&&p.size()>=ihl+8&&p[ihl]==type&&p[ihl+1]==0&&!IpChecksum(p.data()+ihl,p.size()-ihl);
}
// NAT outbound (Port1 Inside -> Port2 Outside), ICMP Echo Request: look up (inside IP, inside ID); a new pair gets
// the next free outside ID. Source IP -> Port2 IP, Identifier -> outside ID, ICMP checksum recomputed.
bool CIPLayer::NatOutbound(Log& entry,arp::Bytes& p,unsigned ihl,Verdict& verdict) {
    if(!EchoMessage(p,ihl,8)) { verdict=Verdict::NatUnsupported; return false; }
    const uint16_t id=Get16(p,ihl+4); const uint64_t now=GetTickCount64();
    auto it=std::find_if(nat.begin(),nat.end(),[&](const NatEntry& e){return e.protocol==1&&e.insideIp==entry.source&&e.insideId==id;});
    if(it==nat.end()) {
        // Outside IDs are handed out in order from 50001, skipping IDs still in the table (wraps after 65535).
        uint16_t outsideId=0;
        for(unsigned tries=0;tries<=65535u-NatFirstId&&!outsideId;++tries) {
            const uint16_t candidate=nextId; nextId=nextId==65535?NatFirstId:(uint16_t)(nextId+1);
            if(std::none_of(nat.begin(),nat.end(),[&](const NatEntry& e){return e.protocol==1&&e.outsideId==candidate;})) outsideId=candidate;
        }
        if(!outsideId) { verdict=Verdict::NatFull; return false; }
        nat.push_back({1,entry.source,id,ports[Outside].ip,outsideId,now}); it=nat.end()-1;
    }
    it->lastUsed=now;   // every use refills the timer
    std::copy(it->outsideIp.begin(),it->outsideIp.end(),p.begin()+12);
    Put16(p,ihl+4,it->outsideId); IcmpChecksum(p,ihl);
    entry.nat=true; entry.natFrom=entry.source; entry.idFrom=id; entry.natTo=it->outsideIp; entry.idTo=it->outsideId;
    ++natOut; return true;
}
// NAT inbound (Port2 Outside -> Port2 IP), ICMP Echo Reply: the outside ID finds the entry. Destination IP ->
// inside host IP, Identifier -> inside ID, ICMP checksum recomputed. No entry: the reply is not let in.
bool CIPLayer::NatInbound(Log& entry,arp::Bytes& p,unsigned ihl,Verdict& verdict) {
    if(!EchoMessage(p,ihl,0)) { verdict=Verdict::NatUnsupported; return false; }
    const uint16_t id=Get16(p,ihl+4);
    auto it=std::find_if(nat.begin(),nat.end(),[&](const NatEntry& e){return e.protocol==1&&e.outsideId==id&&e.outsideIp==entry.destination;});
    if(it==nat.end()) { verdict=Verdict::NatNoEntry; return false; }
    it->lastUsed=GetTickCount64();
    std::copy(it->insideIp.begin(),it->insideIp.end(),p.begin()+16);
    Put16(p,ihl+4,it->insideId); IcmpChecksum(p,ihl);
    entry.nat=true; entry.natFrom=entry.destination; entry.idFrom=id; entry.natTo=it->insideIp; entry.idTo=it->insideId;
    ++natIn; return true;
}
void CIPLayer::Tick(uint64_t now) {
    if(!arpLayer) return;
    std::lock_guard<std::recursive_mutex> guard(arpLayer->mutex);
    nat.erase(std::remove_if(nat.begin(),nat.end(),[&](const NatEntry& e){
        const bool expired=now-e.lastUsed>=NatTimeout; if(expired) ++natExpired; return expired;
    }),nat.end());
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
    // NAT inbound: an ICMP Echo Reply to the Outside port IP answers a translated request. Its destination is
    // restored from the NAT table first, and the restored destination (the inside host) is then routed.
    arp::Bytes packet; arp::Ip target=entry.destination;
    if(port==Outside&&entry.destination==ports[Outside].ip&&entry.icmpType==0) {
        packet.assign(data,data+total); Verdict verdict;
        if(!NatInbound(entry,packet,ihl,verdict)) { ++natDropped; Note(entry,verdict); return FALSE; }
        target=entry.natTo;
    }
    // Addressed to the router itself: only ICMP Echo Request is answered (ping the router's port IPs).
    else if(std::any_of(std::begin(ports),std::end(ports),[&](const Port& p){return p.active&&p.ip==entry.destination;})) {
        ++local; return EchoReply(entry,data,ihl,total);
    }
    const Route* route=Lookup(target);
    if(!route) { ++noRoute; Note(entry,Verdict::NoRoute); return FALSE; }
    // Directed broadcast of a directly connected network (host bits all ones) is not forwarded either.
    const uint32_t mask=arp::toU32(route->mask);
    if(!(route->flags&Gateway)&&mask!=0xffffffffu&&(arp::toU32(target)|mask)==0xffffffffu) { ++broadcasts; return FALSE; }
    // Flag U: destination is on a directly connected network. Flag UG: deliver to the entry's gateway.
    entry.out=route->port; entry.nextHop=(route->flags&Gateway)?route->gateway:target;
    // Outside -> Inside is only possible through a NAT entry: a datagram sent first from outside never gets in.
    if(port==Outside&&route->port==Inside&&!entry.nat) { ++natDropped; Note(entry,Verdict::NatBlocked); return FALSE; }
    if(!ports[route->port].active) { ++arpFailed; Note(entry,Verdict::PortDown); return FALSE; }
    if(data[8]<=1) { ++ttlExpired; Note(entry,Verdict::TtlExpired); return FALSE; }
    if(total>ETHER_MAX_DATA_SIZE) { ++tooBig; Note(entry,Verdict::TooBig); return FALSE; }
    if(packet.empty()) packet.assign(data,data+total);
    // NAT outbound: Inside -> Outside datagrams leave with the Port2 IP as their source (ICMP Echo Request only).
    if(port==Inside&&route->port==Outside) {
        Verdict verdict;
        if(!NatOutbound(entry,packet,ihl,verdict)) { ++natDropped; Note(entry,verdict); return FALSE; }
    }
    // TTL is decremented and the IP header checksum recomputed (it also covers the translated addresses).
    --packet[8]; packet[10]=packet[11]=0;
    const uint16_t sum=IpChecksum(packet.data(),ihl); packet[10]=(unsigned char)(sum>>8); packet[11]=(unsigned char)sum;
    switch(arpLayer->Resolve(route->port,entry.nextHop,std::move(packet))) {
    case CARPLayer::Delivery::Sent: ++forwarded; Note(entry,Verdict::Forwarded); return TRUE;
    case CARPLayer::Delivery::Queued: ++forwarded; Note(entry,Verdict::Queued); return TRUE;
    default: ++arpFailed; Note(entry,Verdict::ArpFailed); return FALSE;
    }
}
