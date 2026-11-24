#include "pch.h"
#include "ARPLayer.h"
#include "EthernetLayer.h"
BOOL CARPLayer::Receive(int port,unsigned char* data,int length) {
    if(port<0||port>1||length<0) return FALSE;
    std::lock_guard<std::recursive_mutex> guard(mutex);
    if(!engine[port].receive(data,(size_t)length,GetTickCount64())) return FALSE;
    Flush(port);
    return TRUE;
}
// Send the datagram to the next hop's MAC from the ARP cache, or hold it while an ARP request is outstanding.
CARPLayer::Delivery CARPLayer::Resolve(int port,const arp::Ip& nextHop,arp::Bytes packet) {
    if(port<0||port>1||!ports[port]) return Delivery::Failed;
    std::lock_guard<std::recursive_mutex> guard(mutex);
    auto& e=engine[port]; const uint64_t now=GetTickCount64();
    auto it=e.find(nextHop);
    if(it!=e.cache.end()&&it->complete&&now-it->created<1200000)
        return ports[port]->SendIp(it->mac,packet.data(),(int)packet.size())?Delivery::Sent:Delivery::Failed;
    // A request is already pending (tick retries it); after three unanswered attempts ask again.
    const bool pending=it!=e.cache.end()&&!it->complete&&(it->attempts<3||now-it->lastSend<1000);
    if(!pending&&!e.request(nextHop,now)) return Delivery::Failed;
    if(waiting.size()>=256) { waiting.erase(waiting.begin()); ++waitDrops; }
    waiting.push_back({port,nextHop,now,std::move(packet)});
    return Delivery::Queued;
}
void CARPLayer::Flush(int port) {
    auto& e=engine[port];
    for(auto it=waiting.begin();it!=waiting.end();) {
        auto entry=it->port==port?e.find(it->nextHop):e.cache.end();
        if(entry!=e.cache.end()&&entry->complete) {
            ports[port]->SendIp(entry->mac,it->packet.data(),(int)it->packet.size());
            it=waiting.erase(it);
        }
        else ++it;
    }
}
void CARPLayer::Tick(uint64_t now) {
    std::lock_guard<std::recursive_mutex> guard(mutex);
    for(int i=0;i<2;++i) { engine[i].tick(now); Flush(i); }
    // Datagrams wait at most 3.5 s (three ARP attempts, 1 s apart) for the next hop to answer.
    waiting.erase(std::remove_if(waiting.begin(),waiting.end(),[&](const Waiting& w){
        const bool stale=now-w.queued>=3500; if(stale) ++waitDrops; return stale;
    }),waiting.end());
}
