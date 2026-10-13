#pragma once
#include <array>
#include <vector>
#include <string>
#include <functional>
#include <cstdint>
#include <algorithm>
#include <cstring>
namespace arp {
using Ip = std::array<unsigned char,4>;
using Mac = std::array<unsigned char,6>;
using Bytes = std::vector<unsigned char>;
inline const Mac Broadcast = {255,255,255,255,255,255};
inline bool validMac(const Mac& m) { return !(m[0]&1) && m != Mac{}; }
inline bool validIp(const Ip& ip) { return ip[0] != 0 && ip[0] < 224 && ip[0] != 127; }
struct Entry { Ip ip{}; Mac mac{}; bool complete=false; uint64_t created=0,lastSend=0; unsigned attempts=0; };
struct Proxy { std::wstring device; Ip ip{}; Mac mac{}; };
enum class Event { None, GarpUpdated, GarpIgnored, ProxyReplied, Conflict };
// Protocol bytes are explicitly serialized; never depend on struct padding or host byte order.
inline Bytes packet(unsigned op,const Mac& mac,const Ip& ip,const Mac& target,const Ip& targetIp) {
    Bytes b(28,0); b[1]=1; b[2]=8; b[4]=6; b[5]=4; b[7]=(unsigned char)op;
    std::copy(mac.begin(),mac.end(),b.begin()+8); std::copy(ip.begin(),ip.end(),b.begin()+14);
    std::copy(target.begin(),target.end(),b.begin()+18); std::copy(targetIp.begin(),targetIp.end(),b.begin()+24); return b;
}
class Engine {
public:
    Ip localIp{}; Mac localMac{}; std::vector<Entry> cache; std::vector<Proxy> proxies;
    // Hardware addresses this host sent gratuitous ARP from; their echoes are not conflicts.
    std::vector<Mac> ownMacs;
    std::function<bool(const Mac& source,const Mac& destination,const Bytes&)> send;
    uint64_t requests=0,replies=0,received=0,sendErrors=0,conflicts=0,garps=0,proxyReplies=0;
    Event event=Event::None; Ip eventIp{}, eventPeer{}; Mac eventMac{}; uint64_t eventAt=0;
    void reset() { requests=replies=received=sendErrors=conflicts=garps=proxyReplies=0; event=Event::None; eventAt=0; ownMacs.clear(); }
    bool transmit(const Mac& src,const Mac& dst,const Bytes& b) { bool ok=send && send(src,dst,b); if(!ok) ++sendErrors; return ok; }
    void note(Event e,const Ip& ip,const Mac& mac,const Ip& peer,uint64_t now) { event=e; eventIp=ip; eventMac=mac; eventPeer=peer; eventAt=now; }
    std::vector<Entry>::iterator find(const Ip& ip) { return std::find_if(cache.begin(),cache.end(),[&](const Entry& e){return e.ip==ip;}); }
    void learn(const Ip& ip,const Mac& mac,uint64_t now) {
        auto it=find(ip);
        if(it==cache.end()) { if(cache.size()>=512) cache.erase(cache.begin()); cache.push_back({ip,mac,true,now,0,0}); }
        else *it={ip,mac,true,now,0,0};
    }
    bool request(const Ip& ip,uint64_t now) {
        if(!validIp(ip)||ip==localIp) return false;
        auto it=find(ip);
        if(it!=cache.end() && it->complete && now-it->created<1200000) return true;
        if(it!=cache.end()) cache.erase(it);
        if(cache.size()>=512) cache.erase(cache.begin());
        cache.push_back({ip,{},false,now,now,1});
        bool ok=transmit(localMac,Broadcast,packet(1,localMac,localIp,{},ip)); if(ok) ++requests; return ok;
    }
    // Gratuitous ARP: broadcast request whose sender and target protocol address are both our own IP.
    bool gratuitous(const Mac& mac) {
        if(!validIp(localIp)||!validMac(mac)) return false;
        if(mac!=localMac && std::find(ownMacs.begin(),ownMacs.end(),mac)==ownMacs.end()) ownMacs.push_back(mac);
        bool ok=transmit(mac,Broadcast,packet(1,mac,localIp,{},localIp)); if(ok) ++garps; return ok;
    }
    bool receive(const unsigned char* p,size_t n,uint64_t now) {
        if(!p||n<28||p[0]||p[1]!=1||p[2]!=8||p[3]||p[4]!=6||p[5]!=4||p[6]||(p[7]!=1&&p[7]!=2)) return false;
        const unsigned op=p[7];
        Mac sm{},tm{}; Ip si{},ti{};
        std::copy_n(p+8,6,sm.begin()); std::copy_n(p+14,4,si.begin());
        std::copy_n(p+18,6,tm.begin()); std::copy_n(p+24,4,ti.begin());
        if(!validMac(sm)||sm==localMac||std::find(ownMacs.begin(),ownMacs.end(),sm)!=ownMacs.end()) return false;
        if(si!=Ip{}&&!validIp(si)) return false;
        if(si==localIp) {
            // Another hardware address claims our IP: duplicate IP address.
            ++conflicts; ++received; note(Event::Conflict,si,sm,ti,now);
            if(op==1&&ti==localIp&&transmit(localMac,sm,packet(2,localMac,localIp,sm,si))) ++replies;
            return true;
        }
        if(validIp(si)&&si==ti) {
            // Gratuitous ARP only refreshes an entry that is already cached.
            ++received;
            if(find(si)!=cache.end()) { learn(si,sm,now); note(Event::GarpUpdated,si,sm,si,now); }
            else note(Event::GarpIgnored,si,sm,si,now);
            return true;
        }
        const bool mine=ti==localIp&&(op==1||tm==localMac);
        auto proxy=proxies.end();
        if(op==1&&!mine) proxy=std::find_if(proxies.begin(),proxies.end(),[&](const Proxy& x){return x.ip==ti;});
        const bool known=validIp(si)&&find(si)!=cache.end();
        if(!mine&&proxy==proxies.end()&&!known) return false;
        ++received;
        if(validIp(si)) learn(si,sm,now);
        if(op==1&&mine) { if(transmit(localMac,sm,packet(2,localMac,localIp,sm,si))) ++replies; }
        else if(proxy!=proxies.end()) {
            const Mac mac=proxy->mac;
            if(transmit(mac,sm,packet(2,mac,ti,sm,si))) { ++proxyReplies; note(Event::ProxyReplied,ti,mac,si,now); }
        }
        return true;
    }
    void tick(uint64_t now) {
        cache.erase(std::remove_if(cache.begin(),cache.end(),[&](const Entry& e){return now-e.created >= (e.complete?1200000ULL:180000ULL);}),cache.end());
        for(auto& e:cache) if(!e.complete&&e.attempts<3&&now-e.lastSend>=1000) {
            ++e.attempts; e.lastSend=now;
            if(transmit(localMac,Broadcast,packet(1,localMac,localIp,{},e.ip))) ++requests;
        }
    }
};
}
