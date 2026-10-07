#pragma once
#include <array>
#include <vector>
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
// Protocol bytes are explicitly serialized; never depend on struct padding or host byte order.
inline Bytes packet(unsigned op,const Mac& mac,const Ip& ip,const Mac& target,const Ip& targetIp) {
    Bytes b(28,0); b[1]=1; b[2]=8; b[4]=6; b[5]=4; b[7]=(unsigned char)op;
    std::copy(mac.begin(),mac.end(),b.begin()+8); std::copy(ip.begin(),ip.end(),b.begin()+14);
    std::copy(target.begin(),target.end(),b.begin()+18); std::copy(targetIp.begin(),targetIp.end(),b.begin()+24); return b;
}
class Engine {
public:
    Ip localIp{}; Mac localMac{}; std::vector<Entry> cache;
    std::function<bool(const Mac&,const Bytes&)> send;
    uint64_t requests=0,replies=0,received=0,sendErrors=0,conflicts=0;
    bool transmit(const Mac& dst,const Bytes& b) { bool ok=send && send(dst,b); if(!ok) ++sendErrors; return ok; }
    void learn(const Ip& ip,const Mac& mac,uint64_t now) {
        auto it=std::find_if(cache.begin(),cache.end(),[&](const Entry& e){return e.ip==ip;});
        if(it==cache.end()) { if(cache.size()>=512) cache.erase(cache.begin()); cache.push_back({ip,mac,true,now,0,0}); }
        else *it={ip,mac,true,now,0,0};
    }
    bool request(const Ip& ip,uint64_t now) {
        if(!validIp(ip)||ip==localIp) return false;
        auto it=std::find_if(cache.begin(),cache.end(),[&](const Entry& e){return e.ip==ip;});
        if(it!=cache.end() && it->complete && now-it->created<1200000) return true;
        if(it!=cache.end()) cache.erase(it);
        if(cache.size()>=512) cache.erase(cache.begin());
        cache.push_back({ip,{},false,now,now,1});
        bool ok=transmit(Broadcast,packet(1,localMac,localIp,{},ip)); if(ok) ++requests; return ok;
    }
    bool receive(const unsigned char* p,size_t n,uint64_t now) {
        if(!p||n<28||p[0]||p[1]!=1||p[2]!=8||p[3]||p[4]!=6||p[5]!=4||p[6]||(p[7]!=1&&p[7]!=2)) return false;
        Mac sm{},tm{}; Ip si{},ti{};
        std::copy_n(p+8,6,sm.begin()); std::copy_n(p+14,4,si.begin());
        std::copy_n(p+18,6,tm.begin()); std::copy_n(p+24,4,ti.begin());
        if(!validMac(sm)||sm==localMac) return false;
        if(si==localIp) { ++conflicts; return false; }
        if(si!=Ip{}&&!validIp(si)) return false;
        // Replies must actually target this interface. Requests for other hosts are ignored.
        if(ti!=localIp || (p[7]==2 && tm!=localMac)) return false;
        ++received;
        if(validIp(si)) learn(si,sm,now);
        if(p[7]==1) { bool ok=transmit(sm,packet(2,localMac,localIp,sm,si)); if(ok) ++replies; }
        return true;
    }
    void tick(uint64_t now) {
        cache.erase(std::remove_if(cache.begin(),cache.end(),[&](const Entry& e){return now-e.created >= (e.complete?1200000ULL:180000ULL);}),cache.end());
        for(auto& e:cache) if(!e.complete&&e.attempts<3&&now-e.lastSend>=1000) {
            ++e.attempts; e.lastSend=now;
            if(transmit(Broadcast,packet(1,localMac,localIp,{},e.ip))) ++requests;
        }
    }
};
}
