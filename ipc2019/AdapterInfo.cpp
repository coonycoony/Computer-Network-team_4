#include "pch.h"
#include <iphlpapi.h>
#include <netioapi.h>
#include "AdapterInfo.h"
#pragma comment(lib,"iphlpapi.lib")
CString IpText(const arp::Ip& ip){CString s;s.Format(L"%u.%u.%u.%u",ip[0],ip[1],ip[2],ip[3]);return s;}
CString MacText(const arp::Mac& m){CString s;s.Format(L"%02X:%02X:%02X:%02X:%02X:%02X",m[0],m[1],m[2],m[3],m[4],m[5]);return s;}
bool ParseIp(const CString& text,arp::Ip& ip){
    CString t(text);t.Trim();unsigned a,b,c,d;int end=0;
    if(swscanf_s(t,L"%u.%u.%u.%u%n",&a,&b,&c,&d,&end)!=4||end!=t.GetLength()||a>255||b>255||c>255||d>255)return false;
    ip={(unsigned char)a,(unsigned char)b,(unsigned char)c,(unsigned char)d};return arp::validIp(ip);
}
bool OnLink(const AdapterInfo& a,const arp::Ip& ip){
    uint32_t local=0,target=0;for(int i=0;i<4;++i){local=(local<<8)|a.ip[i];target=(target<<8)|ip[i];}
    uint32_t mask=a.prefix?0xffffffffu<<(32-a.prefix):0;
    if((local&mask)!=(target&mask))return false;
    if(a.prefix<31&&((target&~mask)==0||(target&~mask)==~mask))return false;
    return true;
}
std::vector<AdapterInfo> EnumerateAdapters(const std::vector<std::string>& devices,CString& error){
    ULONG size=16384,rc=ERROR_BUFFER_OVERFLOW;std::vector<unsigned char> data;
    for(int i=0;i<3&&rc==ERROR_BUFFER_OVERFLOW;++i){data.resize(size);rc=GetAdaptersAddresses(AF_INET,GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_DNS_SERVER,nullptr,(IP_ADAPTER_ADDRESSES*)data.data(),&size);}
    std::vector<AdapterInfo> result;
    if(rc!=NO_ERROR){error.Format(L"IPv4 어댑터 조회 실패 (Windows 오류 %lu)",rc);return result;}
    for(auto a=(IP_ADAPTER_ADDRESSES*)data.data();a;a=a->Next){
        if(a->PhysicalAddressLength!=6||(a->IfType!=IF_TYPE_ETHERNET_CSMACD&&a->IfType!=IF_TYPE_IEEE80211))continue;
        std::string device;
        for(const auto& name:devices){auto pos=name.find('{');if(pos!=std::string::npos&&_stricmp(name.c_str()+pos,a->AdapterName)==0){device=name;break;}}
        for(auto u=a->FirstUnicastAddress;u;u=u->Next){
            if(!u->Address.lpSockaddr||u->Address.lpSockaddr->sa_family!=AF_INET||u->DadState!=IpDadStatePreferred||u->OnLinkPrefixLength>32)continue;
            AdapterInfo item;item.device=device;memcpy(item.mac.data(),a->PhysicalAddress,6);
            memcpy(item.ip.data(),&((sockaddr_in*)u->Address.lpSockaddr)->sin_addr,4);
            if(!arp::validIp(item.ip)||!arp::validMac(item.mac))continue;
            MIB_IF_ROW2 row{};row.InterfaceLuid=a->Luid;if(GetIfEntry2(&row)==NO_ERROR)item.hardware=row.InterfaceAndOperStatusFlags.HardwareInterface;
            item.prefix=u->OnLinkPrefixLength;item.index=a->IfIndex;item.up=a->OperStatus==IfOperStatusUp;item.wifi=a->IfType==IF_TYPE_IEEE80211;
            item.label.Format(L"%s | %s | %s/%u%s%s",a->FriendlyName,item.wifi?L"Wi-Fi":L"Ethernet",IpText(item.ip).GetString(),item.prefix,item.up?L"":L" | 연결 끊김",device.empty()?L" | 캡처 불가":L"");
            result.push_back(item);
        }
    }
    std::stable_sort(result.begin(),result.end(),[](const AdapterInfo& a,const AdapterInfo& b){return ((a.up&&!a.device.empty())*4+a.hardware*2+a.wifi)>((b.up&&!b.device.empty())*4+b.hardware*2+b.wifi);});
    return result;
}
