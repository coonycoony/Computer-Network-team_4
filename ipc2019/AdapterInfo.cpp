#include "pch.h"
#include <iphlpapi.h>
#include <netioapi.h>
#include "AdapterInfo.h"
#pragma comment(lib,"iphlpapi.lib")
CString IpText(const arp::Ip& ip){CString s;s.Format(L"%u.%u.%u.%u",ip[0],ip[1],ip[2],ip[3]);return s;}
CString MacText(const arp::Mac& m){CString s;s.Format(L"%02X:%02X:%02X:%02X:%02X:%02X",m[0],m[1],m[2],m[3],m[4],m[5]);return s;}
// Any dotted quad: network addresses, masks and the default route 0.0.0.0.
bool ParseAddress(const CString& text,arp::Ip& ip){
    CString t(text);t.Trim();unsigned a,b,c,d;int end=0;
    if(swscanf_s(t,L"%u.%u.%u.%u%n",&a,&b,&c,&d,&end)!=4||end!=t.GetLength()||a>255||b>255||c>255||d>255)return false;
    ip={(unsigned char)a,(unsigned char)b,(unsigned char)c,(unsigned char)d};return true;
}
bool ParseIp(const CString& text,arp::Ip& ip){return ParseAddress(text,ip)&&arp::validIp(ip);}
bool ParseMask(const CString& text,arp::Ip& mask){
    if(!ParseAddress(text,mask))return false;
    const uint32_t m=arp::toU32(mask);return (m|(m-1))==0xffffffffu;   // contiguous one bits
}
bool ParseMac(const CString& text,arp::Mac& mac){
    CString t(text);t.Trim();t.Replace(L'-',L':');unsigned v[6];int end=0;
    if(t.GetLength()!=17||swscanf_s(t,L"%2x:%2x:%2x:%2x:%2x:%2x%n",&v[0],&v[1],&v[2],&v[3],&v[4],&v[5],&end)!=6||end!=17)return false;
    for(int i=0;i<6;++i)mac[i]=(unsigned char)v[i];return arp::validMac(mac);
}
unsigned PrefixLength(const arp::Ip& mask){unsigned n=0;for(uint32_t m=arp::toU32(mask);m&0x80000000u;m<<=1)++n;return n;}
bool GetIp(CIPAddressCtrl& control,arp::Ip& ip){BYTE a,b,c,d;if(control.GetAddress(a,b,c,d)!=4)return false;ip={a,b,c,d};return true;}
void SetIp(CIPAddressCtrl& control,const arp::Ip& ip){control.SetAddress(ip[0],ip[1],ip[2],ip[3]);}
std::vector<AdapterInfo> EnumerateAdapters(const std::vector<std::string>& devices,CString& error){
    std::vector<AdapterInfo> result;
    // Router ports run with Windows TCP/IPv4 unchecked, so adapters are listed from the interface table, not from IPv4 bindings.
    ULONG size=16384,rc=ERROR_BUFFER_OVERFLOW;std::vector<unsigned char> data;
    for(int i=0;i<3&&rc==ERROR_BUFFER_OVERFLOW;++i){data.resize(size);rc=GetAdaptersAddresses(AF_INET,GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST|GAA_FLAG_SKIP_DNS_SERVER,nullptr,(IP_ADAPTER_ADDRESSES*)data.data(),&size);}
    PMIB_IF_TABLE2 table=nullptr;DWORD status=GetIfTable2(&table);
    if(status!=NO_ERROR){error.Format(L"네트워크 어댑터 조회 실패 (Windows 오류 %lu)",status);return result;}
    for(ULONG i=0;i<table->NumEntries;++i){
        const MIB_IF_ROW2& row=table->Table[i];
        // Wired Ethernet only (Wi-Fi cannot be used); filter-driver rows duplicate the physical adapter.
        if(row.Type!=IF_TYPE_ETHERNET_CSMACD||row.PhysicalAddressLength!=6||row.InterfaceAndOperStatusFlags.FilterInterface)continue;
        AdapterInfo item;memcpy(item.mac.data(),row.PhysicalAddress,6);
        if(!arp::validMac(item.mac))continue;
        wchar_t guid[64]{};StringFromGUID2(row.InterfaceGuid,guid,64);CStringA guidText(guid);
        for(const auto& name:devices){auto pos=name.find('{');if(pos!=std::string::npos&&_stricmp(name.c_str()+pos,guidText)==0){item.device=name;break;}}
        item.hardware=row.InterfaceAndOperStatusFlags.HardwareInterface;
        if(item.device.empty()&&!item.hardware)continue;
        item.index=row.InterfaceIndex;item.up=row.OperStatus==IfOperStatusUp;item.name=row.Alias;
        if(rc==NO_ERROR)for(auto a=(IP_ADAPTER_ADDRESSES*)data.data();a;a=a->Next){
            if(a->IfIndex!=row.InterfaceIndex)continue;
            for(auto u=a->FirstUnicastAddress;u;u=u->Next)if(u->Address.lpSockaddr&&u->Address.lpSockaddr->sa_family==AF_INET&&u->OnLinkPrefixLength<=32){
                memcpy(item.ip.data(),&((sockaddr_in*)u->Address.lpSockaddr)->sin_addr,4);item.prefix=u->OnLinkPrefixLength;break;
            }
        }
        item.label.Format(L"%s (%s)%s%s%s",row.Alias,row.Description,item.up?L"":L" | 연결 끊김",item.device.empty()?L" | 캡처 불가":L"",item.ip!=arp::Ip{}?L" | Windows IPv4 사용 중":L"");
        result.push_back(item);
    }
    FreeMibTable(table);
    std::stable_sort(result.begin(),result.end(),[](const AdapterInfo& a,const AdapterInfo& b){return ((a.up&&!a.device.empty())*2+a.hardware)>((b.up&&!b.device.empty())*2+b.hardware);});
    return result;
}
