#pragma once
#include "ArpProtocol.h"
#include <string>
struct AdapterInfo { std::string device; CString label; arp::Mac mac{}; arp::Ip ip{}; unsigned prefix=0,index=0; bool up=false,wifi=false,hardware=false; };
std::vector<AdapterInfo> EnumerateAdapters(const std::vector<std::string>& devices,CString& error);
CString IpText(const arp::Ip& ip);
CString MacText(const arp::Mac& mac);
bool ParseIp(const CString& text,arp::Ip& ip);
bool OnLink(const AdapterInfo& adapter,const arp::Ip& ip);
