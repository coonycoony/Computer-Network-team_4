#pragma once
#include "ArpProtocol.h"
#include <string>
// ip/prefix: an IPv4 address Windows still has bound to the adapter (router ports should have none).
struct AdapterInfo { std::string device; CString name,label; arp::Mac mac{}; arp::Ip ip{}; unsigned prefix=0,index=0; bool up=false,hardware=false; };
std::vector<AdapterInfo> EnumerateAdapters(const std::vector<std::string>& devices,CString& error);
CString IpText(const arp::Ip& ip);
CString MacText(const arp::Mac& mac);
bool ParseAddress(const CString& text,arp::Ip& ip);
bool ParseIp(const CString& text,arp::Ip& ip);
bool ParseMask(const CString& text,arp::Ip& mask);
bool ParseMac(const CString& text,arp::Mac& mac);
unsigned PrefixLength(const arp::Ip& mask);
// IP Address control helpers: GetIp fails unless all four fields are filled.
bool GetIp(CIPAddressCtrl& control,arp::Ip& ip);
void SetIp(CIPAddressCtrl& control,const arp::Ip& ip);
