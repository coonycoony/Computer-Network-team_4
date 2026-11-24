#pragma once
#include "resource.h"
#include "IPLayer.h"
#include "AdapterInfo.h"
CString PortText(int port);
// "Routing Table Entry 추가": validates one entry against the current table and the interface IPs.
class CRouteAddDlg:public CDialogEx {
public:
    CRouteAddDlg(const std::vector<CIPLayer::Route>& routes,const arp::Ip* portIps,CWnd* parent)
        :CDialogEx(IDD_ROUTE_ADD,parent),routes(routes),portIps{portIps[0],portIps[1]}{}
    CIPLayer::Route route;
protected:
    BOOL OnInitDialog() override;
    void OnOK() override;
    afx_msg void OnHost();
    DECLARE_MESSAGE_MAP()
private:
    std::vector<CIPLayer::Route> routes; arp::Ip portIps[2];
    CIPAddressCtrl destination,mask,gateway; CComboBox port;
    void Warn(const CString& s){MessageBox(s,L"Routing Table Entry 추가",MB_ICONWARNING);}
};
// "Proxy Entry 추가": the router answers ARP requests for ip on the chosen interface with mac.
class CProxyAddDlg:public CDialogEx {
public:
    CProxyAddDlg(const CString* devices,const arp::Mac* macs,const arp::Ip* portIps,CWnd* parent)
        :CDialogEx(IDD_PROXY_ADD,parent),devices{devices[0],devices[1]},macs{macs[0],macs[1]},portIps{portIps[0],portIps[1]}{}
    int port=0; arp::Ip ip{}; arp::Mac mac{};
protected:
    BOOL OnInitDialog() override;
    void OnOK() override;
    afx_msg void OnDevice();
    DECLARE_MESSAGE_MAP()
private:
    CString devices[2]; arp::Mac macs[2]; arp::Ip portIps[2];
    CIPAddressCtrl address; CComboBox device;
    void Warn(const CString& s){MessageBox(s,L"Proxy Entry 추가",MB_ICONWARNING);}
};
