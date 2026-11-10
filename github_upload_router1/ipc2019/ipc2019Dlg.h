#pragma once
#include "resource.h"
#include "LayerManager.h"
#include "NILayer.h"
#include "EthernetLayer.h"
#include "ARPLayer.h"
#include "IPLayer.h"
#include "AdapterInfo.h"
class Cipc2019Dlg:public CDialogEx {
public:
    Cipc2019Dlg(CWnd* p=nullptr):CDialogEx(IDD_IPC2019_DIALOG,p){}
    ~Cipc2019Dlg(){for(auto& n:ni)n.CloseAdapter();}
protected:
    BOOL OnInitDialog() override;
    void OnOK() override {};
    void OnCancel() override;
    afx_msg void OnStart();
    afx_msg void OnEnd();
    afx_msg void OnAdapter0();
    afx_msg void OnAdapter1();
    afx_msg void OnRouteAdd();
    afx_msg void OnRouteDelete();
    afx_msg void OnDelete();
    afx_msg void OnProxyAdd();
    afx_msg void OnProxyDelete();
    afx_msg void OnTimer(UINT_PTR id);
    DECLARE_MESSAGE_MAP()
private:
    // Two interfaces (0 = 내부, 1 = 외부): NI and Ethernet layers per interface, ARP and IP layers shared.
    CNILayer ni[2]{{(char*)"NI0"},{(char*)"NI1"}};
    CEthernetLayer ethernet[2]{{(char*)"Ethernet0",0},{(char*)"Ethernet1",1}};
    CARPLayer arpLayer; CIPLayer ipLayer; CLayerManager manager;
    CComboBox adapterCombo[2]; CIPAddressCtrl ipControl[2]; CListCtrl routeList,cacheList,proxyList;
    std::vector<AdapterInfo> adapters;
    bool active=false; ULONGLONG hold=0;
    const AdapterInfo* Selected(int port);
    void PortIps(arp::Ip* ips);
    void Populate(); void Stop(); void ShowAdapter(int port); void SetRunning(bool running);
    void Render(); void RenderRoutes(); void RenderProxy();
    void Status(const CString& s); void Show(const CString& s);
};
