#pragma once
#include "resource.h"
#include "LayerManager.h"
#include "NILayer.h"
#include "EthernetLayer.h"
#include "ARPLayer.h"
#include "AdapterInfo.h"
class Cipc2019Dlg:public CDialogEx {
public:
    Cipc2019Dlg(CWnd* p=nullptr):CDialogEx(IDD_IPC2019_DIALOG,p),ni((char*)"NI"),ethernet((char*)"Ethernet"){}
    ~Cipc2019Dlg(){ni.CloseAdapter();}
protected:
    BOOL OnInitDialog() override;
    void OnOK() override {};
    void OnCancel() override;
    afx_msg void OnSelect();
    afx_msg void OnAdapter();
    afx_msg void OnRefresh();
    afx_msg void OnSend();
    afx_msg void OnDelete();
    afx_msg void OnDeleteAll();
    afx_msg void OnGarp();
    afx_msg void OnProxyAdd();
    afx_msg void OnProxyDelete();
    afx_msg void OnTimer(UINT_PTR id);
    DECLARE_MESSAGE_MAP()
private:
    CNILayer ni; CEthernetLayer ethernet; CARPLayer arpLayer; CLayerManager manager;
    CComboBox combo,proxyDevice; CListCtrl list,proxyList;
    std::vector<AdapterInfo> adapters;
    bool active=false; unsigned ticks=0; ULONGLONG hold=0;
    void Populate(); void Stop(); void Render(); void RenderProxy();
    void Status(const CString& s); void Show(const CString& s);
};
