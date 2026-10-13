#include "pch.h"
#include "ipc2019Dlg.h"
BEGIN_MESSAGE_MAP(Cipc2019Dlg,CDialogEx)
    ON_BN_CLICKED(IDC_SELECT,&Cipc2019Dlg::OnSelect)
    ON_BN_CLICKED(IDC_REFRESH,&Cipc2019Dlg::OnRefresh)
    ON_BN_CLICKED(IDC_SEND,&Cipc2019Dlg::OnSend)
    ON_BN_CLICKED(IDC_DELETE,&Cipc2019Dlg::OnDelete)
    ON_BN_CLICKED(IDC_DELETE_ALL,&Cipc2019Dlg::OnDeleteAll)
    ON_BN_CLICKED(IDC_GARP_SEND,&Cipc2019Dlg::OnGarp)
    ON_BN_CLICKED(IDC_PROXY_ADD,&Cipc2019Dlg::OnProxyAdd)
    ON_BN_CLICKED(IDC_PROXY_DELETE,&Cipc2019Dlg::OnProxyDelete)
    ON_CBN_SELCHANGE(IDC_ADAPTER,&Cipc2019Dlg::OnAdapter)
    ON_WM_TIMER()
END_MESSAGE_MAP()
BOOL Cipc2019Dlg::OnInitDialog(){
    CDialogEx::OnInitDialog();SetIcon(AfxGetApp()->LoadIcon(IDR_MAINFRAME),TRUE);
    combo.SubclassDlgItem(IDC_ADAPTER,this);list.SubclassDlgItem(IDC_CACHE,this);
    proxyDevice.SubclassDlgItem(IDC_PROXY_DEVICE,this);proxyList.SubclassDlgItem(IDC_PROXY,this);
    list.SetExtendedStyle(LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES|LVS_EX_DOUBLEBUFFER);
    CRect rect;list.GetClientRect(&rect);int width=rect.Width();
    list.InsertColumn(0,L"IP Address",LVCFMT_LEFT,width*30/100);
    list.InsertColumn(1,L"Ethernet Address",LVCFMT_LEFT,width*40/100);
    list.InsertColumn(2,L"Status",LVCFMT_LEFT,width*28/100);
    proxyList.SetExtendedStyle(LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES|LVS_EX_DOUBLEBUFFER);
    proxyList.GetClientRect(&rect);width=rect.Width();
    proxyList.InsertColumn(0,L"Device",LVCFMT_LEFT,width*27/100);
    proxyList.InsertColumn(1,L"IP Address",LVCFMT_LEFT,width*31/100);
    proxyList.InsertColumn(2,L"Ethernet Address",LVCFMT_LEFT,width*40/100);
    manager.AddLayer(&ni);manager.AddLayer(&ethernet);manager.AddLayer(&arpLayer);
    ni.SetUpperUnderLayer(&ethernet);ethernet.SetUpperUnderLayer(&arpLayer);
    arpLayer.engine.send=[this](const arp::Mac& src,const arp::Mac& dst,const arp::Bytes& bytes){return ethernet.SendArp(src,dst,bytes)!=FALSE;};
    Populate();SetTimer(1,250,nullptr);return TRUE;
}
void Cipc2019Dlg::Show(const CString& s){CString old;GetDlgItemText(IDC_STATUS,old);if(old!=s)SetDlgItemText(IDC_STATUS,s);}
// Messages from user actions stay visible for a few seconds before automatic status text replaces them.
void Cipc2019Dlg::Status(const CString& s){Show(s);hold=GetTickCount64()+4000;}
void Cipc2019Dlg::Stop(){
    active=false;ni.CloseAdapter();GetDlgItem(IDC_SEND)->EnableWindow(FALSE);GetDlgItem(IDC_GARP_SEND)->EnableWindow(FALSE);
    {std::lock_guard<std::mutex> l(arpLayer.mutex);arpLayer.engine.cache.clear();}
    list.DeleteAllItems();SetDlgItemText(IDC_STATS,L"");
}
void Cipc2019Dlg::Populate(){
    combo.ResetContent();proxyDevice.ResetContent();CString error;auto devices=ni.Devices();
    adapters=EnumerateAdapters(devices,error);
    for(auto& a:adapters){combo.AddString(a.label);if(proxyDevice.FindStringExact(-1,a.name)<0)proxyDevice.AddString(a.name);}
    if(!adapters.empty()){combo.SetCurSel(0);OnAdapter();}
    else{SetDlgItemText(IDC_LOCAL_IP,L"");SetDlgItemText(IDC_LOCAL_MAC,L"");Status(L"사용 가능한 IPv4 유선랜/Wi-Fi가 없습니다. 연결과 Windows IPv4 설정을 확인하세요.");}
    if(!error.IsEmpty())Status(error);
    else if(devices.empty())Status(ni.Error());
    GetDlgItem(IDC_SELECT)->EnableWindow(!adapters.empty());
}
void Cipc2019Dlg::OnAdapter(){
    Stop();int index=combo.GetCurSel();if(index<0||index>=(int)adapters.size())return;
    const auto& a=adapters[index];SetDlgItemText(IDC_LOCAL_IP,IpText(a.ip));SetDlgItemText(IDC_LOCAL_MAC,MacText(a.mac));
    SetDlgItemText(IDC_GARP_MAC,MacText(a.mac));SetDlgItemText(IDC_PROXY_MAC,MacText(a.mac));
    proxyDevice.SetCurSel(proxyDevice.FindStringExact(-1,a.name));
    Status(L"실제 IPv4 / MAC 주소를 불러왔습니다. Select를 눌러 ARP 수신을 시작하세요.");
}
void Cipc2019Dlg::OnRefresh(){Stop();Populate();}
void Cipc2019Dlg::OnSelect(){
    Stop();int index=combo.GetCurSel();if(index<0||index>=(int)adapters.size())return;
    auto& a=adapters[index];
    if(!a.up||a.device.empty()){Status(L"연결된 캡처 가능 어댑터를 선택하세요. Npcap 설치와 연결 상태를 확인하세요.");return;}
    CString error;auto current=EnumerateAdapters(ni.Devices(),error);
    auto match=std::find_if(current.begin(),current.end(),[&](const AdapterInfo& x){return x.device==a.device&&x.ip==a.ip&&x.mac==a.mac&&x.up;});
    if(match==current.end()){Status(L"어댑터 주소/연결이 변경되었습니다. Refresh 후 다시 선택하세요.");return;}
    a=*match;ethernet.source=a.mac;
    {std::lock_guard<std::mutex> l(arpLayer.mutex);auto& e=arpLayer.engine;e.localIp=a.ip;e.localMac=a.mac;e.reset();}
    if(!ni.OpenAdapter(a.device.c_str())||!ni.StartReceiveThread()){ni.CloseAdapter();Status(ni.Error());return;}
    active=true;GetDlgItem(IDC_SEND)->EnableWindow(TRUE);GetDlgItem(IDC_GARP_SEND)->EnableWindow(TRUE);
    Status(L"ARP 수신 중. 상대 PC의 IPv4를 입력하고 Send를 누르세요. 상대도 동일 LAN에 연결되어야 합니다.");
}
void Cipc2019Dlg::OnSend(){
    if(!active)return;CString text;GetDlgItemText(IDC_TARGET,text);arp::Ip ip{};
    if(!ParseIp(text,ip)){Status(L"올바른 상대 IPv4 주소를 입력하세요 (예: 192.168.0.20).");return;}
    const auto& a=adapters[combo.GetCurSel()];
    if(ip==a.ip){Status(L"자신의 주소입니다. 자신의 IP 알림은 Gratuitous ARP의 Send를 사용하세요.");return;}
    if(!OnLink(a,ip)){Status(L"상대 IP가 선택한 어댑터의 서브넷 밖이거나 네트워크/브로드캐스트 주소입니다.");return;}
    bool ok;{std::lock_guard<std::mutex> l(arpLayer.mutex);ok=arpLayer.engine.request(ip,GetTickCount64());}
    Status(ok?L"캐시 조회 / ARP 요청 처리 완료. 미응답 시 1초 간격 총 3회 시도하며 Incomplete는 3분 뒤 삭제됩니다.":ni.Error());Render();
}
void Cipc2019Dlg::OnGarp(){
    if(!active)return;const auto& a=adapters[combo.GetCurSel()];
    CString text;GetDlgItemText(IDC_GARP_MAC,text);text.Trim();arp::Mac mac=a.mac;
    if(!text.IsEmpty()&&!ParseMac(text,mac)){Status(L"H/W 주소 형식이 올바르지 않습니다. 유니캐스트 MAC을 입력하세요 (예: 00:0C:29:5D:8B:A9).");return;}
    bool ok;{std::lock_guard<std::mutex> l(arpLayer.mutex);ok=arpLayer.engine.gratuitous(mac);}
    CString s;
    if(ok)s.Format(L"GARP 전송 (Broadcast): Sender/Target IP %s, Sender H/W %s. 상대 캐시의 항목이 갱신되며, 응답이 오면 IP 중복입니다.",IpText(a.ip).GetString(),MacText(mac).GetString());
    else s=ni.Error();
    Status(s);Render();
}
void Cipc2019Dlg::OnProxyAdd(){
    CString device,ipText,macText;int sel=proxyDevice.GetCurSel();if(sel>=0)proxyDevice.GetLBText(sel,device);
    GetDlgItemText(IDC_PROXY_IP,ipText);GetDlgItemText(IDC_PROXY_MAC,macText);
    arp::Ip ip{};arp::Mac mac{};
    if(device.IsEmpty()){Status(L"Proxy ARP 항목의 Device를 선택하세요.");return;}
    if(!ParseIp(ipText,ip)){Status(L"Proxy ARP 항목의 IP 주소가 올바르지 않습니다 (예: 192.168.0.100).");return;}
    if(!ParseMac(macText,mac)){Status(L"Proxy ARP 항목의 MAC 주소가 올바르지 않습니다. 유니캐스트 MAC을 입력하세요.");return;}
    int index=combo.GetCurSel();
    if(index>=0&&index<(int)adapters.size()&&adapters[index].ip==ip){Status(L"자신의 IP는 Proxy ARP 항목으로 추가할 수 없습니다.");return;}
    {std::lock_guard<std::mutex> l(arpLayer.mutex);auto& p=arpLayer.engine.proxies;
        auto it=std::find_if(p.begin(),p.end(),[&](const arp::Proxy& x){return x.ip==ip;});
        if(it==p.end())p.push_back({std::wstring(device.GetString()),ip,mac});else *it={std::wstring(device.GetString()),ip,mac};
    }
    RenderProxy();SetDlgItemText(IDC_PROXY_IP,L"");
    CString s;s.Format(L"Proxy ARP 항목 추가: %s 에 대한 ARP Request에 %s 로 대신 응답합니다.",IpText(ip).GetString(),MacText(mac).GetString());Status(s);
}
void Cipc2019Dlg::OnProxyDelete(){
    POSITION pos=proxyList.GetFirstSelectedItemPosition();if(!pos){Status(L"삭제할 Proxy ARP 항목을 선택하세요.");return;}
    arp::Ip ip{};if(!ParseIp(proxyList.GetItemText(proxyList.GetNextSelectedItem(pos),1),ip))return;
    {std::lock_guard<std::mutex> l(arpLayer.mutex);auto& p=arpLayer.engine.proxies;p.erase(std::remove_if(p.begin(),p.end(),[&](const arp::Proxy& x){return x.ip==ip;}),p.end());}
    RenderProxy();
}
void Cipc2019Dlg::RenderProxy(){
    std::lock_guard<std::mutex> l(arpLayer.mutex);proxyList.DeleteAllItems();
    for(const auto& p:arpLayer.engine.proxies){int row=proxyList.InsertItem(proxyList.GetItemCount(),p.device.c_str());
        proxyList.SetItemText(row,1,IpText(p.ip));proxyList.SetItemText(row,2,MacText(p.mac));}
}
void Cipc2019Dlg::OnDelete(){
    POSITION pos=list.GetFirstSelectedItemPosition();if(!pos)return;int row=list.GetNextSelectedItem(pos);arp::Ip ip{};
    if(!ParseIp(list.GetItemText(row,0),ip))return;
    {std::lock_guard<std::mutex> l(arpLayer.mutex);auto& c=arpLayer.engine.cache;c.erase(std::remove_if(c.begin(),c.end(),[&](const arp::Entry& e){return e.ip==ip;}),c.end());}Render();
}
void Cipc2019Dlg::OnDeleteAll(){{std::lock_guard<std::mutex> l(arpLayer.mutex);arpLayer.engine.cache.clear();}Render();}
void Cipc2019Dlg::Render(){
    CString selected;POSITION pos=list.GetFirstSelectedItemPosition();if(pos)selected=list.GetItemText(list.GetNextSelectedItem(pos),0);
    std::lock_guard<std::mutex> l(arpLayer.mutex);const auto& e=arpLayer.engine;list.SetRedraw(FALSE);list.DeleteAllItems();
    for(const auto& entry:e.cache){CString ip=IpText(entry.ip);int row=list.InsertItem(list.GetItemCount(),ip);
        list.SetItemText(row,1,entry.complete?MacText(entry.mac):CString(L"??:??:??:??:??:??"));
        list.SetItemText(row,2,entry.complete?L"Complete":L"Incomplete");if(selected==ip)list.SetItemState(row,LVIS_SELECTED,LVIS_SELECTED);
    }
    list.SetRedraw(TRUE);list.Invalidate(FALSE);
    CString stats;stats.Format(L"Request TX: %llu   Reply TX: %llu   GARP TX: %llu   Proxy Reply TX: %llu   RX: %llu   TX error: %llu   IP conflict: %llu",
        e.requests,e.replies,e.garps,e.proxyReplies,e.received,e.sendErrors,e.conflicts);SetDlgItemText(IDC_STATS,stats);
    const ULONGLONG now=GetTickCount64();CString s;
    if(e.event==arp::Event::Conflict&&now-e.eventAt<10000){
        s.Format(L"duplicate IP address sent from Ethernet address: %s  (다른 호스트가 로컬 IP %s 를 사용 중입니다)",MacText(e.eventMac).GetString(),IpText(e.eventIp).GetString());Show(s);return;
    }
    if(e.event!=arp::Event::None&&e.event!=arp::Event::Conflict&&now-e.eventAt<6000){
        if(e.event==arp::Event::GarpUpdated)s.Format(L"GARP 수신: %s 의 Ethernet 주소가 %s 로 갱신되었습니다.",IpText(e.eventIp).GetString(),MacText(e.eventMac).GetString());
        else if(e.event==arp::Event::GarpIgnored)s.Format(L"GARP 수신: %s (%s) - 캐시에 없는 IP라 추가하지 않았습니다. 먼저 ARP 요청으로 캐시에 등록하세요.",IpText(e.eventIp).GetString(),MacText(e.eventMac).GetString());
        else s.Format(L"Proxy ARP 응답: %s 의 %s 요청에 Proxy 항목의 %s 로 대신 응답했습니다.",IpText(e.eventPeer).GetString(),IpText(e.eventIp).GetString(),MacText(e.eventMac).GetString());
        Show(s);return;
    }
    if(now<hold)return;
    if(e.sendErrors)Show(ni.Error());
    else if(std::any_of(e.cache.begin(),e.cache.end(),[&](const arp::Entry& x){return !x.complete&&x.attempts>=3&&now-x.created>=3500;}))
        Show(L"응답 없음: 상대 IP, 선택 어댑터, 동일 LAN/VLAN 및 공유기의 AP/클라이언트 격리 설정을 확인하세요.");
    else if(!e.cache.empty()&&std::all_of(e.cache.begin(),e.cache.end(),[](const arp::Entry& x){return x.complete;}))
        Show(L"ARP 주소 확인 완료. Complete 항목은 마지막 갱신으로부터 20분간 유지됩니다.");
}
void Cipc2019Dlg::OnTimer(UINT_PTR id){
    if(id==1&&active){
        if(!ni.Running()){CString error=ni.Error();Stop();Status(error);return;}
        {std::lock_guard<std::mutex> l(arpLayer.mutex);arpLayer.engine.tick(GetTickCount64());}Render();
        if(++ticks%20==0){CString error;auto current=EnumerateAdapters({},error);const auto& a=adapters[combo.GetCurSel()];
            if(!error.IsEmpty()||std::none_of(current.begin(),current.end(),[&](const AdapterInfo& x){return x.index==a.index&&x.ip==a.ip&&x.mac==a.mac&&x.prefix==a.prefix&&x.up;})){
                Stop();Status(L"연결 또는 IP/MAC 설정이 변경되었습니다. Refresh 후 Select를 누르세요.");
            }
        }
    }CDialogEx::OnTimer(id);
}
void Cipc2019Dlg::OnCancel(){KillTimer(1);Stop();CDialogEx::OnCancel();}
