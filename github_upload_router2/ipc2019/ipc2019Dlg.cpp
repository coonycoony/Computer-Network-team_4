#include "pch.h"
#include "ipc2019Dlg.h"
#include "EntryDlg.h"
BEGIN_MESSAGE_MAP(Cipc2019Dlg,CDialogEx)
    ON_BN_CLICKED(IDC_START,&Cipc2019Dlg::OnStart)
    ON_BN_CLICKED(IDC_END,&Cipc2019Dlg::OnEnd)
    ON_CBN_SELCHANGE(IDC_ADAPTER0,&Cipc2019Dlg::OnAdapter0)
    ON_CBN_SELCHANGE(IDC_ADAPTER1,&Cipc2019Dlg::OnAdapter1)
    ON_BN_CLICKED(IDC_ROUTE_ADD,&Cipc2019Dlg::OnRouteAdd)
    ON_BN_CLICKED(IDC_ROUTE_DELETE,&Cipc2019Dlg::OnRouteDelete)
    ON_BN_CLICKED(IDC_DELETE,&Cipc2019Dlg::OnDelete)
    ON_BN_CLICKED(IDC_PROXY_ADD,&Cipc2019Dlg::OnProxyAdd)
    ON_BN_CLICKED(IDC_PROXY_DELETE,&Cipc2019Dlg::OnProxyDelete)
    ON_WM_TIMER()
END_MESSAGE_MAP()
using Lock=std::lock_guard<std::recursive_mutex>;
static void Columns(CListCtrl& list,std::initializer_list<std::pair<LPCWSTR,int>> columns){
    list.SetExtendedStyle(LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES|LVS_EX_DOUBLEBUFFER);
    CRect rect;list.GetClientRect(&rect);int index=0;
    for(const auto& c:columns)list.InsertColumn(index++,c.first,LVCFMT_LEFT,rect.Width()*c.second/100);
}
static CString FlagText(unsigned flags){
    CString s;if(flags&CIPLayer::Up)s+=L"U";if(flags&CIPLayer::Gateway)s+=L"G";if(flags&CIPLayer::Host)s+=L"H";
    return s.IsEmpty()?CString(L"-"):s;
}
static CString ProtocolText(const CIPLayer::Log& l){
    CString s;
    if(l.protocol==1){
        if(l.icmpType==8)return L"ICMP Echo Request";
        if(l.icmpType==0)return L"ICMP Echo Reply";
        s.Format(L"ICMP type %u",l.icmpType);return s;
    }
    if(l.protocol==6)return L"TCP";
    if(l.protocol==17)return L"UDP";
    s.Format(L"IP proto %u",l.protocol);return s;
}
static CString VerdictText(CIPLayer::Verdict v){
    switch(v){
    case CIPLayer::Verdict::Forwarded:return L"전달";
    case CIPLayer::Verdict::Queued:return L"ARP 확인 후 전달";
    case CIPLayer::Verdict::Local:return L"라우터 자신 (미처리)";
    case CIPLayer::Verdict::EchoReplied:return L"라우터 자신 → Echo Reply 응답";
    case CIPLayer::Verdict::NoRoute:return L"경로 없음 (폐기)";
    case CIPLayer::Verdict::PortDown:return L"출력 포트 정지";
    case CIPLayer::Verdict::TtlExpired:return L"TTL 만료 (폐기)";
    case CIPLayer::Verdict::TooBig:return L"MTU 초과 (폐기)";
    default:return L"ARP/송신 실패";
    }
}
BOOL Cipc2019Dlg::OnInitDialog(){
    CDialogEx::OnInitDialog();SetIcon(AfxGetApp()->LoadIcon(IDR_MAINFRAME),TRUE);
    for(int i=0;i<2;++i){adapterCombo[i].SubclassDlgItem(IDC_ADAPTER0+i,this);ipControl[i].SubclassDlgItem(IDC_IP0+i,this);
        CRect rect;adapterCombo[i].GetWindowRect(&rect);adapterCombo[i].SetDroppedWidth(rect.Width()*2);}   // adapter names are long
    routeList.SubclassDlgItem(IDC_ROUTES,this);cacheList.SubclassDlgItem(IDC_CACHE,this);proxyList.SubclassDlgItem(IDC_PROXY,this);
    Columns(routeList,{{L"Destination",19},{L"NetMask",19},{L"GateWay",19},{L"Flag",10},{L"Interface",17},{L"Metric",12}});
    Columns(cacheList,{{L"IP Address",28},{L"Ethernet Address",36},{L"Interface",18},{L"Flag",16}});
    Columns(proxyList,{{L"IP Address",30},{L"Ethernet Address",40},{L"Interface",28}});
    // NI(i) <-> Ethernet(i) per interface; both Ethernet layers deliver to the shared ARP and IP layers.
    ipLayer.arpLayer=&arpLayer;
    for(int i=0;i<2;++i){
        manager.AddLayer(&ni[i]);manager.AddLayer(&ethernet[i]);ni[i].SetUpperUnderLayer(&ethernet[i]);
        ethernet[i].arpLayer=&arpLayer;ethernet[i].ipLayer=&ipLayer;arpLayer.ports[i]=&ethernet[i];
        arpLayer.engine[i].send=[this,i](const arp::Mac& src,const arp::Mac& dst,const arp::Bytes& bytes){return ethernet[i].SendArp(src,dst,bytes)!=FALSE;};
    }
    manager.AddLayer(&arpLayer);manager.AddLayer(&ipLayer);
    Populate();RenderRoutes();RenderProxy();SetTimer(1,250,nullptr);return TRUE;
}
void Cipc2019Dlg::Show(const CString& s){CString old;GetDlgItemText(IDC_STATUS,old);if(old!=s)SetDlgItemText(IDC_STATUS,s);}
// Messages from user actions stay visible for a few seconds before automatic status text replaces them.
void Cipc2019Dlg::Status(const CString& s){Show(s);hold=GetTickCount64()+4000;}
const AdapterInfo* Cipc2019Dlg::Selected(int port){
    if(port<0||port>1)return nullptr;int index=adapterCombo[port].GetCurSel();
    return index>=0&&index<(int)adapters.size()?&adapters[index]:nullptr;
}
// Interface IPs typed in the UI (zero when a field is incomplete).
void Cipc2019Dlg::PortIps(arp::Ip* ips){for(int i=0;i<2;++i)if(!GetIp(ipControl[i],ips[i]))ips[i]={};}
void Cipc2019Dlg::SetRunning(bool running){
    for(int i=0;i<2;++i){adapterCombo[i].EnableWindow(!running);ipControl[i].EnableWindow(!running);}
    GetDlgItem(IDC_START)->EnableWindow(!running&&adapters.size()>=2);GetDlgItem(IDC_END)->EnableWindow(running);
}
void Cipc2019Dlg::Stop(){
    active=false;for(auto& n:ni)n.CloseAdapter();
    {Lock l(arpLayer.mutex);for(int i=0;i<2;++i){ipLayer.ports[i].active=false;arpLayer.engine[i].cache.clear();}arpLayer.waiting.clear();}
    SetRunning(false);
}
void Cipc2019Dlg::ShowAdapter(int port){
    const AdapterInfo* a=Selected(port);SetDlgItemText(IDC_MAC0+port,a?MacText(a->mac):CString());
    if(a&&a->ip!=arp::Ip{}){
        CString s;s.Format(L"%s Network 어댑터에 Windows TCP/IPv4(%s)가 켜져 있습니다. 어댑터 속성에서 TCP/IPv4 체크를 해제하세요.",port?L"외부":L"내부",IpText(a->ip).GetString());Status(s);
    }
}
void Cipc2019Dlg::Populate(){
    CString error;auto devices=ni[0].Devices();adapters=EnumerateAdapters(devices,error);
    for(int i=0;i<2;++i){
        adapterCombo[i].ResetContent();for(const auto& a:adapters)adapterCombo[i].AddString(a.label);
        if(i<(int)adapters.size())adapterCombo[i].SetCurSel(i);
    }
    Status(L"내부/외부 Network 어댑터와 인터페이스 IP를 입력하고, Static Routing Table에 엔트리를 Add한 뒤 Start를 누르세요.");
    for(int i=0;i<2;++i)ShowAdapter(i);
    if(!error.IsEmpty())Status(error);
    else if(devices.empty())Status(ni[0].Error());
    else if(adapters.size()<2)Status(L"유선 Ethernet 어댑터가 2개 필요합니다 (Wi-Fi 사용 불가). 랜카드를 연결한 뒤 프로그램을 다시 실행하세요.");
    SetRunning(false);
}
void Cipc2019Dlg::OnAdapter0(){ShowAdapter(0);}
void Cipc2019Dlg::OnAdapter1(){ShowAdapter(1);}
void Cipc2019Dlg::OnStart(){
    if(active)return;
    const AdapterInfo* chosen[2]{};arp::Ip ips[2]{};
    for(int i=0;i<2;++i){
        CString s;chosen[i]=Selected(i);LPCWSTR side=i?L"외부":L"내부";
        if(!chosen[i]||!chosen[i]->up||chosen[i]->device.empty()){s.Format(L"%s Network: 랜선이 연결된 캡처 가능 유선 어댑터를 선택하세요 (Npcap 설치 확인).",side);Status(s);return;}
        if(!GetIp(ipControl[i],ips[i])||!arp::validIp(ips[i])){s.Format(L"%s Network: 인터페이스 IP를 입력하세요 (예: 192.168.1.1).",side);Status(s);ipControl[i].SetFocus();return;}
    }
    if(chosen[0]->device==chosen[1]->device){Status(L"내부/외부 Network에 서로 다른 어댑터를 선택하세요.");return;}
    if(ips[0]==ips[1]){Status(L"두 인터페이스의 IP가 같습니다. 서로 다른 네트워크의 주소를 입력하세요.");return;}
    {
        Lock l(arpLayer.mutex);arpLayer.waiting.clear();arpLayer.waitDrops=0;ipLayer.reset();
        for(int i=0;i<2;++i){
            auto& e=arpLayer.engine[i];e.cache.clear();e.localIp=ips[i];e.localMac=chosen[i]->mac;e.reset();
            ipLayer.ports[i]={ips[i],true};ethernet[i].source=chosen[i]->mac;
        }
    }
    for(int i=0;i<2;++i)if(!ni[i].OpenAdapter(chosen[i]->device.c_str())||!ni[i].StartReceiveThread()){
        CString s;s.Format(L"%s Network: %s",i?L"외부":L"내부",ni[i].Error().GetString());Stop();Status(s);return;
    }
    active=true;SetRunning(true);
    CString s=L"라우터 동작 중. Host A에서 Host B로 ping을 보내 보세요.";
    {
        // Each interface IP should fall in a directly connected (Flag U) entry on that interface.
        Lock l(arpLayer.mutex);
        for(int i=1;i>=0;--i){
            const CIPLayer::Route* route=ipLayer.Lookup(ips[i]);
            if(!route||route->port!=i||(route->flags&CIPLayer::Gateway))
                s.Format(L"라우터 동작 중. 단, %s(%s)이 속한 네트워크의 UP 엔트리가 Routing Table에 없습니다. 먼저 직접 연결된 네트워크를 Add하세요.",PortText(i).GetString(),IpText(ips[i]).GetString());
        }
    }
    for(int i=0;i<2;++i)if(chosen[i]->ip!=arp::Ip{})
        s.Format(L"라우터 동작 중. 경고: %s Network 어댑터에 Windows TCP/IPv4가 켜져 있어 Windows도 패킷을 처리합니다. TCP/IPv4 체크를 해제하세요.",i?L"외부":L"내부");
    Status(s);Render();
}
void Cipc2019Dlg::OnEnd(){if(!active)return;Stop();Status(L"라우터를 정지했습니다. Routing Table과 Proxy ARP Table은 유지됩니다.");}
void Cipc2019Dlg::OnRouteAdd(){
    std::vector<CIPLayer::Route> routes;{Lock l(arpLayer.mutex);routes=ipLayer.routes;}
    arp::Ip ips[2];PortIps(ips);
    CRouteAddDlg dialog(routes,ips,this);if(dialog.DoModal()!=IDOK)return;
    const CIPLayer::Route& r=dialog.route;
    {
        Lock l(arpLayer.mutex);auto& table=ipLayer.routes;
        auto it=std::find_if(table.begin(),table.end(),[&](const CIPLayer::Route& x){return x.destination==r.destination&&x.mask==r.mask;});
        if(it==table.end())table.push_back(r);else *it=r;
    }
    RenderRoutes();
    CString s;s.Format(L"Routing 엔트리 추가: %s/%u → %s, %s, Flag %s",IpText(r.destination).GetString(),PrefixLength(r.mask),
        (r.flags&CIPLayer::Gateway)?IpText(r.gateway).GetString():L"직접 연결",PortText(r.port).GetString(),FlagText(r.flags).GetString());
    Status(s);
}
void Cipc2019Dlg::OnRouteDelete(){
    POSITION pos=routeList.GetFirstSelectedItemPosition();if(!pos){Status(L"삭제할 Routing 엔트리를 선택하세요.");return;}
    const int row=routeList.GetNextSelectedItem(pos);
    {Lock l(arpLayer.mutex);auto& routes=ipLayer.routes;if(row<(int)routes.size())routes.erase(routes.begin()+row);}
    RenderRoutes();
}
void Cipc2019Dlg::RenderRoutes(){
    Lock l(arpLayer.mutex);routeList.DeleteAllItems();
    for(const auto& r:ipLayer.routes){
        int row=routeList.InsertItem(routeList.GetItemCount(),IpText(r.destination));
        routeList.SetItemText(row,1,IpText(r.mask));routeList.SetItemText(row,2,r.gateway==arp::Ip{}?CString(L"-"):IpText(r.gateway));
        routeList.SetItemText(row,3,FlagText(r.flags));routeList.SetItemText(row,4,PortText(r.port));
        CString metric;metric.Format(L"%u",r.metric);routeList.SetItemText(row,5,metric);
    }
}
void Cipc2019Dlg::OnProxyAdd(){
    CString devices[2];arp::Mac macs[2]{};arp::Ip ips[2];PortIps(ips);
    for(int i=0;i<2;++i){
        const AdapterInfo* a=Selected(i);devices[i].Format(L"%s (%s Network)",PortText(i).GetString(),i?L"외부":L"내부");
        if(a)macs[i]=a->mac;
    }
    CProxyAddDlg dialog(devices,macs,ips,this);if(dialog.DoModal()!=IDOK)return;
    {
        Lock l(arpLayer.mutex);auto& p=arpLayer.engine[dialog.port].proxies;
        const arp::Proxy entry{std::wstring(PortText(dialog.port).GetString()),dialog.ip,dialog.mac};
        auto it=std::find_if(p.begin(),p.end(),[&](const arp::Proxy& x){return x.ip==dialog.ip;});
        if(it==p.end())p.push_back(entry);else *it=entry;
    }
    RenderProxy();
    CString s;s.Format(L"Proxy ARP 항목 추가: %s 에서 %s 에 대한 ARP Request에 %s 로 대신 응답합니다.",PortText(dialog.port).GetString(),IpText(dialog.ip).GetString(),MacText(dialog.mac).GetString());Status(s);
}
void Cipc2019Dlg::OnProxyDelete(){
    POSITION pos=proxyList.GetFirstSelectedItemPosition();if(!pos){Status(L"삭제할 Proxy ARP 항목을 선택하세요.");return;}
    const int row=proxyList.GetNextSelectedItem(pos),port=(int)proxyList.GetItemData(row);arp::Ip ip{};
    if(port<0||port>1||!ParseIp(proxyList.GetItemText(row,0),ip))return;
    {Lock l(arpLayer.mutex);auto& p=arpLayer.engine[port].proxies;p.erase(std::remove_if(p.begin(),p.end(),[&](const arp::Proxy& x){return x.ip==ip;}),p.end());}
    RenderProxy();
}
void Cipc2019Dlg::RenderProxy(){
    Lock l(arpLayer.mutex);proxyList.DeleteAllItems();
    for(int i=0;i<2;++i)for(const auto& p:arpLayer.engine[i].proxies){
        int row=proxyList.InsertItem(proxyList.GetItemCount(),IpText(p.ip));proxyList.SetItemData(row,i);
        proxyList.SetItemText(row,1,MacText(p.mac));proxyList.SetItemText(row,2,PortText(i));
    }
}
void Cipc2019Dlg::OnDelete(){
    POSITION pos=cacheList.GetFirstSelectedItemPosition();if(!pos){Status(L"삭제할 ARP Cache 항목을 선택하세요.");return;}
    const int row=cacheList.GetNextSelectedItem(pos),port=(int)cacheList.GetItemData(row);arp::Ip ip{};
    if(port<0||port>1||!ParseIp(cacheList.GetItemText(row,0),ip))return;
    {Lock l(arpLayer.mutex);auto& c=arpLayer.engine[port].cache;c.erase(std::remove_if(c.begin(),c.end(),[&](const arp::Entry& e){return e.ip==ip;}),c.end());}
    Render();
}
void Cipc2019Dlg::Render(){
    CString selected;int selectedPort=-1;POSITION pos=cacheList.GetFirstSelectedItemPosition();
    if(pos){int row=cacheList.GetNextSelectedItem(pos);selected=cacheList.GetItemText(row,0);selectedPort=(int)cacheList.GetItemData(row);}
    Lock l(arpLayer.mutex);cacheList.SetRedraw(FALSE);cacheList.DeleteAllItems();
    for(int i=0;i<2;++i)for(const auto& entry:arpLayer.engine[i].cache){
        CString ip=IpText(entry.ip);int row=cacheList.InsertItem(cacheList.GetItemCount(),ip);cacheList.SetItemData(row,i);
        cacheList.SetItemText(row,1,entry.complete?MacText(entry.mac):CString(L"??:??:??:??:??:??"));
        cacheList.SetItemText(row,2,PortText(i));cacheList.SetItemText(row,3,entry.complete?L"Complete":L"Incomplete");
        if(i==selectedPort&&ip==selected)cacheList.SetItemState(row,LVIS_SELECTED,LVIS_SELECTED);
    }
    cacheList.SetRedraw(TRUE);cacheList.Invalidate(FALSE);
    // Counters plus the most recent datagram the router handled.
    const auto& a=arpLayer.engine[0];const auto& b=arpLayer.engine[1];const auto& last=ipLayer.last;
    CString stats,recent,old;
    stats.Format(L"IP 수신 %llu  전달 %llu  경로 없음 %llu  TTL 만료 %llu\r\nARP Request %llu  Reply %llu  ARP 실패 %llu  Ping 응답 %llu",
        ipLayer.received,ipLayer.forwarded,ipLayer.noRoute,ipLayer.ttlExpired,a.requests+b.requests,a.replies+b.replies+a.proxyReplies+b.proxyReplies,ipLayer.arpFailed+arpLayer.waitDrops,ipLayer.echoReplies);
    if(ipLayer.logSeq){
        if(last.verdict==CIPLayer::Verdict::EchoReplied)recent.Format(L"\r\n최근: %s  %s → %s\r\n        %s 수신, %s (%s 송신)",ProtocolText(last).GetString(),IpText(last.source).GetString(),IpText(last.destination).GetString(),PortText(last.in).GetString(),VerdictText(last.verdict).GetString(),PortText(last.out).GetString());
        else if(last.out>=0)recent.Format(L"\r\n최근: %s  %s → %s\r\n        %s → %s, TTL %u, %s",ProtocolText(last).GetString(),IpText(last.source).GetString(),IpText(last.destination).GetString(),PortText(last.in).GetString(),PortText(last.out).GetString(),last.ttl,VerdictText(last.verdict).GetString());
        else recent.Format(L"\r\n최근: %s  %s → %s\r\n        %s 수신, %s",ProtocolText(last).GetString(),IpText(last.source).GetString(),IpText(last.destination).GetString(),PortText(last.in).GetString(),VerdictText(last.verdict).GetString());
    }
    stats+=recent;GetDlgItemText(IDC_STATS,old);if(old!=stats)SetDlgItemText(IDC_STATS,stats);
    const ULONGLONG now=GetTickCount64();
    for(int i=0;i<2;++i){
        const auto& e=arpLayer.engine[i];CString s;
        if(e.event==arp::Event::Conflict&&now-e.eventAt<10000){
            s.Format(L"%s: duplicate IP address sent from Ethernet address: %s (다른 호스트가 인터페이스 IP %s 를 사용 중입니다)",PortText(i).GetString(),MacText(e.eventMac).GetString(),IpText(e.eventIp).GetString());Show(s);return;
        }
        if(e.event==arp::Event::ProxyReplied&&now-e.eventAt<4000){
            s.Format(L"%s Proxy ARP 응답: %s 의 %s 요청에 %s 로 대신 응답했습니다.",PortText(i).GetString(),IpText(e.eventPeer).GetString(),IpText(e.eventIp).GetString(),MacText(e.eventMac).GetString());Show(s);return;
        }
    }
    if(!active||now<hold)return;
    for(int i=0;i<2;++i){
        CString s,error=ni[i].Error();
        if(!error.IsEmpty()){s.Format(L"%s: %s",PortText(i).GetString(),error.GetString());Show(s);return;}
        const auto& c=arpLayer.engine[i].cache;
        auto failed=std::find_if(c.begin(),c.end(),[&](const arp::Entry& x){return !x.complete&&x.attempts>=3&&now-x.lastSend>=1000&&now-x.lastSend<10000;});
        if(failed!=c.end()){s.Format(L"%s: next hop %s 의 ARP 응답이 없습니다. 해당 호스트의 연결·IP 설정과 Routing Table의 Interface를 확인하세요.",PortText(i).GetString(),IpText(failed->ip).GetString());Show(s);return;}
    }
}
void Cipc2019Dlg::OnTimer(UINT_PTR id){
    if(id==1){
        if(active){
            for(int i=0;i<2;++i)if(!ni[i].Running()){
                CString s;s.Format(L"%s: %s",PortText(i).GetString(),ni[i].Error().GetString());Stop();Status(s);break;
            }
            if(active)arpLayer.Tick(GetTickCount64());
        }
        Render();
    }
    CDialogEx::OnTimer(id);
}
void Cipc2019Dlg::OnCancel(){KillTimer(1);Stop();CDialogEx::OnCancel();}
