#include "pch.h"
#include "EntryDlg.h"
CString PortText(int port){CString s;s.Format(L"Port %d",port);return s;}
BEGIN_MESSAGE_MAP(CRouteAddDlg,CDialogEx)
    ON_BN_CLICKED(IDC_ENTRY_HOST,&CRouteAddDlg::OnHost)
END_MESSAGE_MAP()
BOOL CRouteAddDlg::OnInitDialog(){
    CDialogEx::OnInitDialog();
    destination.SubclassDlgItem(IDC_ENTRY_DEST,this);mask.SubclassDlgItem(IDC_ENTRY_MASK,this);
    gateway.SubclassDlgItem(IDC_ENTRY_GATEWAY,this);port.SubclassDlgItem(IDC_ENTRY_PORT,this);
    port.AddString(L"Port 0 (내부 Network)");port.AddString(L"Port 1 (외부 Network)");port.SetCurSel(0);
    CheckDlgButton(IDC_ENTRY_UP,BST_CHECKED);
    return TRUE;
}
// Flag H: the destination is one host, so the netmask is 255.255.255.255.
void CRouteAddDlg::OnHost(){if(IsDlgButtonChecked(IDC_ENTRY_HOST))SetIp(mask,{255,255,255,255});}
void CRouteAddDlg::OnOK(){
    CString s;CIPLayer::Route r;r.port=port.GetCurSel()==1?1:0;
    r.flags=(IsDlgButtonChecked(IDC_ENTRY_UP)?CIPLayer::Up:0)|(IsDlgButtonChecked(IDC_ENTRY_GW)?CIPLayer::Gateway:0)|(IsDlgButtonChecked(IDC_ENTRY_HOST)?CIPLayer::Host:0);
    if(!GetIp(destination,r.destination)){Warn(L"Destination을 입력하세요 (기본 경로는 0.0.0.0).");destination.SetFocus();return;}
    const bool maskRead=GetIp(mask,r.mask);const uint32_t dst=arp::toU32(r.destination),m=arp::toU32(r.mask);
    if(!maskRead||(m|(m-1))!=0xffffffffu){Warn(L"Netmask가 올바르지 않습니다. 앞에서부터 연속된 1 비트여야 합니다 (예: 255.255.255.0, 기본 경로는 0.0.0.0).");mask.SetFocus();return;}
    if((dst&m)!=dst){s.Format(L"Destination의 호스트 부분이 0이 아닙니다. 네트워크 주소 %s 를 입력하세요.",IpText(arp::fromU32(dst&m)).GetString());Warn(s);return;}
    if((r.flags&CIPLayer::Host)&&m!=0xffffffffu){Warn(L"Host 플래그 엔트리의 Netmask는 255.255.255.255 이어야 합니다.");return;}
    const bool hasGateway=!gateway.IsBlank();
    if(hasGateway&&!GetIp(gateway,r.gateway)){Warn(L"Gateway 주소의 네 칸을 모두 입력하세요.");gateway.SetFocus();return;}
    if(r.flags&CIPLayer::Gateway){
        if(!hasGateway||!arp::validIp(r.gateway)){Warn(L"Gateway 플래그 엔트리에는 다음 라우터의 Gateway IP가 필요합니다.");gateway.SetFocus();return;}
        if(r.gateway==portIps[r.port]){Warn(L"Gateway가 라우터 자신의 인터페이스 IP입니다. 직접 연결된 네트워크는 UP 플래그만 사용하세요.");return;}
        // The next router must sit on a network directly connected to that interface (its Flag U entry).
        bool connected=false,anyConnected=false;
        for(const auto& x:routes)if(x.port==r.port&&(x.flags&CIPLayer::Up)&&!(x.flags&CIPLayer::Gateway)){
            anyConnected=true;if((arp::toU32(r.gateway)&arp::toU32(x.mask))==arp::toU32(x.destination))connected=true;
        }
        if(anyConnected&&!connected){s.Format(L"Gateway %s 가 %s 에 직접 연결된 네트워크(UP 엔트리)에 속하지 않습니다.",IpText(r.gateway).GetString(),PortText(r.port).GetString());Warn(s);return;}
    }
    if(!(r.flags&CIPLayer::Up)&&MessageBox(L"UP 플래그가 없는 엔트리는 라우팅에 사용되지 않습니다. 그래도 추가할까요?",L"Routing Table Entry 추가",MB_ICONQUESTION|MB_YESNO)!=IDYES)return;
    r.metric=(r.flags&CIPLayer::Gateway)?2:1;
    route=r;CDialogEx::OnOK();
}
BEGIN_MESSAGE_MAP(CProxyAddDlg,CDialogEx)
    ON_CBN_SELCHANGE(IDC_ENTRY_DEVICE,&CProxyAddDlg::OnDevice)
END_MESSAGE_MAP()
BOOL CProxyAddDlg::OnInitDialog(){
    CDialogEx::OnInitDialog();
    address.SubclassDlgItem(IDC_ENTRY_IP,this);device.SubclassDlgItem(IDC_ENTRY_DEVICE,this);
    for(const auto& d:devices)device.AddString(d);
    device.SetCurSel(0);OnDevice();return TRUE;
}
// Default answer: the chosen interface's own MAC (classic proxy ARP).
void CProxyAddDlg::OnDevice(){const int sel=device.GetCurSel();if(sel>=0&&sel<2)SetDlgItemText(IDC_ENTRY_MAC,macs[sel]==arp::Mac{}?CString():MacText(macs[sel]));}
void CProxyAddDlg::OnOK(){
    CString macText;GetDlgItemText(IDC_ENTRY_MAC,macText);port=device.GetCurSel()==1?1:0;
    if(!GetIp(address,ip)||!arp::validIp(ip)){Warn(L"IP Address가 올바르지 않습니다 (예: 10.0.0.1).");address.SetFocus();return;}
    if(ip==portIps[0]||ip==portIps[1]){Warn(L"라우터 인터페이스 자신의 IP는 Proxy 항목으로 추가할 수 없습니다.");return;}
    if(!ParseMac(macText,mac)){Warn(L"Ethernet Address가 올바르지 않습니다. 유니캐스트 MAC을 입력하세요 (예: 00:50:56:C0:00:01).");GetDlgItem(IDC_ENTRY_MAC)->SetFocus();return;}
    CDialogEx::OnOK();
}
