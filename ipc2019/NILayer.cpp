#include "pch.h"
#include "NILayer.h"
#include <chrono>
CNILayer::~CNILayer(){ CloseAdapter(); if(library) FreeLibrary(library); }
void CNILayer::SetError(const CString& e){std::lock_guard<std::mutex> l(errorMutex);error=e;}
CString CNILayer::Error(){std::lock_guard<std::mutex> l(errorMutex);return error;}
bool CNILayer::Load(){
    if(library) return true;
    wchar_t system[MAX_PATH]{}; GetSystemDirectoryW(system,MAX_PATH);
    CString path(system); path+=L"\\Npcap\\wpcap.dll";
    library=LoadLibraryExW(path,nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);
    if(!library){SetError(L"Npcap을 찾을 수 없습니다. npcap.com에서 Npcap을 설치한 후 다시 실행하세요.");return false;}
#define API(member,name) member=reinterpret_cast<decltype(member)>(GetProcAddress(library,name)); if(!member){SetError(L"Npcap API를 불러오지 못했습니다.");FreeLibrary(library);library=nullptr;return false;}
    API(open,"pcap_open_live") API(close,"pcap_close") API(next,"pcap_next_ex") API(send,"pcap_sendpacket")
    API(nonblock,"pcap_setnonblock") API(datalink,"pcap_datalink") API(geterr,"pcap_geterr")
    API(find,"pcap_findalldevs") API(freeDevices,"pcap_freealldevs")
#undef API
    return true;
}
std::vector<std::string> CNILayer::Devices(){
    std::vector<std::string> result; if(!Load())return result;
    CaptureDevice* first=nullptr; char message[256]{};
    if(find(&first,message)<0){SetError(CString(message));return result;}
    for(auto d=first;d;d=d->next)if(d->name)result.push_back(d->name);
    if(first)freeDevices(first);return result;
}
BOOL CNILayer::OpenAdapter(const char* name){
    CloseAdapter(); if(!Load())return FALSE;
    char message[256]{};
    // Managed Wi-Fi exposes Ethernet frames. Do not enable monitor/promiscuous mode.
    capture=open(name,65536,0,25,message);
    if(!capture){SetError(CString(L"어댑터 열기 실패: ")+CString(message));return FALSE;}
    if(datalink(capture)!=1){SetError(L"Ethernet 형식이 아닙니다. Wi-Fi 모니터 모드를 해제하세요.");CloseAdapter();return FALSE;}
    if(nonblock(capture,1,message)<0){SetError(CString(message));CloseAdapter();return FALSE;}
    SetError(L"");return TRUE;
}
BOOL CNILayer::Send(unsigned char* data,int length){
    std::lock_guard<std::mutex> l(io);
    if(!capture||!data||length<14)return FALSE;
    if(send(capture,data,length)){SetError(CString(L"송신 실패: ")+CString(geterr(capture)));return FALSE;} return TRUE;
}
BOOL CNILayer::StartReceiveThread(){
    if(!capture)return FALSE;
    running=true;
    try {reader=std::thread([this]{
        while(running){
            std::vector<unsigned char> bytes;int result;
            {std::lock_guard<std::mutex> l(io);CaptureHeader* h=nullptr;const unsigned char* p=nullptr;
                result=next(capture,&h,&p);
                if(result==1&&h&&p&&h->caplen<=65536) bytes.assign(p,p+h->caplen);
                if(result<0)SetError(CString(L"수신 중단: ")+CString(geterr(capture)));
            }
            if(result<0){running=false;break;}
            if(!bytes.empty()&&m_nUpperLayerCount)mp_aUpperLayer[0]->Receive(bytes.data(),(int)bytes.size());
            if(result==0)std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    });}catch(...){running=false;SetError(L"수신 스레드를 시작하지 못했습니다.");return FALSE;}
    return TRUE;
}
void CNILayer::CloseAdapter(){
    running=false;if(reader.joinable())reader.join();
    std::lock_guard<std::mutex> l(io);if(capture){close(capture);capture=nullptr;}
}
