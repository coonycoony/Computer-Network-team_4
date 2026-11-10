#pragma once
#include "BaseLayer.h"
#include <mutex>
#include <thread>
#include <atomic>
#include <string>
#include <vector>
// Stable Npcap C ABI subset. Loaded from the installed system Npcap only.
struct pcap;
struct CaptureHeader { long sec,usec; unsigned int caplen,len; };
struct CaptureDevice { CaptureDevice* next; char* name; char* description; void* addresses; unsigned int flags; };
class CNILayer:public CBaseLayer {
public:
    CNILayer(char* name):CBaseLayer(name){}
    ~CNILayer();
    bool Load();
    std::vector<std::string> Devices();
    BOOL OpenAdapter(const char* name);
    void CloseAdapter();
    BOOL Send(unsigned char* data,int length) override;
    BOOL StartReceiveThread();
    CString Error();
    bool Running() const { return running.load(); }
private:
    void SetError(const CString& error);
    HMODULE library=nullptr; pcap* capture=nullptr;
    std::mutex io,errorMutex;
    CString error;
    std::thread reader; std::atomic<bool> running{false};
    pcap* (__cdecl* open)(const char*,int,int,int,char*)=nullptr;
    void (__cdecl* close)(pcap*)=nullptr;
    int (__cdecl* next)(pcap*,CaptureHeader**,const unsigned char**)=nullptr;
    int (__cdecl* send)(pcap*,const unsigned char*,int)=nullptr;
    int (__cdecl* nonblock)(pcap*,int,char*)=nullptr;
    int (__cdecl* datalink)(pcap*)=nullptr;
    char* (__cdecl* geterr)(pcap*)=nullptr;
    int (__cdecl* find)(CaptureDevice**,char*)=nullptr;
    void (__cdecl* freeDevices)(CaptureDevice*)=nullptr;
};
