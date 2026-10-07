#include "pch.h"
#include "ARPLayer.h"
BOOL CARPLayer::Receive(unsigned char* data,int length) {
    if(length<0) return FALSE;
    std::lock_guard<std::mutex> guard(mutex);
    return engine.receive(data,(size_t)length,GetTickCount64());
}
