#include "pch.h"
#include "EthernetLayer.h"
BOOL CEthernetLayer::SendArp(const arp::Mac& destination,const arp::Bytes& payload) {
    if(!mp_UnderLayer||payload.size()!=28) return FALSE;
    // 60 bytes excluding the NIC-generated FCS: Ethernet minimum frame length.
    unsigned char frame[60]{};
    memcpy(frame,destination.data(),6); memcpy(frame+6,source.data(),6);
    frame[12]=8; frame[13]=6; memcpy(frame+14,payload.data(),28);
    return mp_UnderLayer->Send(frame,sizeof(frame));
}
BOOL CEthernetLayer::Receive(unsigned char* data,int length) {
    if(!data||length<42||!m_nUpperLayerCount) return FALSE;
    if(memcmp(data,source.data(),6)&&memcmp(data,arp::Broadcast.data(),6)) return FALSE;
    if(!memcmp(data+6,source.data(),6)) return FALSE;
    unsigned offset=14; unsigned type=(data[12]<<8)|data[13];
    // Accept up to two VLAN tags when a driver retains them on receive.
    for(int i=0;i<2&&(type==0x8100||type==0x88a8);++i) {
        if(length<(int)offset+4) return FALSE;
        type=(data[offset+2]<<8)|data[offset+3]; offset+=4;
    }
    if(type!=0x0806||length<(int)offset+28) return FALSE;
    if(memcmp(data+6,data+offset+8,6)) return FALSE;
    return mp_aUpperLayer[0]->Receive(data+offset,length-offset);
}
