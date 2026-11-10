#include "pch.h"
#include "EthernetLayer.h"
#include "ARPLayer.h"
#include "IPLayer.h"
BOOL CEthernetLayer::SendArp(const arp::Mac& sender,const arp::Mac& destination,const arp::Bytes& payload) {
    if(!mp_UnderLayer||payload.size()!=28) return FALSE;
    // 60 bytes excluding the NIC-generated FCS: Ethernet minimum frame length.
    // The Ethernet source follows the ARP sender hardware address (proxy entries).
    unsigned char frame[60]{};
    memcpy(frame,destination.data(),6); memcpy(frame+6,sender.data(),6);
    frame[12]=8; frame[13]=6; memcpy(frame+14,payload.data(),28);
    return mp_UnderLayer->Send(frame,sizeof(frame));
}
// Forwarded datagram: destination = next hop MAC, source = this (outgoing) interface MAC.
BOOL CEthernetLayer::SendIp(const arp::Mac& destination,const unsigned char* packet,int length) {
    if(!mp_UnderLayer||!packet||length<20||length>ETHER_MAX_DATA_SIZE) return FALSE;
    unsigned char frame[ETHER_MAX_SIZE]{};
    memcpy(frame,destination.data(),6); memcpy(frame+6,source.data(),6);
    frame[12]=8; frame[13]=0; memcpy(frame+14,packet,length);
    return mp_UnderLayer->Send(frame,length+14<60?60:length+14);
}
BOOL CEthernetLayer::Receive(unsigned char* data,int length) {
    if(!data||length<14) return FALSE;
    // Only frames addressed to this interface (or broadcast) are processed; our own transmissions are ignored.
    if(memcmp(data,source.data(),6)&&memcmp(data,arp::Broadcast.data(),6)) return FALSE;
    if(!memcmp(data+6,source.data(),6)) return FALSE;
    unsigned offset=14; unsigned type=(data[12]<<8)|data[13];
    // Accept up to two VLAN tags when a driver retains them on receive.
    for(int i=0;i<2&&(type==0x8100||type==0x88a8);++i) {
        if(length<(int)offset+4) return FALSE;
        type=(data[offset+2]<<8)|data[offset+3]; offset+=4;
    }
    if(type==0x0806) {
        if(!arpLayer||length<(int)offset+28) return FALSE;
        if(memcmp(data+6,data+offset+8,6)) return FALSE;
        return arpLayer->Receive(port,data+offset,length-offset);
    }
    if(type==0x0800&&ipLayer) return ipLayer->Receive(port,data+offset,length-offset);
    return FALSE;
}
