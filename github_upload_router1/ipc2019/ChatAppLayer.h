#pragma once

#include "BaseLayer.h"
#include "pch.h"


class CChatAppLayer : public CBaseLayer
{
public:
    CChatAppLayer(char* pName);
    virtual ~CChatAppLayer();

    virtual BOOL Send(unsigned char* ppayload, int nlength);
    virtual BOOL Receive(unsigned char* ppayload);
    virtual BOOL Receive(unsigned char* ppayload, int length);

    // 기존 IPC 프로젝트 코드와의 호환용
    void SetSourceAddress(unsigned int src_addr);
    void SetDestinAddress(unsigned int dst_addr);

    unsigned int GetSourceAddress();
    unsigned int GetDestinAddress();


public:
    enum
    {
        CHAT_HEADER_SIZE = 4,

        DATA_TYPE_FIRST = 0x00,
        DATA_TYPE_MIDDLE = 0x01,
        DATA_TYPE_LAST = 0x02
    };


    typedef struct _CHAT_APP_HEADER
    {
        // 전체 채팅 메시지 길이
        unsigned short capp_totlen;

        // FIRST / MIDDLE / LAST
        unsigned char capp_type;

        // 현재 사용하지 않음
        unsigned char capp_unused;

        // 실제 채팅 데이터
        unsigned char capp_data[
            ETHER_MAX_DATA_SIZE - CHAT_HEADER_SIZE
        ];

    } CHAT_APP_HEADER, * PCHAT_APP_HEADER;


private:
    void ResetHeader();
    void ResetReceiveBuffer();

    unsigned short ConvertByteOrder16(unsigned short value);


private:
    CHAT_APP_HEADER m_sHeader;

    // Fragment를 다시 합치기 위한 버퍼
    unsigned char* m_pReceiveBuffer;

    int m_nReceiveTotalLength;
    int m_nReceivedBytes;

    // 기존 IPC 코드 호환용
    unsigned int m_legacySrcAddr;
    unsigned int m_legacyDstAddr;
};