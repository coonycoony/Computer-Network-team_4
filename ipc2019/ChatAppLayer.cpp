#include "stdafx.h"
#include "pch.h"

#include "ChatAppLayer.h"
#include "EthernetLayer.h"


#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#define new DEBUG_NEW
#endif


CChatAppLayer::CChatAppLayer(char* pName)
    : CBaseLayer(pName),
    m_pReceiveBuffer(NULL),
    m_nReceiveTotalLength(0),
    m_nReceivedBytes(0),
    m_legacySrcAddr(0),
    m_legacyDstAddr(0)
{
    ResetHeader();
}


CChatAppLayer::~CChatAppLayer()
{
    ResetReceiveBuffer();
}


void CChatAppLayer::ResetHeader()
{
    m_sHeader.capp_totlen = 0;
    m_sHeader.capp_type = 0;
    m_sHeader.capp_unused = 0;

    memset(
        m_sHeader.capp_data,
        0,
        sizeof(m_sHeader.capp_data)
    );
}


void CChatAppLayer::ResetReceiveBuffer()
{
    if (m_pReceiveBuffer != NULL)
    {
        delete[] m_pReceiveBuffer;
        m_pReceiveBuffer = NULL;
    }

    m_nReceiveTotalLength = 0;
    m_nReceivedBytes = 0;
}


unsigned short CChatAppLayer::ConvertByteOrder16(
    unsigned short value)
{
    return (unsigned short)(
        ((value & 0x00FF) << 8) |
        ((value & 0xFF00) >> 8)
        );
}


// 기존 코드 호환용
void CChatAppLayer::SetSourceAddress(
    unsigned int src_addr)
{
    m_legacySrcAddr = src_addr;
}


void CChatAppLayer::SetDestinAddress(
    unsigned int dst_addr)
{
    m_legacyDstAddr = dst_addr;
}


unsigned int CChatAppLayer::GetSourceAddress()
{
    return m_legacySrcAddr;
}


unsigned int CChatAppLayer::GetDestinAddress()
{
    return m_legacyDstAddr;
}


BOOL CChatAppLayer::Send(
    unsigned char* ppayload,
    int nlength)
{
    if (ppayload == NULL)
        return FALSE;
    if (nlength <= 0)
        return FALSE;
    if (nlength > 0xFFFF)
        return FALSE;
    if (mp_UnderLayer == NULL)
        return FALSE;
    CEthernetLayer* pEthernet =
        (CEthernetLayer*)mp_UnderLayer;
    const int CHAT_DATA_SIZE =
        ETHER_MAX_DATA_SIZE -
        CHAT_HEADER_SIZE;
    int offset = 0;
    while (offset < nlength)
    {
        ResetHeader();
        m_sHeader.capp_totlen =
            ConvertByteOrder16(
                (unsigned short)nlength
            );
        int remain =
            nlength - offset;
        int fragmentLength =
            (remain > CHAT_DATA_SIZE)
            ? CHAT_DATA_SIZE
            : remain;
        if (offset == 0)
        {
            m_sHeader.capp_type =
                DATA_TYPE_FIRST;
        }
        else if (
            offset + fragmentLength >=
            nlength)
        {
            m_sHeader.capp_type =
                DATA_TYPE_LAST;
        }
        else
        {
            m_sHeader.capp_type =
                DATA_TYPE_MIDDLE;
        }
        memcpy(
            m_sHeader.capp_data,
            ppayload + offset,
            fragmentLength
        );
        if (!pEthernet->SendWithType(
            (unsigned char*)&m_sHeader,
            CHAT_HEADER_SIZE +
            fragmentLength,
            CEthernetLayer::CHAT_FRAME_TYPE))
        {
            return FALSE;
        }
        offset += fragmentLength;
    }
    return TRUE;
}


BOOL CChatAppLayer::Receive(
    unsigned char* ppayload)
{
    if (ppayload == NULL)
        return FALSE;


    PCHAT_APP_HEADER pHeader =
        (PCHAT_APP_HEADER)ppayload;


    const int CHAT_DATA_SIZE =
        ETHER_MAX_DATA_SIZE -
        CHAT_HEADER_SIZE;


    int totalLength =
        (int)ConvertByteOrder16(
            pHeader->capp_totlen
        );


    if (totalLength <= 0)
        return FALSE;


    // FIRST
    if (pHeader->capp_type ==
        DATA_TYPE_FIRST)
    {
        ResetReceiveBuffer();


        m_nReceiveTotalLength =
            totalLength;


        m_pReceiveBuffer =
            new unsigned char[
                m_nReceiveTotalLength + 1
            ];


        memset(
            m_pReceiveBuffer,
            0,
            m_nReceiveTotalLength + 1
        );


        int copyLength =
            (m_nReceiveTotalLength >
                CHAT_DATA_SIZE)
            ? CHAT_DATA_SIZE
            : m_nReceiveTotalLength;


        memcpy(
            m_pReceiveBuffer,
            pHeader->capp_data,
            copyLength
        );


        m_nReceivedBytes =
            copyLength;


        // 한 개 Fragment로 끝나는 경우
        if (m_nReceivedBytes >=
            m_nReceiveTotalLength)
        {
            m_pReceiveBuffer[
                m_nReceiveTotalLength
            ] = '\0';


            if (m_nUpperLayerCount > 0 &&
                mp_aUpperLayer[0] != NULL)
            {
                mp_aUpperLayer[0]->Receive(
                    m_pReceiveBuffer
                );
            }


            ResetReceiveBuffer();
        }


        return TRUE;
    }


    if (m_pReceiveBuffer == NULL)
        return FALSE;


    int remain =
        m_nReceiveTotalLength -
        m_nReceivedBytes;


    if (remain <= 0)
        return FALSE;


    // MIDDLE
    if (pHeader->capp_type ==
        DATA_TYPE_MIDDLE)
    {
        int copyLength =
            (remain > CHAT_DATA_SIZE)
            ? CHAT_DATA_SIZE
            : remain;


        memcpy(
            m_pReceiveBuffer +
            m_nReceivedBytes,
            pHeader->capp_data,
            copyLength
        );


        m_nReceivedBytes +=
            copyLength;


        return TRUE;
    }


    // LAST
    if (pHeader->capp_type ==
        DATA_TYPE_LAST)
    {
        int copyLength =
            (remain > CHAT_DATA_SIZE)
            ? CHAT_DATA_SIZE
            : remain;


        memcpy(
            m_pReceiveBuffer +
            m_nReceivedBytes,
            pHeader->capp_data,
            copyLength
        );


        m_nReceivedBytes +=
            copyLength;


        if (m_nReceivedBytes >=
            m_nReceiveTotalLength)
        {
            m_pReceiveBuffer[
                m_nReceiveTotalLength
            ] = '\0';


            if (m_nUpperLayerCount > 0 &&
                mp_aUpperLayer[0] != NULL)
            {
                mp_aUpperLayer[0]->Receive(
                    m_pReceiveBuffer
                );
            }


            ResetReceiveBuffer();

            return TRUE;
        }


        ResetReceiveBuffer();

        return FALSE;
    }


    return FALSE;
}
BOOL CChatAppLayer::Receive(unsigned char* payload, int length)
{
    if (!payload || length < CHAT_HEADER_SIZE) return FALSE;
    PCHAT_APP_HEADER h = (PCHAT_APP_HEADER)payload;
    int total = ConvertByteOrder16(h->capp_totlen);
    int remain = h->capp_type == DATA_TYPE_FIRST ? total : m_nReceiveTotalLength - m_nReceivedBytes;
    if (h->capp_type != DATA_TYPE_FIRST && total != m_nReceiveTotalLength) return FALSE;
    int needed = remain > ETHER_MAX_DATA_SIZE - CHAT_HEADER_SIZE ? ETHER_MAX_DATA_SIZE - CHAT_HEADER_SIZE : remain;
    if (needed <= 0 || length < CHAT_HEADER_SIZE + needed) return FALSE;
    return Receive(payload);
}
