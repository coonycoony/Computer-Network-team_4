#pragma once
#include "BaseLayer.h"
#include <afxmt.h>
#include <vector>

class CFileAppLayer : public CBaseLayer
{
public:
    CFileAppLayer(char* name);
    virtual ~CFileAppLayer();
    enum { FILE_HEADER_SIZE = 12, FILE_DATA_SIZE = ETHER_MAX_DATA_SIZE - 12, FILE_NAME_SIZE = 256 };
    enum { FILE_TYPE_SINGLE = 0, FILE_TYPE_FIRST = 1, FILE_TYPE_MIDDLE = 2, FILE_TYPE_LAST = 3 };
    enum { FILE_MSG_INFO = 0, FILE_MSG_DATA = 1, FILE_MSG_END = 2 };
    struct FILE_APP_HEADER {
        unsigned long fapp_totlen;
        unsigned short fapp_type;
        unsigned char fapp_msg_type, fapp_unused;
        unsigned long fapp_seq_num;
        unsigned char fapp_data[FILE_DATA_SIZE];
    };
    struct FILE_INFO { char file_name[FILE_NAME_SIZE]; unsigned long file_size; };
    typedef FILE_APP_HEADER* PFILE_APP_HEADER;
    typedef FILE_INFO* PFILE_INFO;
    BOOL SendFile(const CString& path);
    BOOL StartFileTransfer(const CString& path);
    void StopFileTransfer();
    BOOL IsFileTransferRunning() const;
    BOOL IsReceiveRunning();
    int GetSendProgress() const;
    int GetReceiveProgress() const;
    CString GetLastReceivedFilePath();
    void CheckReceiveTimeout();
    virtual BOOL Receive(unsigned char* data);
    virtual BOOL Receive(unsigned char* data, int length);
private:
    struct FILE_THREAD_PARAM { CFileAppLayer* layer; CString path; };
    static UINT __cdecl FileTransferThread(LPVOID param);
    unsigned short ConvertByteOrder16(unsigned short value);
    unsigned long ConvertByteOrder32(unsigned long value);
    BOOL CStringToUtf8(const CString& source, char* destination, int destinationSize);
    CString Utf8ToCString(const char* source);
    BOOL SendFrame(unsigned short type, unsigned char msg, unsigned long seq,
        const unsigned char* data, int length, unsigned long total);
    void ResetReceive();
    BOOL FailReceive();
    BOOL CompleteReceive();
    CString ReceiveDirectory();
    CWinThread* m_pFileThread;
    mutable volatile LONG m_bFileTransferRunning, m_nSendProgress, m_nReceiveProgress, m_cancel;
    CCriticalSection m_receiveLock;
    CFile m_spool;
    BOOL m_receiving, m_endSeen;
    unsigned long m_total, m_received, m_fragmentCount;
    ULONGLONG m_lastReceiveTick;
    std::vector<bool> m_fragments;
    CString m_tempPath, m_targetPath, m_lastPath;
};
