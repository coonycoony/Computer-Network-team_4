#include "pch.h"
#include "stdafx.h"
#include "FileAppLayer.h"
#include "EthernetLayer.h"
#include <stddef.h>
#include <new>

static_assert(offsetof(CFileAppLayer::FILE_APP_HEADER, fapp_data) == 12, "File header must be 12 bytes");
static_assert(sizeof(CFileAppLayer::FILE_APP_HEADER) == 1500, "File packet exceeds MTU");

CFileAppLayer::CFileAppLayer(char* name) : CBaseLayer(name), m_pFileThread(NULL),
    m_bFileTransferRunning(FALSE), m_nSendProgress(0), m_nReceiveProgress(-2), m_cancel(FALSE),
    m_receiving(FALSE), m_endSeen(FALSE), m_total(0), m_received(0), m_fragmentCount(0), m_lastReceiveTick(0) {}
CFileAppLayer::~CFileAppLayer() { StopFileTransfer(); ResetReceive(); }

BOOL CFileAppLayer::SendFrame(unsigned short type, unsigned char msg, unsigned long seq,
    const unsigned char* data, int length, unsigned long total)
{
    if (!mp_UnderLayer || length < 0 || length > FILE_DATA_SIZE || (length && !data)) return FALSE;
    FILE_APP_HEADER frame = {};
    frame.fapp_totlen = ConvertByteOrder32(total);
    frame.fapp_type = ConvertByteOrder16(type);
    frame.fapp_msg_type = msg;
    frame.fapp_seq_num = ConvertByteOrder32(seq);
    if (length) memcpy(frame.fapp_data, data, length);
    return ((CEthernetLayer*)mp_UnderLayer)->SendWithType((unsigned char*)&frame,
        FILE_HEADER_SIZE + length, CEthernetLayer::FILE_FRAME_TYPE);
}

BOOL CFileAppLayer::SendFile(const CString& path)
{
    CFile file;
    try {
        if (path.IsEmpty() || !file.Open(path, CFile::modeRead | CFile::shareDenyWrite | CFile::typeBinary)) return FALSE;
        ULONGLONG length = file.GetLength();
        if (length > 0xFFFFFFFFULL) return FALSE;
        unsigned long total = (unsigned long)length;
        CString name = path.Mid(path.ReverseFind(_T('\\')) + 1);
        name = name.Mid(name.ReverseFind(_T('/')) + 1);
        FILE_INFO info = {};
        if (!CStringToUtf8(name, info.file_name, FILE_NAME_SIZE)) return FALSE;
        info.file_size = ConvertByteOrder32(total);
        unsigned short startType = total <= FILE_DATA_SIZE ? FILE_TYPE_SINGLE : FILE_TYPE_FIRST;
        if (!SendFrame(startType, FILE_MSG_INFO, 0, (unsigned char*)&info, sizeof(info), total)) return FALSE;
        unsigned long sent = 0, seq = 1;
        unsigned char buffer[FILE_DATA_SIZE];
        while (sent < total) {
            if (InterlockedCompareExchange(&m_cancel, 0, 0)) return FALSE;
            UINT wanted = total - sent > FILE_DATA_SIZE ? FILE_DATA_SIZE : total - sent;
            UINT bytes = file.Read(buffer, wanted);
            if (bytes != wanted) return FALSE;
            unsigned short type = total <= FILE_DATA_SIZE ? FILE_TYPE_SINGLE :
                (sent + bytes == total ? FILE_TYPE_LAST : (seq == 1 ? FILE_TYPE_FIRST : FILE_TYPE_MIDDLE));
            if (!SendFrame(type, FILE_MSG_DATA, seq, buffer, bytes, total)) return FALSE;
            sent += bytes;
            ++seq;
            // Reserve 100% for successful transmission of the END frame.
            InterlockedExchange(&m_nSendProgress, (LONG)((ULONGLONG)sent * 99 / total));
            if ((seq % 32) == 0) Sleep(1);
        }
        if (InterlockedCompareExchange(&m_cancel, 0, 0)) return FALSE;
        if (!SendFrame(total <= FILE_DATA_SIZE ? FILE_TYPE_SINGLE : FILE_TYPE_LAST,
            FILE_MSG_END, seq, NULL, 0, total)) return FALSE;
        InterlockedExchange(&m_nSendProgress, 100);
        return TRUE;
    } catch (CException* e) { e->Delete(); return FALSE; }
}

UINT __cdecl CFileAppLayer::FileTransferThread(LPVOID raw)
{
    FILE_THREAD_PARAM* param = (FILE_THREAD_PARAM*)raw;
    CFileAppLayer* layer = param->layer;
    CString path = param->path;
    delete param;
    BOOL ok = FALSE;
    try { ok = layer->SendFile(path); }
    catch (CException* e) { e->Delete(); }
    catch (const std::bad_alloc&) {}
    if (!ok) InterlockedExchange(&layer->m_nSendProgress, -1);
    InterlockedExchange(&layer->m_bFileTransferRunning, FALSE);
    return ok ? 0 : 1;
}
BOOL CFileAppLayer::StartFileTransfer(const CString& path)
{
    if (path.IsEmpty() || IsFileTransferRunning()) return FALSE;
    StopFileTransfer();
    InterlockedExchange(&m_cancel, FALSE);
    FILE_THREAD_PARAM* p = new FILE_THREAD_PARAM;
    p->layer = this; p->path = path;
    InterlockedExchange(&m_nSendProgress, 0);
    InterlockedExchange(&m_bFileTransferRunning, TRUE);
    m_pFileThread = AfxBeginThread(FileTransferThread, p, THREAD_PRIORITY_NORMAL, 0, CREATE_SUSPENDED);
    if (!m_pFileThread) { delete p; InterlockedExchange(&m_bFileTransferRunning, FALSE); return FALSE; }
    m_pFileThread->m_bAutoDelete = FALSE;
    m_pFileThread->ResumeThread();
    return TRUE;
}
void CFileAppLayer::StopFileTransfer()
{
    InterlockedExchange(&m_cancel, TRUE);
    if (m_pFileThread) {
        WaitForSingleObject(m_pFileThread->m_hThread, INFINITE);
        delete m_pFileThread; m_pFileThread = NULL;
    }
}
BOOL CFileAppLayer::IsFileTransferRunning() const { return InterlockedCompareExchange(&m_bFileTransferRunning, 0, 0) != 0; }
int CFileAppLayer::GetSendProgress() const { return InterlockedCompareExchange(&m_nSendProgress, 0, 0); }
int CFileAppLayer::GetReceiveProgress() const { return InterlockedCompareExchange(&m_nReceiveProgress, 0, 0); }
BOOL CFileAppLayer::IsReceiveRunning() { CSingleLock lock(&m_receiveLock, TRUE); return m_receiving; }
CString CFileAppLayer::GetLastReceivedFilePath() { CSingleLock lock(&m_receiveLock, TRUE); return m_lastPath; }

CString CFileAppLayer::ReceiveDirectory()
{
    TCHAR path[MAX_PATH];
    DWORD count = GetModuleFileName(NULL, path, MAX_PATH);
    if (!count || count >= MAX_PATH) return CString();
    CString dir(path);
    return dir.Left(dir.ReverseFind(_T('\\')) + 1);
}
void CFileAppLayer::ResetReceive()
{
    if (m_spool.m_hFile != CFile::hFileNull) m_spool.Abort();
    if (!m_tempPath.IsEmpty()) DeleteFile(m_tempPath);
    m_tempPath.Empty(); m_targetPath.Empty();
    m_fragments.clear(); m_receiving = FALSE; m_endSeen = FALSE;
    m_total = m_received = m_fragmentCount = 0;
}
BOOL CFileAppLayer::FailReceive()
{
    ResetReceive(); InterlockedExchange(&m_nReceiveProgress, -1); return FALSE;
}
void CFileAppLayer::CheckReceiveTimeout()
{
    CSingleLock lock(&m_receiveLock, TRUE);
    if (m_receiving && GetTickCount64() - m_lastReceiveTick >= 30000) FailReceive();
}
BOOL CFileAppLayer::CompleteReceive()
{
    if (!m_endSeen || m_received != m_total) return TRUE;
    // Place fragments at sequence offsets in a disk-backed buffer, avoiding
    // whole-file RAM allocation. Publish only after all fragments and END arrive.
    m_spool.Flush(); m_spool.Close();
    CString destination = m_targetPath;
    unsigned long suffix = 1;
    while (GetFileAttributes(destination) != INVALID_FILE_ATTRIBUTES) {
        int dot = m_targetPath.ReverseFind(_T('.'));
        int slash = m_targetPath.ReverseFind(_T('\\'));
        CString stem = dot > slash ? m_targetPath.Left(dot) : m_targetPath;
        CString ext = dot > slash ? m_targetPath.Mid(dot) : CString();
        destination.Format(_T("%s_%lu%s"), stem.GetString(), suffix++, ext.GetString());
    }
    if (!MoveFile(m_tempPath, destination)) return FailReceive();
    m_tempPath.Empty(); m_lastPath = destination;
    ResetReceive(); InterlockedExchange(&m_nReceiveProgress, 100);
    return TRUE;
}
BOOL CFileAppLayer::Receive(unsigned char*) { return FALSE; }
BOOL CFileAppLayer::Receive(unsigned char* data, int length)
{
    if (!data || length < FILE_HEADER_SIZE || length > ETHER_MAX_DATA_SIZE) return FALSE;
    CSingleLock lock(&m_receiveLock, TRUE);
    FILE_APP_HEADER* h = (FILE_APP_HEADER*)data;
    unsigned long total = ConvertByteOrder32(h->fapp_totlen);
    unsigned long seq = ConvertByteOrder32(h->fapp_seq_num);
    unsigned short type = ConvertByteOrder16(h->fapp_type);
    try {
        if (h->fapp_msg_type == FILE_MSG_INFO) {
            if (seq != 0 || length < FILE_HEADER_SIZE + sizeof(FILE_INFO) ||
                type != (total <= FILE_DATA_SIZE ? FILE_TYPE_SINGLE : FILE_TYPE_FIRST)) return FALSE;
            FILE_INFO* info = (FILE_INFO*)h->fapp_data;
            if (ConvertByteOrder32(info->file_size) != total || !memchr(info->file_name, 0, FILE_NAME_SIZE)) return FALSE;
            if (m_receiving) return FALSE;
            CString name = Utf8ToCString(info->file_name);
            name = name.Mid(name.ReverseFind(_T('\\')) + 1);
            name = name.Mid(name.ReverseFind(_T('/')) + 1);
            if (name.IsEmpty() || name.FindOneOf(_T(":*?\"<>|")) >= 0) return FALSE;
            CString dir = ReceiveDirectory();
            if (dir.IsEmpty()) return FALSE;
            ResetReceive();
            m_targetPath = dir + _T("received_") + name;
            TCHAR temporary[MAX_PATH];
            if (!GetTempFileName(dir, _T("ipc"), 0, temporary)) return FailReceive();
            m_tempPath = temporary;
            if (!m_spool.Open(m_tempPath, CFile::modeWrite | CFile::shareExclusive | CFile::typeBinary)) return FailReceive();
            m_total = total;
            m_fragmentCount = total / FILE_DATA_SIZE + (total % FILE_DATA_SIZE != 0);
            m_fragments.assign(m_fragmentCount, false);
            m_receiving = TRUE; m_lastReceiveTick = GetTickCount64();
            InterlockedExchange(&m_nReceiveProgress, 0);
            return TRUE;
        }
        if (!m_receiving || total != m_total) return FALSE;
        if (h->fapp_msg_type == FILE_MSG_END) {
            if (seq != m_fragmentCount + 1 || type != (total <= FILE_DATA_SIZE ? FILE_TYPE_SINGLE : FILE_TYPE_LAST)) return FALSE;
            m_endSeen = TRUE; m_lastReceiveTick = GetTickCount64();
            return CompleteReceive();
        }
        if (h->fapp_msg_type != FILE_MSG_DATA || seq == 0 || seq > m_fragmentCount) return FALSE;
        unsigned short expected = total <= FILE_DATA_SIZE ? FILE_TYPE_SINGLE :
            (seq == m_fragmentCount ? FILE_TYPE_LAST : (seq == 1 ? FILE_TYPE_FIRST : FILE_TYPE_MIDDLE));
        if (type != expected) return FALSE;
        ULONGLONG offset = (ULONGLONG)(seq - 1) * FILE_DATA_SIZE;
        unsigned long remaining = total - (unsigned long)offset;
        UINT bytes = remaining > FILE_DATA_SIZE ? FILE_DATA_SIZE : remaining;
        if (length < FILE_HEADER_SIZE + (int)bytes) return FALSE;
        if (m_fragments[seq - 1]) return TRUE;
        m_spool.Seek(offset, CFile::begin);
        m_spool.Write(h->fapp_data, bytes);
        m_fragments[seq - 1] = true;
        m_received += bytes; m_lastReceiveTick = GetTickCount64();
        InterlockedExchange(&m_nReceiveProgress, (LONG)((ULONGLONG)m_received * 99 / m_total));
        return CompleteReceive();
    } catch (CException* e) { e->Delete(); return FailReceive(); }
    catch (const std::bad_alloc&) { return FailReceive(); }
}

unsigned short
CFileAppLayer::ConvertByteOrder16(
    unsigned short value)
{
    return (unsigned short)(
        ((value & 0x00FF) << 8) |
        ((value & 0xFF00) >> 8)
        );
}


unsigned long
CFileAppLayer::ConvertByteOrder32(
    unsigned long value)
{
    return (
        ((value & 0x000000FFUL) << 24) |
        ((value & 0x0000FF00UL) << 8) |
        ((value & 0x00FF0000UL) >> 8) |
        ((value & 0xFF000000UL) >> 24)
        );
}


//////////////////////////////////////////////////////////////////////
// CString -> UTF-8
//////////////////////////////////////////////////////////////////////

BOOL CFileAppLayer::CStringToUtf8(const CString& source, char* destination, int destinationSize)
{
    if (!destination || destinationSize <= 0) return FALSE;
    CStringW wide(source);
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.GetString(), -1,
        destination, destinationSize, NULL, NULL) > 0;
}

CString CFileAppLayer::Utf8ToCString(const char* source)
{
    if (!source) return CString();
    int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, source, -1, NULL, 0);
    if (length <= 0) return CString();
    std::vector<wchar_t> wide(length);
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, source, -1, wide.data(), length)) return CString();
    return CString(wide.data());
}
