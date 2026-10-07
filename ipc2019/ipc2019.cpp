#include "pch.h"
#include "ipc2019.h"
#include "ipc2019Dlg.h"
BEGIN_MESSAGE_MAP(Cipc2019App,CWinApp)
END_MESSAGE_MAP()
Cipc2019App theApp;
Cipc2019App::Cipc2019App(){}
BOOL Cipc2019App::InitInstance(){
    INITCOMMONCONTROLSEX controls{sizeof(controls),ICC_WIN95_CLASSES};InitCommonControlsEx(&controls);
    CWinApp::InitInstance();AfxEnableControlContainer();
    Cipc2019Dlg dialog;m_pMainWnd=&dialog;dialog.DoModal();return FALSE;
}
