
// SafeEnvLaunchDlg.cpp : implementation file
//

#include "stdafx.h"
#include "SafeEnvLaunch.h"
#include "SafeEnvLaunchDlg.h"
#include "afxdialogex.h"
#include "AdminPwdDlg.h"
#include <string.h>
#include <WinSvc.h>

#include <strsafe.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define WM_MYMSG  WM_USER+200
#define WM_STARTMSG WM_USER+201
#define WM_ENDMSG WM_USER+202

static CString strPwd;
static CString oriCmd;

// CSafeEnvLaunchDlg dialog
typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
 
LPFN_ISWOW64PROCESS fnIsWow64Process;

BOOL IsWow64()
{
    BOOL bIsWow64 = FALSE;
 
    fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
        GetModuleHandle(TEXT("kernel32")),"IsWow64Process");
   
    if (NULL != fnIsWow64Process)
    {
        if (!fnIsWow64Process(GetCurrentProcess(),&bIsWow64))
        {
            // handle error
        }
    }
    return bIsWow64;
}
#define USELOGIN 0
BOOL CreateMyProcess(CString strCommand,DWORD& dwReturn,CString & strLog,CString strPwd)
{
 
	//尝试登陆管理员账户
#if USELOGIN
	HANDLE hToken;
	dwReturn=-1;
	strLog=_T("");
	if(!LogonUser(_T("Administrator"),
				NULL,strPwd,
				LOGON32_LOGON_INTERACTIVE,
				LOGON32_PROVIDER_DEFAULT,
				&hToken
	)){
		int iError=GetLastError();
		strLog.Format(_T("Error On LogonUser(),errorcode is %d."),iError);
		return FALSE;
	}
	BOOL blResult=FALSE;
	SECURITY_ATTRIBUTES sa;
	HANDLE hRead,hWrite;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;//创建管道
	if(!CreatePipe(&hRead,&hWrite,&sa,0)){
		strLog=_T("ErrorOnCreatePipe()");
		return FALSE;
	}
	STARTUPINFO si = { sizeof(si) };//将cb成员初始化为sizeof(si)，其他成员初始化为0
	::GetStartupInfo(&si);
	si.hStdError = hWrite;
	si.hStdOutput = hWrite;
	si.wShowWindow = SW_HIDE;
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	PROCESS_INFORMATION pi;
	CString strInfo=_T("");
	ZeroMemory(&pi,sizeof(pi));//管理员方式启动进程
	if(!CreateProcessWithLogonW(_T("Administrator"),
								NULL,
								strPwd,
								LOGON_WITH_PROFILE,NULL,
								strCommand.GetBuffer(),
								CREATE_UNICODE_ENVIRONMENT,
								NULL,
								oriCmd,
								&si,
								&pi))
#else
	

	STARTUPINFO si;
	memset(&si,0,sizeof(STARTUPINFO));//初始化si在内存块中的值（详见memset函数）
	si.cb=sizeof(STARTUPINFO);
#ifdef _DEBUG
	si.dwFlags=STARTF_USESHOWWINDOW;

	si.wShowWindow=SW_SHOW;
#else
	si.wShowWindow = SW_HIDE;
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;

#endif
	PROCESS_INFORMATION pi;//必备参数设置结束


	if(!CreateProcess(NULL,strCommand.GetBuffer(),NULL,NULL,FALSE,0,NULL,NULL,&si,&pi))
#endif
	{
		int iError=GetLastError();
		strLog.Format(strCommand + _T(",errorcode is %d."),iError);
#if USELOGIN
		CloseHandle(hWrite);
		CloseHandle(hRead);
#endif
		return FALSE;
	}
#if USELOGIN
	CloseHandle(hWrite);
	char buffer[4096]={0};
	DWORD bytesRead=0;//读取回传值
	while(true){
		if(ReadFile(hRead,buffer,4095,&bytesRead,NULL)==NULL)break;//获取了回传值，处理回传值
		Sleep(100);
	}//资源清理
	CloseHandle(hRead);
	CloseHandle(hToken);
#endif
	WaitForSingleObject(pi.hProcess,INFINITE);
	GetExitCodeProcess(pi.hProcess,&dwReturn);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	return TRUE;
}

DWORD WINAPI UnInstallFunc(LPVOID p)
{
	HWND safeHwnd = (HWND)p;
	DWORD retCode = 0;
	CString strLog;
	
	//oriCmd = _T("D:\\VBox\\VirtualBox-5.0.0\\out\\win.amd64\\debug\\bin\\");
	BOOL cmpRet = FALSE;
	int i = 1;
	
	SendMessage(safeHwnd,WM_STARTMSG,7,0);
	CString VBoxStrCmd;
	VBoxStrCmd.Format(_T("%sVBoxSVC.exe /UnregServer"),oriCmd);
	cmpRet = CreateMyProcess(VBoxStrCmd,retCode,strLog,strPwd);
	if(!cmpRet){
		::MessageBox(NULL,strLog,_T("VBoxSVC /UnregServer"),MB_OK);
		return 0;
	}
	SendMessage(safeHwnd,WM_MYMSG,(WPARAM)i++,0);
	VBoxStrCmd.Format(_T("regsvr32 /s /u \"%sx86\\VBoxClient-x86.dll\""),oriCmd);
	cmpRet = CreateMyProcess(VBoxStrCmd,retCode,strLog,strPwd);
	if(!cmpRet){
		::MessageBox(NULL,strLog,_T("regsvr32 VBoxClient-x86.dll"),MB_OK);
		return 0 ;
	}
	SendMessage(safeHwnd,WM_MYMSG,(WPARAM)i++,0);
	VBoxStrCmd.Format(_T("regsvr32 /s /u \"%sVBoxC.dll\""),oriCmd);
	cmpRet = CreateMyProcess(VBoxStrCmd,retCode,strLog,strPwd);
	if(!cmpRet){
		::MessageBox(NULL,strLog,_T("regsvr32 VBoxC.dll"),MB_OK);
		return 0 ;
	}
	SendMessage(safeHwnd,WM_MYMSG,(WPARAM)i++,0);
	VBoxStrCmd.Format(_T("regsvr32 /s /u \"%sx86\\VBoxProxyStub.dll\""),oriCmd);
	cmpRet = CreateMyProcess(VBoxStrCmd,retCode,strLog,strPwd);
	if(!cmpRet){
		::MessageBox(NULL,strLog,_T("regsvr32 VBoxProxyStub.dll"),MB_OK);
		return 0 ;
	}
	SendMessage(safeHwnd,WM_MYMSG,(WPARAM)i++,0);
	VBoxStrCmd.Format(_T("regsvr32 /s /u \"%sx86\\VBoxProxyStub-x86.dll\""),oriCmd);
	cmpRet = CreateMyProcess(VBoxStrCmd,retCode,strLog,strPwd);
	if(!cmpRet){
		::MessageBox(NULL,strLog,_T("regsvr32 VBoxProxyStub-x86.dll"),MB_OK);
		return 0 ;
	}
	SendMessage(safeHwnd,WM_MYMSG,(WPARAM)i++,0);
	VBoxStrCmd.Format(_T("%sUSBUninstall"),oriCmd);
	cmpRet = CreateMyProcess(VBoxStrCmd,retCode,strLog,strPwd);
	if(!cmpRet){
		::MessageBox(NULL,strLog,_T("USBUninstall"),MB_OK);
		return 0 ;
	}
	SendMessage(safeHwnd,WM_MYMSG,(WPARAM)i++,0);
	VBoxStrCmd.Format(_T("%sNETLwfUninstall"),oriCmd);
	cmpRet = CreateMyProcess(VBoxStrCmd,retCode,strLog,strPwd);
	if(!cmpRet){
		::MessageBox(NULL,strLog,_T("NETLwfUninstall"),MB_OK);
		return 0 ;
	}
	SendMessage(safeHwnd,WM_MYMSG,(WPARAM)i++,0);
	VBoxStrCmd.Format(_T("%sSUPUninstall"),oriCmd);
	cmpRet = CreateMyProcess(VBoxStrCmd,retCode,strLog,strPwd);
	if(!cmpRet){
		::MessageBox(NULL,strLog,_T("SUPUninstall"),MB_OK);
		return 0 ;
	}
	SendMessage(safeHwnd,WM_MYMSG,(WPARAM)i++,0);

	SendMessage(safeHwnd,WM_ENDMSG,0,0);
}

DWORD WINAPI  InstallFunc(LPVOID p)
{
	HWND safeHwnd = (HWND)p;
	DWORD retCode = 0;
	CString strLog;
	
	BOOL cmpRet = FALSE;
	int i = 1;
	
	SendMessage(safeHwnd,WM_STARTMSG,6,0);

	CString VBoxStrCmd;
	VBoxStrCmd.Format(_T("%sVBoxSVC /RegServer"),oriCmd);
	cmpRet = CreateMyProcess(VBoxStrCmd,retCode,strLog,strPwd);
	if(!cmpRet){
		::MessageBox(NULL,strLog,VBoxStrCmd,MB_OK);
		return 0;
	}
	SendMessage(safeHwnd,WM_MYMSG,(WPARAM)i++,0);

	VBoxStrCmd.Format(_T("regsvr32 /s  \"%sVBoxC.dll\""),oriCmd);
	cmpRet = CreateMyProcess(VBoxStrCmd,retCode,strLog,strPwd);
	if(!cmpRet){
		::MessageBox(NULL,strLog,_T("regsvr32 VBoxC.dll"),MB_OK);
		return 0 ;
	}
	SendMessage(safeHwnd,WM_MYMSG,(WPARAM)i++,0);
	
	VBoxStrCmd.Format(_T("regsvr32 /s  \"%sx86\\VBoxClient-x86.dll\""),oriCmd);
	cmpRet = CreateMyProcess(VBoxStrCmd,retCode,strLog,strPwd);
	if(!cmpRet){
		::MessageBox(NULL,strLog,_T("regsvr32 VBoxClient-x86.dll"),MB_OK);
		return 0 ;
	}
	SendMessage(safeHwnd,WM_MYMSG,(WPARAM)i++,0);

	VBoxStrCmd.Format(_T("%sUSBInstall"),oriCmd);
	cmpRet = CreateMyProcess(VBoxStrCmd,retCode,strLog,strPwd);
	if(!cmpRet){
		::MessageBox(NULL,strLog,_T("USBInstall"),MB_OK);
		return 0 ;
	}
	SendMessage(safeHwnd,WM_MYMSG,(WPARAM)i++,0);

	VBoxStrCmd.Format(_T("%sNETLwfInstall"),oriCmd);
	cmpRet = CreateMyProcess(VBoxStrCmd,retCode,strLog,strPwd);
	if(!cmpRet){
		::MessageBox(NULL,strLog,_T("NETLwfInstall"),MB_OK);
		return 0 ;
	}
	SendMessage(safeHwnd,WM_MYMSG,(WPARAM)i++,0);

	VBoxStrCmd.Format(_T("%sSUPInstall"),oriCmd);
	cmpRet = CreateMyProcess(VBoxStrCmd,retCode,strLog,strPwd);
	if(!cmpRet){
		::MessageBox(NULL,strLog,_T("SUPInstall"),MB_OK);
		return 0 ;
	}
	SendMessage(safeHwnd,WM_MYMSG,(WPARAM)i++,0);

	SendMessage(safeHwnd,WM_ENDMSG,0,0);
}

CSafeEnvLaunchDlg::CSafeEnvLaunchDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CSafeEnvLaunchDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

LRESULT CSafeEnvLaunchDlg::OnMyStartHandler(WPARAM w , LPARAM l)
{
	m_csStatus.SetWindowTextW(_T(""));
	GetDlgItem(IDOK)->EnableWindow(FALSE);
	totalStep = (int) w;

	return 0;
}
LRESULT CSafeEnvLaunchDlg::OnMyEndHandler(WPARAM w , LPARAM l)
{
	if(w==1)
		GetDlgItem(IDOK)->EnableWindow(TRUE);
	return 0;
}

LRESULT CSafeEnvLaunchDlg::OnMyMsgHandler(WPARAM w,LPARAM l)
{
	int pgs = (int)w;
	
	m_pcSetup.SetPos(w * 100 / totalStep);
	return 0;
}

void CSafeEnvLaunchDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_STATIC_OS, m_csOS);
	DDX_Control(pDX, IDC_STATIC_OSBIT, m_csOSBit);
	DDX_Control(pDX, IDC_PROGRESS_SETUP, m_pcSetup);
	DDX_Control(pDX, IDC_STATIC_STATUS, m_csStatus);
}

BEGIN_MESSAGE_MAP(CSafeEnvLaunchDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CSafeEnvLaunchDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDC_BUTTON_CHECK, &CSafeEnvLaunchDlg::OnBnClickedButtonCheck)
	ON_MESSAGE(WM_MYMSG,OnMyMsgHandler)
	ON_MESSAGE(WM_STARTMSG,OnMyStartHandler)
	ON_MESSAGE(WM_ENDMSG,OnMyEndHandler)
	ON_BN_CLICKED(IDC_BUTTON_INSTALL, &CSafeEnvLaunchDlg::OnBnClickedButtonInstall)
	ON_BN_CLICKED(IDC_BUTTON_UNINSTALL, &CSafeEnvLaunchDlg::OnBnClickedButtonUninstall)
END_MESSAGE_MAP()


// CSafeEnvLaunchDlg message handlers

BOOL CSafeEnvLaunchDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here

	DWORD dirlen = GetPrivateProfileString(_T("ProcDir"),_T("DebugDir"),NULL,oriCmd.GetBuffer(256),256,_T("./DebugDir.ini"));
	if(dirlen >0){
		m_csStatus.SetWindowTextW(oriCmd);
	}
	else{
		TCHAR szPath[MAX_PATH] = L"";
		GetModuleFileName(NULL, szPath, MAX_PATH);
		TCHAR drive[MAX_PATH] = L"";
		TCHAR dir[MAX_PATH] = L"";
		TCHAR fileName[MAX_PATH] = L"";
		TCHAR ext[MAX_PATH] = L"";
		_wsplitpath_s(szPath, drive, dir, fileName, ext);
		
		
		if(IsWow64()){
			oriCmd.Format(_T("%s%sSafeEnv\\"),drive ,dir);
		}
		else {
			oriCmd.Format(_T("%s%sSafeEnv_32\\"),drive ,dir);
		}
		m_csStatus.SetWindowTextW(oriCmd);
	}

	getSystemName();
	if(IsWow64()){
        m_csOSBit.SetWindowTextW(_T(" 64位操作系统"));
	}
    else {
		m_csOSBit.SetWindowTextW(_T(" 32位操作系统"));
	}
	m_pcSetup.SetRange(0,100);
	m_pcSetup.SetPos(0);
#if USELOGIN
	IsInputPwd = FALSE;
#else
	IsInputPwd = TRUE;
#endif
	totalStep = 100;
	SetEnvironmentVariable(_T("VBOX_LOG_DEST"),_T("nofile"));
	SetEnvironmentVariable(_T("VBOX_LOG_FLAGS"),_T("disabled"));
	SetEnvironmentVariable(_T("VBOX_RELEASE_LOG_DEST"),_T("nofile"));
	SetEnvironmentVariable(_T("VBOX_LOG"),_T("-all"));
	return TRUE;  // return TRUE  unless you set the focus to a control
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CSafeEnvLaunchDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CSafeEnvLaunchDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CSafeEnvLaunchDlg::CheckPwd()
{
	if(!IsInputPwd){
		CAdminPwdDlg inputDlg;
		if(inputDlg.DoModal() == IDCANCEL)
			return ;
		IsInputPwd = TRUE;
		strPwd = inputDlg.m_strAdminPwd;
	}
}


void CSafeEnvLaunchDlg::OnBnClickedOk()
{
	// TODO: Add your control notification handler code here
	CString exfatCmd;
	DWORD dirlen = GetPrivateProfileString(_T("ProcDir"),_T("exfatServer"),NULL,exfatCmd.GetBuffer(256),256,_T("./DebugDir.ini"));
	if(dirlen<=0){
		TCHAR szPath[MAX_PATH] = L"";
		GetModuleFileName(NULL, szPath, MAX_PATH);
		TCHAR drive[MAX_PATH] = L"";
		TCHAR dir[MAX_PATH] = L"";
		TCHAR fileName[MAX_PATH] = L"";
		TCHAR ext[MAX_PATH] = L"";
		_wsplitpath_s(szPath, drive, dir, fileName, ext);
		exfatCmd.Format(_T("%s%simg_Tool\\exfatserver.exe"),drive,dir);
	}
	
	STARTUPINFO si;
	memset(&si,0,sizeof(STARTUPINFO));//初始化si在内存块中的值（详见memset函数）
	si.cb=sizeof(STARTUPINFO);
	si.dwFlags=STARTF_USESHOWWINDOW;
	si.wShowWindow=SW_SHOW;
	PROCESS_INFORMATION pi;//必备参数设置结束
	if(!CreateProcess(exfatCmd,
		NULL,
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&si,
		&pi
		)){
			//cout<<"CreateFail!"<<endl;
			MessageBox(_T("Create ExfatServer Failed!"));
				
	}else{
		//cout<<"Success!"<<endl;
		//OnAccept();
			
		//不使用的句柄最好关掉
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		Sleep(1000);
#define BUFSIZE 4096
		{
			STARTUPINFO si;
			memset(&si,0,sizeof(STARTUPINFO));//初始化si在内存块中的值（详见memset函数）
			si.cb=sizeof(STARTUPINFO);
			si.dwFlags=STARTF_USESHOWWINDOW;
			si.wShowWindow=SW_SHOW;
			PROCESS_INFORMATION pi;//必备参数设置结束
			CString vboxCmd;
			CString vboxDir;
			CString vboxEnv;
			vboxCmd.Format(_T("%sVirtualBox.exe"),oriCmd);
			if(!CreateProcess(vboxCmd,
				NULL,
				NULL,
				NULL,
				TRUE,
				CREATE_UNICODE_ENVIRONMENT,
				//_T("VBOX_LOG_FLAGS=disabled\0\0VBOX_LOG_DEST=nofile\0\0VBOX_RELEASE_LOG_DEST=nofile\0\0VBOX_LOG=-all\0\0\0\0"),
				//_T("FHAHADEBUG=0\0\0\0\0"),
				//(LPVOID)chNewEnv,
				NULL,
				//_T("VBOX_LOG_DEST=nofile\0\0\0\0"),
				oriCmd,
				&si,
				&pi
				)){
					//cout<<"CreateFail!"<<endl;
					MessageBox(_T("Create VirtualBox Failed!"));
				
			}else{
				//cout<<"Success!"<<endl;
				//OnAccept();
			
				//不使用的句柄最好关掉
				CloseHandle(pi.hThread);
				CloseHandle(pi.hProcess);
				DestroyWindow();
			}
		}

		//DestroyWindow();
	}
	
	
	return ;

}
 
void CSafeEnvLaunchDlg::getSystemName()
{
	CString vname;
	//先判断是否为win8.1或win10
	typedef void(__stdcall*NTPROC)(DWORD*, DWORD*, DWORD*);
	HINSTANCE hinst = LoadLibrary(_T("ntdll.dll"));
	DWORD dwMajor, dwMinor, dwBuildNumber;
	NTPROC proc = (NTPROC)GetProcAddress(hinst, "RtlGetNtVersionNumbers"); 
	proc(&dwMajor, &dwMinor, &dwBuildNumber); 
	if (dwMajor == 6 && dwMinor == 3)	//win 8.1
	{
		vname = _T("Microsoft Windows 8.1");
		//printf_s("此电脑的版本为:%s\n", vname.c_str());
		m_csOS.SetWindowTextW(vname);
		return;
	}
	if (dwMajor == 10 && dwMinor == 0)	//win 10
	{
		vname = _T("Microsoft Windows 10");
		//printf_s("此电脑的版本为:%s\n", vname.c_str());
		m_csOS.SetWindowTextW(vname);
		return;
	}
	//下面判断不能Win Server，因为本人还未有这种系统的机子，暂时不给出
 
 
 
	//判断win8.1以下的版本
	SYSTEM_INFO info;                //用SYSTEM_INFO结构判断64位AMD处理器  
	GetSystemInfo(&info);            //调用GetSystemInfo函数填充结构  
	OSVERSIONINFOEX os;
	os.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	#pragma warning(disable:4996)
	if (GetVersionEx((OSVERSIONINFO *)&os))
	{
 
		//下面根据版本信息判断操作系统名称  
		switch (os.dwMajorVersion)
		{                        //判断主版本号  
		case 4:
			switch (os.dwMinorVersion)
			{                //判断次版本号  
			case 0:
				if (os.dwPlatformId == VER_PLATFORM_WIN32_NT)
					vname = _T("Microsoft Windows NT 4.0");  //1996年7月发布  
				else if (os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS)
					vname = _T("Microsoft Windows 95");
				break;
			case 10:
				vname = _T("Microsoft Windows 98");
				break;
			case 90:
				vname = _T("Microsoft Windows Me");
				break;
			}
			break;
		case 5:
			switch (os.dwMinorVersion)
			{               //再比较dwMinorVersion的值  
			case 0:
				vname = _T("Microsoft Windows 2000");    //1999年12月发布  
				break;
			case 1:
				vname = _T("Microsoft Windows XP");      //2001年8月发布  
				break;
			case 2:
				if (os.wProductType == VER_NT_WORKSTATION &&
					info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
					vname = _T("Microsoft Windows XP Professional x64 Edition");
				else if (GetSystemMetrics(SM_SERVERR2) == 0)
					vname = _T("Microsoft Windows Server 2003");   //2003年3月发布  
				else if (GetSystemMetrics(SM_SERVERR2) != 0)
					vname = _T("Microsoft Windows Server 2003 R2");
				break;
			}
			break;
		case 6:
			switch (os.dwMinorVersion)
			{
			case 0:
				if (os.wProductType == VER_NT_WORKSTATION)
					vname = _T("Microsoft Windows Vista");
				else
					vname = _T("Microsoft Windows Server 2008");   //服务器版本  
				break;
			case 1:
				if (os.wProductType == VER_NT_WORKSTATION)
					vname = _T("Microsoft Windows 7");
				else
					vname = _T("Microsoft Windows Server 2008 R2");
				break;
			case 2:
				if (os.wProductType == VER_NT_WORKSTATION)
					vname = _T("Microsoft Windows 8");
				else
					vname = _T("Microsoft Windows Server 2012");
				break;
			}
			break;
		default:
			vname = _T("未知操作系统");
		}
		//printf_s("此电脑的版本为:%s\n", vname.c_str());
	}
	//else
		//printf_s("版本获取失败\n");

	m_csOS.SetWindowTextW(vname);


}
 

void CSafeEnvLaunchDlg::OnBnClickedButtonCheck()
{
	CheckPwd();
	
 
    BOOL bResult = FALSE;  
  
    //打开服务控制管理器   
    SC_HANDLE hSCM = ::OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);  
  
    if (hSCM != NULL)  
    {  
        //打开服务   
        SC_HANDLE hService = ::OpenService(hSCM, _T("VBoxDrv"), SERVICE_QUERY_CONFIG |  SERVICE_QUERY_STATUS);  
        if (hService != NULL)  
        {  
			SERVICE_STATUS sStatus;
			BOOL qret = ::QueryServiceStatus(hService,&sStatus);
			if(qret){
				if(sStatus.dwCurrentState!=SERVICE_RUNNING){
					sStatus.dwCurrentState = SERVICE_RUNNING;
					if(::StartService(hService,0,NULL)==0){
						m_csStatus.SetWindowTextW(_T("Service VBoxDrv Start Failed"));
					}
					else{
						m_csStatus.SetWindowTextW(_T("VBoxDrv Start Ok"));
					}
				}
				else{
					m_csStatus.SetWindowTextW(_T("VBoxDrv is Running"));
					GetDlgItem(IDOK)->EnableWindow(TRUE);
				}
			}
			else{
				CString failStr;
				failStr.Format(_T("Query Status Failed for %d"),GetLastError());
				m_csStatus.SetWindowTextW(failStr);
			}
            ::CloseServiceHandle(hService);  
        }  
		else{
			MessageBox(_T("Service VBoxDrv Not Installed!"));
		}
        ::CloseServiceHandle(hSCM);  
    }  
    return ;  
	
}


void CSafeEnvLaunchDlg::OnBnClickedButtonInstall()
{
	
	CheckPwd();
	HANDLE  hThread;

    DWORD  threadId;
	CheckPwd();
    hThread = CreateThread(NULL,
		0,
		InstallFunc,
		GetSafeHwnd(),
		0,
		&threadId);

}


void CSafeEnvLaunchDlg::OnBnClickedButtonUninstall()
{
	CheckPwd();
	HANDLE  hThread;

    DWORD  threadId;
    hThread = CreateThread(NULL,
		0,
		UnInstallFunc,
		GetSafeHwnd(),
		0,
		&threadId);
}
