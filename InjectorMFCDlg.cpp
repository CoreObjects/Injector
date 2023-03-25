
// InjectorMFCDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "InjectorMFC.h"
#include "InjectorMFCDlg.h"
#include "afxdialogex.h"
#include "ProcessList.h"
#include "psapi.h"
#include "Inject.h"
#include <TlHelp32.h>
#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx {
public:
	CAboutDlg();

	// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX) {
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX) {
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CInjectorMFCDlg 对话框



CInjectorMFCDlg::CInjectorMFCDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_INJECTORMFC_DIALOG, pParent)
	, m_dwProcessId(0) {
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CInjectorMFCDlg::DoDataExchange(CDataExchange* pDX) {
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO1, m_Inject_type);
	DDX_Control(pDX, IDC_COMBO2, m_x86orx64);
	DDX_Control(pDX, IDC_LIST1, m_ModuleList);
	DDX_Control(pDX, IDC_EDIT1, m_ModulePath);
	DDX_Text(pDX, IDC_EDIT2, m_dwProcessId);
	DDX_Control(pDX, IDC_EDIT3, m_FilePath);
}

BEGIN_MESSAGE_MAP(CInjectorMFCDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CInjectorMFCDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CInjectorMFCDlg::OnBnClickedButton2)
	ON_WM_CONTEXTMENU()
	ON_COMMAND(ID_32773, &CInjectorMFCDlg::OnFlush)
	ON_BN_CLICKED(IDC_BUTTON3, &CInjectorMFCDlg::OnBnClickedButton3)
	ON_COMMAND(ID_32774, &CInjectorMFCDlg::OnUnLoad)
	ON_COMMAND(ID_Menu, &CInjectorMFCDlg::OnUnloadx86)
	ON_BN_CLICKED(IDC_BUTTON4, &CInjectorMFCDlg::OnBnClickedButton4)
END_MESSAGE_MAP()


// CInjectorMFCDlg 消息处理程序

BOOL CInjectorMFCDlg::OnInitDialog() {
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr) {
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty()) {
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	m_Inject_type.AddString(L"远程线程注入");
	m_Inject_type.AddString(L"劫持进程注入");
	m_Inject_type.AddString(L"无痕注入");
	m_Inject_type.SetCurSel(0);
	m_x86orx64.AddString(L"x86");
	m_x86orx64.AddString(L"x64");
	m_x86orx64.SetCurSel(0);
	m_ModuleList.InsertColumn(0, L"模块名", 0, 100);
	m_ModuleList.InsertColumn(1, L"模块基址", 0, 80);
	m_ModuleList.InsertColumn(2, L"模块大小", 0, 80);
	m_ModuleList.InsertColumn(3, L"模块路径", 0, 600);
	m_ModuleList.SetExtendedStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CInjectorMFCDlg::OnSysCommand(UINT nID, LPARAM lParam) {
	if ((nID & 0xFFF0) == IDM_ABOUTBOX) {
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else {
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CInjectorMFCDlg::OnPaint() {
	if (IsIconic()) {
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else {
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CInjectorMFCDlg::OnQueryDragIcon() {
	return static_cast<HCURSOR>(m_hIcon);
}


/*
explicit CFileDialog(
	BOOL bOpenFileDialog,
	LPCTSTR lpszDefExt = NULL,
	LPCTSTR lpszFileName = NULL,
	DWORD dwFlags = OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT,
	LPCTSTR lpszFilter = NULL,
	CWnd* pParentWnd = NULL,
	DWORD dwSize = 0,
	BOOL bVistaStyle = TRUE);
*/
void CInjectorMFCDlg::OnBnClickedButton1() {
	// TODO: 在此添加控件通知处理程序代码
	CFileDialog fileDlg(TRUE, NULL, NULL, NULL, L"动态链接库|*.dll|AllFiles|*.*||", this);
	fileDlg.DoModal();
	CString csDllPath = fileDlg.GetPathName();
	m_ModulePath.SetWindowTextW(csDllPath);

}


void CInjectorMFCDlg::OnBnClickedButton2() {
	// TODO: 在此添加控件通知处理程序代码
	UpdateData(TRUE);
	ProcessList page;
	m_dwProcessId = page.DoModal();
	UpdateData(FALSE);
	InitModuleList();

}
/*
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	//注入远程线程回调函数参数
	if (hProcess == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	LPVOID lpBuffer = VirtualAllocEx(hProcess, NULL, MAX_PATH, MEM_COMMIT, PAGE_READWRITE);
	if (lpBuffer == NULL) {
		return FALSE;
	}
	DWORD dwWriteSize;
	BOOL bRet = WriteProcessMemory(hProcess, lpBuffer, szPath, (wcslen(szPath) + 1) * 2, &dwWriteSize);
	if (bRet == FALSE) {
		return FALSE;
	}
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryW, lpBuffer, 0, NULL);
	if (hThread != NULL) {
		WaitForSingleObject(hThread, -1);
		CloseHandle(hThread);
	}
	VirtualFreeEx(hProcess, lpBuffer, 0, MEM_RELEASE);
	CloseHandle(hProcess);
	return TRUE;
*/

BOOL CInjectorMFCDlg::RemoteThreadInject(DWORD dwProcessId, CString csDllPath) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProcess != INVALID_HANDLE_VALUE) {
		LPVOID lpBuffer = VirtualAllocEx(hProcess, NULL, MAX_PATH, MEM_COMMIT, PAGE_READWRITE);
		if (lpBuffer != NULL) {
			SIZE_T dwRealWrite;
			BOOL bRet = WriteProcessMemory(hProcess, lpBuffer, csDllPath.GetBuffer(), ((long long)csDllPath.GetLength() + 1) * 2, &dwRealWrite);
			if (bRet) {
				HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, lpBuffer, 0, NULL);
				if (hThread != NULL) {
					WaitForSingleObject(hThread, -1);
					CloseHandle(hThread);
				}
			}
			VirtualFreeEx(hProcess, lpBuffer, 0, MEM_RELEASE);

		}
		CloseHandle(hProcess);
	}
	return TRUE;
}

void CInjectorMFCDlg::InitModuleList() {
	m_ModuleList.DeleteAllItems();
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, m_dwProcessId);
	if (hSnap != INVALID_HANDLE_VALUE) {
		MODULEENTRY32 me32{ sizeof(me32) };
		BOOL bRet = Module32First(hSnap, &me32);
		DWORD dwIndex = 0;
		while (bRet) {
			m_ModuleList.InsertItem(dwIndex, me32.szModule);
			CString csModuleBase, csModuleSize;
			csModuleBase.Format(L"%p", me32.modBaseAddr);
			csModuleSize.Format(L"%d", me32.modBaseSize);
			m_ModuleList.SetItemText(dwIndex, 1, csModuleBase);
			m_ModuleList.SetItemText(dwIndex, 2, csModuleSize);
			m_ModuleList.SetItemText(dwIndex, 3, me32.szExePath);
			bRet = Module32Next(hSnap, &me32);
			dwIndex++;
		}
		CloseHandle(hSnap);
	}
}

void CInjectorMFCDlg::MsgHookInject() {

	HHOOK hHook;
	//	SetWindowsHookEx()

}

void CInjectorMFCDlg::OnContextMenu(CWnd* pWnd, CPoint point) {
	// TODO: 在此处添加消息处理程序代码
	CMenu mMenu;
	mMenu.LoadMenuW(IDR_MENU2);
	CMenu* mSubMenu = mMenu.GetSubMenu(0);
	mSubMenu->TrackPopupMenu(TPM_CENTERALIGN, point.x, point.y, this);
}


void CInjectorMFCDlg::OnFlush() {
	// TODO: 在此添加命令处理程序代码
	InitModuleList();
}




void CInjectorMFCDlg::OnBnClickedButton3() {
	// TODO: 在此添加控件通知处理程序代码
	CString csdllPath;
	int nInjectType = m_Inject_type.GetCurSel();
	int nx86orx64 = m_x86orx64.GetCurSel();
	m_ModulePath.GetWindowTextW(csdllPath);
	if (nInjectType == 0 && nx86orx64 == 1) {
		RemoteThreadInject(m_dwProcessId, csdllPath);
		InitModuleList();
	}
	else if (nInjectType == 0 && nx86orx64 == 0) {
		STARTUPINFO startupInfo{ sizeof(startupInfo) };
		PROCESS_INFORMATION procInfo;
		WCHAR wcsCmd[MAX_PATH];
		wsprintf(wcsCmd, L"X86Injecter.exe %d %d %s", 0, m_dwProcessId, csdllPath.GetBuffer());
		CreateProcess(L"X86Injecter.exe", wcsCmd, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &procInfo);
		CloseHandle(procInfo.hProcess);
		CloseHandle(procInfo.hThread);
		InitModuleList();
	}
	else if (nInjectType == 1 && nx86orx64 == 0) {

		unsigned char ShellcodeInject[220] = {
			0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x20, 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x8B, 0x40, 0x0C, 0x8B,
			0x40, 0x1C, 0x8B, 0x00, 0x8B, 0x00, 0x8B, 0x40, 0x08, 0x89, 0x45, 0xFC, 0x8B, 0xC8, 0xBA, 0xE8,
			0x22, 0x19, 0x64, 0xE8, 0x4D, 0x00, 0x00, 0x00, 0xBB, 0xCC, 0xCC, 0xCC, 0xCC, 0x53, 0xFF, 0xD0,
			0xBA, 0x48, 0xC9, 0xDE, 0x3D, 0x8B, 0x4D, 0xFC, 0xE8, 0x38, 0x00, 0x00, 0x00, 0x89, 0x45, 0xF4,
			0xC7, 0x45, 0xF0, 0xCC, 0xCC, 0xCC, 0xCC, 0x8D, 0x5D, 0xF8, 0x53, 0x6A, 0x40, 0x6A, 0x05, 0xFF,
			0x75, 0xF0, 0xFF, 0xD0, 0x8B, 0x45, 0xF0, 0xC6, 0x00, 0xCC, 0x40, 0xC7, 0x00, 0xCC, 0xCC, 0xCC,
			0xCC, 0x8D, 0x5D, 0xF8, 0x53, 0xFF, 0x75, 0xF8, 0x6A, 0x05, 0xFF, 0x75, 0xF0, 0xFF, 0x55, 0xF4,
			0xFF, 0x65, 0xF0, 0xC9, 0xC3, 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x0C, 0x8B, 0xD9, 0x89, 0x55, 0xF8,
			0x56, 0x57, 0x8B, 0x43, 0x3C, 0x8B, 0x44, 0x18, 0x78, 0x8B, 0x54, 0x18, 0x1C, 0x8B, 0x4C, 0x18,
			0x20, 0x03, 0xD3, 0x8B, 0x7C, 0x18, 0x24, 0x03, 0xCB, 0x89, 0x55, 0xF4, 0x03, 0xFB, 0x8B, 0x31,
			0x03, 0xF3, 0x89, 0x4D, 0xFC, 0x8A, 0x06, 0x0F, 0xBE, 0xD0, 0x84, 0xC0, 0x74, 0x12, 0x46, 0xC1,
			0xCA, 0x07, 0x8A, 0x0E, 0x0F, 0xBE, 0xC1, 0x03, 0xD0, 0x84, 0xC9, 0x75, 0xF1, 0x8B, 0x4D, 0xFC,
			0x3B, 0x55, 0xF8, 0x74, 0x08, 0x83, 0xC1, 0x04, 0x83, 0xC7, 0x02, 0xEB, 0xD1, 0x0F, 0xB7, 0x07,
			0x8B, 0x4D, 0xF4, 0x5F, 0x5E, 0x8B, 0x04, 0x81, 0x03, 0xC3, 0xC9, 0xC3
		};
		CString csFilePath;
		m_FilePath.GetWindowTextW(csFilePath);
		HANDLE hFile = CreateFile(csFilePath.GetBuffer(), GENERIC_READ | GENERIC_WRITE, \
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, \
			OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		DWORD dwEntryAddr = 0;
		if (hFile != INVALID_HANDLE_VALUE) {
			DWORD dwFileSize = GetFileSize(hFile, NULL);
			char* szBuffer = new char[dwFileSize] { 0 };
			DWORD dwRealRead;
			BOOL bRet = ReadFile(hFile, szBuffer, dwFileSize, &dwRealRead, NULL);
			if (bRet) {
				PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)szBuffer;
				PIMAGE_NT_HEADERS32 pNtHeader = (PIMAGE_NT_HEADERS32)((LONG_PTR)pDosHeader + pDosHeader->e_lfanew);
				dwEntryAddr = pNtHeader->OptionalHeader.AddressOfEntryPoint;
				dwEntryAddr += pNtHeader->OptionalHeader.ImageBase;
				pNtHeader->FileHeader.Characteristics |= 1;
				SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
				bRet = WriteFile(hFile, szBuffer, dwFileSize, &dwRealRead, NULL);
			}
			delete[]szBuffer;
			CloseHandle(hFile);
		}
		STARTUPINFOW si{ sizeof(si) };
		PROCESS_INFORMATION pi{ 0 };
		BOOL bRet = CreateProcess(csFilePath.GetBuffer(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
		if (bRet) {
			char JmpCode[5];
			DWORD dwlen = csdllPath.GetLength();
			char* szBuffer = new char[dwlen + 1]{ 0 };
			int nNeedChars = WideCharToMultiByte(CP_ACP, 0, csdllPath.GetBuffer(), -1, 0, 0, 0, 0);
			if (nNeedChars > 0)//再次判断一下
			{
				::WideCharToMultiByte(CP_ACP, 0, csdllPath.GetBuffer(), -1, szBuffer, nNeedChars, 0, 0);
				LPVOID lpBuffer = VirtualAllocEx(pi.hProcess, NULL, MAX_PATH, MEM_COMMIT, PAGE_READWRITE);
				if (lpBuffer) {
					SIZE_T dwRealWrite;
					bRet = WriteProcessMemory(pi.hProcess, lpBuffer, szBuffer, strlen(szBuffer) + 1, &dwRealWrite);
					if (!bRet) {
						return;
					}
					LPVOID lpShellcode = VirtualAllocEx(pi.hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
					if (lpShellcode) {
						char OldCode[5]{ 0 };
						if (dwEntryAddr) {
							char JmpCode[5];
							JmpCode[0] = 0xE9;
							*(DWORD*)(JmpCode + 1) = (DWORD)lpShellcode - (dwEntryAddr + 5);
							bRet = ReadProcessMemory(pi.hProcess, (LPVOID)dwEntryAddr, OldCode, 5, &dwRealWrite);
							bRet = WriteProcessMemory(pi.hProcess, (LPVOID)dwEntryAddr, JmpCode, 5, &dwRealWrite);
						}
						*(DWORD*)(ShellcodeInject + 0x29) = (DWORD)lpBuffer;
						*(DWORD*)(ShellcodeInject + 0x43) = dwEntryAddr;

						*(BYTE*)(ShellcodeInject + 0x59) = OldCode[0];
						*(DWORD*)(ShellcodeInject + 0x5D) = *(DWORD*)(OldCode + 1);
						bRet = WriteProcessMemory(pi.hProcess, lpShellcode, ShellcodeInject, sizeof(ShellcodeInject), &dwRealWrite);
						//						VirtualFreeEx(pi.hProcess, lpShellcode, 0, MEM_RELEASE);
					}
					//					VirtualFreeEx(pi.hProcess, lpBuffer, 0, MEM_RELEASE);
				}
			}
			ResumeThread(pi.hThread);
			m_dwProcessId = pi.dwProcessId;
			UpdateData(FALSE);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
		}


		Sleep(100);
		//		*(DWORD*)(hexData1 + 42) = (DWORD)szBuffer;
		InitModuleList();
	}
	else if (nInjectType == 1 && nx86orx64 == 1) {

		CString csFilePath;
		m_FilePath.GetWindowTextW(csFilePath);
		STARTUPINFOW si{ sizeof(si) };
		PROCESS_INFORMATION pi{ 0 };
		BOOL bRet = CreateProcess(csFilePath.GetBuffer(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
		m_dwProcessId = pi.dwProcessId;
		RemoteThreadInject(m_dwProcessId, csdllPath);
		UpdateData(FALSE);
		ResumeThread(pi.hThread);
		Sleep(100);
		InitModuleList();

	}
	else if (nInjectType == 2 && nx86orx64 == 0) {
		STARTUPINFO startupInfo{ sizeof(startupInfo) };
		PROCESS_INFORMATION procInfo;
		WCHAR wcsCmd[MAX_PATH];
		wsprintf(wcsCmd, L"X86Injecter.exe %d %d %s", 2, m_dwProcessId, csdllPath.GetBuffer());
		CreateProcess(L"X86Injecter.exe", wcsCmd, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &procInfo);
		WaitForSingleObject(procInfo.hThread, -1);
		CloseHandle(procInfo.hProcess);
		CloseHandle(procInfo.hThread);




		InitModuleList();
	}
	else if (nInjectType == 2 && nx86orx64 == 1) {
		Inject injector;
		injector.UnTraceInject(m_dwProcessId, csdllPath.GetBuffer());
		InitModuleList();
	}
}


void CInjectorMFCDlg::OnUnLoad() {
	// TODO: 在此添加命令处理程序代码
	int nPos = (int)m_ModuleList.GetFirstSelectedItemPosition() - 1;
	CString csModuleBase = m_ModuleList.GetItemText(nPos, 1);
	LONG_PTR dwModuleHandle = wcstoll(csModuleBase.GetBuffer(), NULL, 16);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_dwProcessId);
	if (hProcess != INVALID_HANDLE_VALUE) {
		//		LONG_PTR ptr =(LONG_PTR)GetProcAddress(LoadLibraryA("kernel32.dll"), "FreeLibrary");
		HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)FreeLibrary, (LPVOID)dwModuleHandle, 0, NULL);
		if (hThread) {
			WaitForSingleObject(hThread, -1);
			CloseHandle(hThread);
		}
		CloseHandle(hProcess);
	}
	InitModuleList();
}


void CInjectorMFCDlg::OnUnloadx86() {
	// TODO: 在此添加命令处理程序代码
	int nPos = (int)m_ModuleList.GetFirstSelectedItemPosition() - 1;
	CString csModuleName = m_ModuleList.GetItemText(nPos, 0);

	STARTUPINFO startupInfo{ sizeof(startupInfo) };
	PROCESS_INFORMATION procInfo;
	WCHAR wcsCmd[MAX_PATH];
	wsprintf(wcsCmd, L"X86Injecter.exe %d %d %s", 1, m_dwProcessId, csModuleName.GetBuffer());
	BOOL bRet = CreateProcess(L"X86Injecter.exe", wcsCmd, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &procInfo);
	WaitForSingleObject(procInfo.hThread, -1);
	CloseHandle(procInfo.hProcess);
	CloseHandle(procInfo.hThread);
	InitModuleList();
}


void CInjectorMFCDlg::OnBnClickedButton4() {
	// TODO: 在此添加控件通知处理程序代码
	CFileDialog fileDlg(TRUE, NULL, NULL, NULL, L"可执行程序|*.exe||", this);
	fileDlg.DoModal();
	CString csDllPath = fileDlg.GetPathName();
	m_FilePath.SetWindowTextW(csDllPath);
}
