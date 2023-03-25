// ProcessList.cpp: 实现文件
//

#include "pch.h"
#include "InjectorMFC.h"
#include "ProcessList.h"
#include "afxdialogex.h"
#include <TlHelp32.h>

// ProcessList 对话框

IMPLEMENT_DYNAMIC(ProcessList, CDialogEx)

ProcessList::ProcessList(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG1, pParent) {

}

ProcessList::~ProcessList() {
}

void ProcessList::DoDataExchange(CDataExchange* pDX) {
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, m_ProcessList);
}


BOOL ProcessList::OnInitDialog() {
	CDialogEx::OnInitDialog();
	SetWindowTextW(L"进程列表");
	m_ProcessList.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	m_ProcessList.InsertColumn(0, L"进程名", 0, 250);
	m_ProcessList.InsertColumn(1, L"进程ID", 0, 100);
	InitModuleList();

	return TRUE;
}

void ProcessList::InitModuleList() {
	m_ProcessList.DeleteAllItems();
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 pe32{ sizeof(pe32) };
		BOOL bRet = Process32First(hSnap, &pe32);
		DWORD dwIndex = 0;
		while (bRet) {
			m_ProcessList.InsertItem(dwIndex, pe32.szExeFile);
			CString csProcessId;
			csProcessId.Format(L"%d", pe32.th32ProcessID);
			m_ProcessList.SetItemText(dwIndex, 1, csProcessId);
			bRet = Process32Next(hSnap, &pe32);
			dwIndex++;
		}
	}
}

BEGIN_MESSAGE_MAP(ProcessList, CDialogEx)
	ON_WM_CONTEXTMENU()
	ON_COMMAND(ID_YOUJIAN_32771, &ProcessList::OnFlush)
	ON_COMMAND(ID_YOUJIAN_32772, &ProcessList::OnGetProcessId)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST1, &ProcessList::OnDblclkList1)
END_MESSAGE_MAP()


// ProcessList 消息处理程序


void ProcessList::OnContextMenu(CWnd* pWnd, CPoint pt) {
	// TODO: 在此处添加消息处理程序代码
	CMenu mMenu;
	mMenu.LoadMenuW(IDR_MENU1);
	CMenu* mSubMenu = mMenu.GetSubMenu(0);
	mSubMenu->TrackPopupMenu(TPM_CENTERALIGN, pt.x, pt.y, this);

}


void ProcessList::OnFlush() {
	// TODO: 在此添加命令处理程序代码
	InitModuleList();
}


void ProcessList::OnGetProcessId() {
	// TODO: 在此添加命令处理程序代码
	int nPos = (int)m_ProcessList.GetFirstSelectedItemPosition() - 1;
	DWORD dwProcessId = _ttoi(m_ProcessList.GetItemText(nPos, 1));
	EndDialog(dwProcessId);
//	::SendMessage(this->m_hWnd, 0x12138, dwProcessId, NULL);
}


void ProcessList::OnDblclkList1(NMHDR* pNMHDR, LRESULT* pResult) {
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	int nPos = (int)m_ProcessList.GetFirstSelectedItemPosition() - 1;
	DWORD dwProcessId = _ttoi(m_ProcessList.GetItemText(nPos, 1));
	EndDialog(dwProcessId);
	*pResult = 0;
}
