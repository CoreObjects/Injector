
// InjectorMFCDlg.h: 头文件
//

#pragma once


// CInjectorMFCDlg 对话框
class CInjectorMFCDlg : public CDialogEx
{
// 构造
public:
	CInjectorMFCDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_INJECTORMFC_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CComboBox m_Inject_type;
	CComboBox m_x86orx64;
	CListCtrl m_ModuleList;
	CEdit m_ModulePath;
	DWORD m_dwProcessId;
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton2();
	BOOL RemoteThreadInject(DWORD dwProcessId, CString csDllPath);
	void InitModuleList();
	void MsgHookInject();
	afx_msg void OnContextMenu(CWnd* /*pWnd*/, CPoint /*point*/);
	afx_msg void OnFlush();
	afx_msg void OnBnClickedButton3();
	afx_msg void OnUnLoad();
	afx_msg void OnUnloadx86();
	CEdit m_FilePath;
	afx_msg void OnBnClickedButton4();
};
