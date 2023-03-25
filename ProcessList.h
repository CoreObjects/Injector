#pragma once


// ProcessList 对话框

class ProcessList : public CDialogEx
{
	DECLARE_DYNAMIC(ProcessList)

public:
	ProcessList(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~ProcessList();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG1 };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
	virtual BOOL OnInitDialog();

	void InitModuleList();

	DECLARE_MESSAGE_MAP()
public:
	CListCtrl m_ProcessList;
	afx_msg void OnContextMenu(CWnd* /*pWnd*/, CPoint /*point*/);
	afx_msg void OnFlush();
	afx_msg void OnGetProcessId();
	afx_msg void OnDblclkList1(NMHDR* pNMHDR, LRESULT* pResult);
};
