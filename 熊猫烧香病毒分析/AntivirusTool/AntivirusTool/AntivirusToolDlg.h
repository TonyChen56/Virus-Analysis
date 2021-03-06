
// AntivirusToolDlg.h: 头文件
//

#pragma once


// CAntivirusToolDlg 对话框
class CAntivirusToolDlg : public CDialogEx
{
// 构造
public:
	CAntivirusToolDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ANTIVIRUSTOOL_DIALOG };
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
	afx_msg void OnBnClickedButton1();
	CString m_Edit;

	//1.在内存中查找病毒是否还存在
	BOOL FindTargetProcess(char* pszProcessName,DWORD *dwPid);
	//2.提升权限,访问一些受限制的系统资源
	bool EnableDebugPrivilege(char * pszPrivilege);
	//3.计算CRC32值
	DWORD CRC32(BYTE* ptr, DWORD Size);
};
