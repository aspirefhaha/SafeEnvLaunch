
// SafeEnvLaunchDlg.h : header file
//

#pragma once


// CSafeEnvLaunchDlg dialog
class CSafeEnvLaunchDlg : public CDialogEx
{
// Construction
public:
	CSafeEnvLaunchDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	enum { IDD = IDD_SAFEENVLAUNCH_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg LRESULT OnMyMsgHandler(WPARAM w,LPARAM l);
	afx_msg LRESULT OnMyStartHandler(WPARAM w,LPARAM l);
	afx_msg LRESULT OnMyEndHandler(WPARAM w, LPARAM l);
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedButtonCheck();
	CStatic m_csOS;
	CStatic m_csOSBit;
private:
	void getSystemName();
	void CheckPwd();
	BOOL IsInputPwd;
public:
	CProgressCtrl m_pcSetup;
	int totalStep ;
	afx_msg void OnBnClickedButtonInstall();
	afx_msg void OnBnClickedButtonUninstall();
	CStatic m_csStatus;
};
