#pragma once


// CAdminPwdDlg dialog

class CAdminPwdDlg : public CDialog
{
	DECLARE_DYNAMIC(CAdminPwdDlg)

public:
	CAdminPwdDlg(CWnd* pParent = NULL);   // standard constructor
	virtual ~CAdminPwdDlg();

// Dialog Data
	enum { IDD = IDD_DIALOG_INPUTPWD };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	CString m_strAdminPwd;
};
