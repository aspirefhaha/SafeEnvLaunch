// AdminPwdDlg.cpp : implementation file
//

#include "stdafx.h"
#include "SafeEnvLaunch.h"
#include "AdminPwdDlg.h"
#include "afxdialogex.h"


// CAdminPwdDlg dialog

IMPLEMENT_DYNAMIC(CAdminPwdDlg, CDialog)

CAdminPwdDlg::CAdminPwdDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CAdminPwdDlg::IDD, pParent)
{

	m_strAdminPwd = _T("");
}

CAdminPwdDlg::~CAdminPwdDlg()
{
}

void CAdminPwdDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_PWD, m_strAdminPwd);
}


BEGIN_MESSAGE_MAP(CAdminPwdDlg, CDialog)
END_MESSAGE_MAP()


// CAdminPwdDlg message handlers
