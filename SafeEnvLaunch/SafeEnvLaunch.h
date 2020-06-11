
// SafeEnvLaunch.h : main header file for the PROJECT_NAME application
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols


// CSafeEnvLaunchApp:
// See SafeEnvLaunch.cpp for the implementation of this class
//

class CSafeEnvLaunchApp : public CWinApp
{
public:
	CSafeEnvLaunchApp();

// Overrides
public:
	virtual BOOL InitInstance();

// Implementation

	DECLARE_MESSAGE_MAP()
};

extern CSafeEnvLaunchApp theApp;