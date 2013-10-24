/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Windows Client
 *
 * Copyright 2009-2011 Jay Sorg
 * Copyright 2010-2011 Vic Lee
 * Copyright 2010-2011 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <winpr/windows.h>

#include <winpr/crt.h>
#include <winpr/credui.h>

#include <freerdp/freerdp.h>
#include <freerdp/constants.h>
#include <freerdp/utils/event.h>
#include <freerdp/utils/svc_plugin.h>

#include <freerdp/client/file.h>
#include <freerdp/client/cmdline.h>
#include <freerdp/client/channels.h>
#include <freerdp/channels/channels.h>

#include "resource.h"
#include <strsafe.h>

#include "wf_interface.h"

#pragma comment(lib,"winscard")


//#include <wincred.h>
#define OFFSET(type, field) ((ULONG_PTR)(&((type *)0)->field))

typedef struct _SC_Csp_Data
{
	PWSTR pszCardName;
	UINT cbCardName;
	PWSTR pszReaderName;
	UINT cbReaderName;
	PWSTR pszContainerName;
	UINT cbContainerName;
	PWSTR pszCspName;
	UINT cbCspName;
} SC_CSP_DATA, *PSC_CSP_DATA;

extern SC_CSP_DATA gSCCspData;

BOOL CopyCspDataValue(PKERB_SMARTCARD_CSP_INFO cspInfo, PWSTR* buffer, PUINT len, DWORD offset)
{
				DWORD bufferLen = cspInfo->dwCspInfoLen - (ULONG) OFFSET(KERB_SMARTCARD_CSP_INFO, bBuffer); // (pInfo->nCardNameOffset*sizeof(TCHAR));
				size_t fieldLen = 0;
	/*
				PWSTR pszStart = (PWSTR)&cspInfo->bBuffer + (offset * sizeof(WCHAR));
				PWSTR pszEnd = (PWSTR)&cspInfo->bBuffer+bufferLen;
				*len = 0;
				while (pszStart <= pszEnd) {
					*len += sizeof(WCHAR);

					if (L'\0' == *pszStart) {
						break;
					}

					pszStart++;
				}
				*buffer =  (PWSTR)malloc(*len);
	*/
				STRSAFE_PCNZWCH start = (&cspInfo->bBuffer)+offset;
				StringCbLength(start, bufferLen, &fieldLen);
				*buffer = (PWSTR)malloc(fieldLen);
				RtlCopyMemory(*buffer, &cspInfo->bBuffer+offset, fieldLen);
				*len = fieldLen;
				return TRUE;
}

INT WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	int index;
	int status;
	HANDLE thread;
	wfContext* wfc;
	DWORD dwExitCode;
	rdpContext* context;
	rdpSettings* settings;
	RDP_CLIENT_ENTRY_POINTS clientEntryPoints;
	DWORD dwResult;

	PVOID   pvInAuthBlob = NULL;
	ULONG   cbInAuthBlob = 0;
	PVOID   pvAuthBlob = NULL;
	ULONG   cbAuthBlob = 0;
	CREDUI_INFO ui;
	ULONG   ulAuthPackage = 0;
	BOOL    fSave = FALSE;

	WCHAR   szUsername[MAX_PATH] = {0};
	DWORD   cchUsername = ARRAYSIZE(szUsername);
	WCHAR   szPassword[MAX_PATH] = {0};
	DWORD		cchPassword = ARRAYSIZE(szPassword);
	WCHAR   szDomain[MAX_PATH] = {0};
	DWORD   cchDomain = ARRAYSIZE(szDomain);
	BOOL ret;
	DWORD flags = CRED_PACK_PROTECTED_CREDENTIALS | CRED_PACK_GENERIC_CREDENTIALS;

	gLogMutex = CreateMutex(NULL, FALSE, NULL);

	// Display a dialog box to request credentials.
	ui.cbSize = sizeof(ui);
	ui.hwndParent = NULL; //GetConsoleWindow();
	ui.pszMessageText = L"Connect to RDP server";
	ui.pszCaptionText = L"Enter your credentials";
	ui.hbmBanner = NULL;

	ZeroMemory(&clientEntryPoints, sizeof(RDP_CLIENT_ENTRY_POINTS));
	clientEntryPoints.Size = sizeof(RDP_CLIENT_ENTRY_POINTS);
	clientEntryPoints.Version = RDP_CLIENT_INTERFACE_VERSION;

	RdpClientEntry(&clientEntryPoints);

	context = freerdp_client_context_new(&clientEntryPoints);

	settings = context->settings;
	wfc = (wfContext*) context;

	context->argc = __argc;
	context->argv = (char**) malloc(sizeof(char*) * __argc);

	for (index = 0; index < context->argc; index++)
		context->argv[index] = _strdup(__argv[index]);

	status = freerdp_client_parse_command_line(context, context->argc, context->argv);

	status = freerdp_client_command_line_status_print(context->argc, context->argv, settings, status);

	if (status)
	{
		_getch();
		freerdp_client_context_free(context);
		return 0;
	}

	dwResult = CredUIPromptForWindowsCredentials(
		&ui,             // Customizing information
		0,               // Error code to display
		&ulAuthPackage,  // Authorization package
		NULL,    // Credential byte array
		0,    // Size of credential input buffer
		&pvAuthBlob,     // Output credential byte array
		&cbAuthBlob,     // Size of credential byte array
		&fSave,          // Select the save check box.
		CREDUIWIN_AUTHPACKAGE_ONLY
		);
	if (dwResult != NO_ERROR) {
		return 0;
	}

	{
		PKERB_INTERACTIVE_LOGON pLogon = (PKERB_INTERACTIVE_LOGON)pvAuthBlob;

		switch (pLogon->MessageType) {
		case 13 /*KerbCertificateLogon*/:
		case KerbSmartCardLogon:
			{
				int x = 0;
				PWSTR pszCardName = NULL;
				PWSTR pszContainerName = NULL;

				DWORD cardNameLen = 0;
				DWORD containerNameLen = 0;

				PKERB_CERTIFICATE_LOGON pCertLogon = (PKERB_CERTIFICATE_LOGON)pvAuthBlob;
				unsigned int csp_offset = (UINT)pCertLogon->CspData;

				PKERB_SMARTCARD_CSP_INFO pInfo = (PKERB_SMARTCARD_CSP_INFO)((PBYTE)pvAuthBlob+csp_offset);

				CopyCspDataValue(pInfo, &gSCCspData.pszCardName, &gSCCspData.cbCardName, pInfo->nCardNameOffset);
				CopyCspDataValue(pInfo, &gSCCspData.pszReaderName, &gSCCspData.cbReaderName, pInfo->nReaderNameOffset);
				CopyCspDataValue(pInfo, &gSCCspData.pszContainerName, &gSCCspData.cbContainerName, pInfo->nContainerNameOffset);
				CopyCspDataValue(pInfo, &gSCCspData.pszCspName, &gSCCspData.cbCspName, pInfo->nCSPNameOffset);
				break;
			}

		default:
			break;
		}
	}

	ret = CredUnPackAuthenticationBuffer(flags, pvAuthBlob, cbAuthBlob, &szUsername[0], &cchUsername, &szDomain[0], &cchDomain, &szPassword[0], &cchPassword); 
	if (ret == TRUE) {
		int len = 0;
#if 0
		if (CredIsMarshaledCredential(szUsername)) {
			CRED_MARSHAL_TYPE cmType;
			void* cmData;
			PCERT_CREDENTIAL_INFO ci;
			CredUnmarshalCredential(szUsername, &cmType, &cmData);

			ci = (PCERT_CREDENTIAL_INFO)cmData;
			len = ci->cbSize;
			settings->Username = (char *)malloc(len);
			StringCbCopyA(settings->Username, len, (STRSAFE_LPCSTR)ci->rgbHashOfCert);
		} else {
#else
		{
			len = cchUsername + 1;
			settings->Username = (char*)malloc(len);
			WideCharToMultiByte(CP_ACP, 0, szUsername, cchUsername, settings->Username, len, NULL, NULL);
		}
#endif

		len = cchDomain + 1;
		settings->Domain = (char*)malloc(len);
		WideCharToMultiByte(CP_ACP, 0, szDomain, cchDomain, settings->Domain, len, NULL, NULL);

		len = cchPassword + 1;
		settings->Password = (char*)malloc(len);
		WideCharToMultiByte(CP_ACP, 0, szPassword, cchPassword, settings->Password, len, NULL, NULL);
		settings->CredentialsType = 2;
	}

	freerdp_client_start(context);

	thread = freerdp_client_get_thread(context);

	WaitForSingleObject(thread, INFINITE);

	GetExitCodeThread(thread, &dwExitCode);

	freerdp_client_stop(context);

	//_getch();

	freerdp_client_context_free(context);

	return 0;
}
