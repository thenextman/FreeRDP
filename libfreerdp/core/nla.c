/**
 * WinPR: Windows Portable Runtime
 * Network Level Authentication (NLA)
 *
 * Copyright 2010-2012 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *		 http://www.apache.org/licenses/LICENSE-2.0
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

#include <time.h>

#ifndef _WIN32
#include <unistd.h>
#endif


#include <freerdp/crypto/tls.h>

#include <winpr/crt.h>
#include <winpr/sspi.h>
#include <winpr/print.h>
#include <winpr/tchar.h>
#include <winpr/library.h>
#include <winpr/registry.h>
#include <winpr/credentials.h>

#include "nla.h"

#include <strsafe.h>
/**
 * TSRequest ::= SEQUENCE {
 * 	version    [0] INTEGER,
 * 	negoTokens [1] NegoData OPTIONAL,
 * 	authInfo   [2] OCTET STRING OPTIONAL,
 * 	pubKeyAuth [3] OCTET STRING OPTIONAL
 * }
 *
 * NegoData ::= SEQUENCE OF NegoDataItem
 *
 * NegoDataItem ::= SEQUENCE {
 * 	negoToken [0] OCTET STRING
 * }
 *
 * TSCredentials ::= SEQUENCE {
 * 	credType    [0] INTEGER,
 * 	credentials [1] OCTET STRING
 * }
 *
 * TSPasswordCreds ::= SEQUENCE {
 * 	domainName  [0] OCTET STRING,
 * 	userName    [1] OCTET STRING,
 * 	password    [2] OCTET STRING
 * }
 *
 * TSSmartCardCreds ::= SEQUENCE {
 * 	pin        [0] OCTET STRING,
 * 	cspData    [1] TSCspDataDetail,
 * 	userHint   [2] OCTET STRING OPTIONAL,
 * 	domainHint [3] OCTET STRING OPTIONAL
 * }
 *
 * TSCspDataDetail ::= SEQUENCE {
 * 	keySpec       [0] INTEGER,
 * 	cardName      [1] OCTET STRING OPTIONAL,
 * 	readerName    [2] OCTET STRING OPTIONAL,
 * 	containerName [3] OCTET STRING OPTIONAL,
 * 	cspName       [4] OCTET STRING OPTIONAL
 * }
 *
 */

#define USE_NEGOTIATE
//#define USE_KERBEROS

#ifdef WITH_DEBUG_NLA
#define WITH_DEBUG_CREDSSP
#endif

#ifdef WITH_NATIVE_SSPI
#define NLA_PKG_NAME	NTLMSP_NAME
#if defined(USE_NEGOTIATE)
#define NLA_SC_PKG_NAME NEGOSSP_NAME
#elif defined(USE_KERBEROS)
#define NLA_SC_PKG_NAME MICROSOFT_KERBEROS_NAME
#endif

int save_ts_request = 0;
#else
#define NLA_PKG_NAME	NTLMSP_NAME
#endif

#define TERMSRV_SPN_PREFIX	"TERMSRV/"

#define LOGMSG(Msg, ...) fprintf(stderr, Msg, ##__VA_ARGS__); fflush(stderr);

void credssp_send(rdpCredssp* credssp);
int credssp_recv(rdpCredssp* credssp);
void credssp_buffer_print(rdpCredssp* credssp);
void credssp_buffer_free(rdpCredssp* credssp);
SECURITY_STATUS credssp_encrypt_public_key_echo(rdpCredssp* credssp);
SECURITY_STATUS credssp_encrypt_public_key_echo_nego(rdpCredssp* credssp);
SECURITY_STATUS credssp_decrypt_public_key_echo(rdpCredssp* credssp);
//SECURITY_STATUS credssp_decrypt_public_key_echo_nego(rdpCredssp* credssp);
SECURITY_STATUS credssp_encrypt_ts_credentials(rdpCredssp* credssp);
SECURITY_STATUS credssp_encrypt_ts_credentials_nego(rdpCredssp* credssp);
SECURITY_STATUS credssp_decrypt_ts_credentials(rdpCredssp* credssp);

void credssp_encode_ts_credentials(rdpCredssp* credssp);

#define ber_sizeof_sequence_octet_string(length) ber_sizeof_contextual_tag(ber_sizeof_octet_string(length)) + ber_sizeof_octet_string(length)
#define ber_sizeof_sequence_integer(i) ber_sizeof_contextual_tag(ber_sizeof_integer(i)) + ber_sizeof_integer(i)
#define ber_write_sequence_octet_string(stream, context, value, length) ber_write_contextual_tag(stream, context, ber_sizeof_octet_string(length), TRUE) + ber_write_octet_string(stream, value, length)
#define ber_write_sequence_integer(stream, context, value) ber_write_contextual_tag(stream, context, ber_sizeof_integer(value), TRUE) + ber_write_integer(stream, value)
#define ber_write_sequence_header(stream, context, length) ber_write_contextual_tag(stream, context, ber_sizeof_sequence_octet_string(length), TRUE) + ber_write_octet_string_tag(stream, ber_sizeof_sequence(length))
#define ber_write_sequence_header(stream, context, length) ber_write_contextual_tag(stream, context, ber_sizeof_sequence_octet_string(length), TRUE) + ber_write_octet_string_tag(stream, ber_sizeof_sequence(length))

SC_CSP_DATA gSCCspData = {0};

void SaveBufferToFile(const char* filename, PBYTE data, int length)
{
	FILE *fp;

	fp = fopen(filename, "wb");
	if (fp != NULL) {
		fwrite(data, length, 1, fp);
		fclose(fp);
	}
}

static void PrintHexDump( DWORD length, PBYTE buffer )
{
  DWORD i,count,index;
  CHAR rgbDigits[]="0123456789abcdef";
  CHAR rgbLine[100];
  char cbLine;

  for(index = 0; length; length -= count, buffer += count, index += count) {
    count = (length > 16) ? 16:length;
    sprintf(rgbLine, "%4.4x  ",index);
    cbLine = 6;

    for(i=0; i<count; i++) {
      rgbLine[cbLine++] = rgbDigits[buffer[i] >> 4];
      rgbLine[cbLine++] = rgbDigits[buffer[i] & 0x0f];
      if(i == 7) {
        rgbLine[cbLine++] = ':';
      } else {
        rgbLine[cbLine++] = ' ';
      }
    }
    for(; i < 16; i++) {
      rgbLine[cbLine++] = ' ';
      rgbLine[cbLine++] = ' ';
      rgbLine[cbLine++] = ' ';
    }
    rgbLine[cbLine++] = ' ';

    for(i = 0; i < count; i++) {
      if(buffer[i] < 32 || buffer[i] > 126 || buffer[i] == '%') {
        rgbLine[cbLine++] = '.';
      } else {
        rgbLine[cbLine++] = buffer[i];
      }
    }
    rgbLine[cbLine++] = 0;
    printf("%s\n", rgbLine);
		OutputDebugStringA(rgbLine);
  }
}

/**
 * Initialize NTLMSSP authentication module (client).
 * @param credssp
 */

#include <ntdsapi.h>
#pragma comment(lib,"ntdsapi")

int credssp_ntlm_client_init(rdpCredssp* credssp)
{
	char* spn;
	int length;
	freerdp* instance;
	rdpSettings* settings;
	DWORD fn = 0;
	LPTSTR* f = NULL;

	settings = credssp->settings;
	instance = (freerdp*) settings->instance;

	if ((settings->Password == NULL) || (settings->Username == NULL))
	{
		if (instance->Authenticate)
		{
			BOOL proceed = instance->Authenticate(instance,
					&settings->Username, &settings->Password, &settings->Domain);
			if (!proceed)
				return 0;
		}
	}

	sspi_SetAuthIdentity(&(credssp->identity), settings->Username, settings->Domain, settings->Password);

#ifdef WITH_DEBUG_NLA
	//_tprintf(_T("User: %s Domain: %s Password: %s\n"), (char*) credssp->identity.User, (char*) credssp->identity.Domain, (char*) credssp->identity.Password);
#endif

	sspi_SecBufferAlloc(&credssp->PublicKey, credssp->transport->TlsIn->PublicKeyLength);
	CopyMemory(credssp->PublicKey.pvBuffer, credssp->transport->TlsIn->PublicKey, credssp->transport->TlsIn->PublicKeyLength);

#if 0
	length = sizeof(TERMSRV_SPN_PREFIX) + strlen(settings->ServerHostname) + strlen(".dev.local:3389");

	spn = (SEC_CHAR*) malloc(length + 1);
	sprintf(spn, "%s%s.dev.local:3389", TERMSRV_SPN_PREFIX, settings->ServerHostname);
#endif

#ifdef UNICODE
#if 0
	credssp->ServicePrincipalName = (LPTSTR) malloc(length * 2 + 2);
	MultiByteToWideChar(CP_UTF8, 0, spn, length,
		(LPWSTR) credssp->ServicePrincipalName, length);
	free(spn);
#else
#if 1
	{
		//DWORD st;
		//DWORD dwLen = 0;
		int hostLen = strlen(credssp->settings->ServerHostname);
		int serviceLen = sizeof(TERMSRV_SPN_PREFIX);
		DWORD dwLen = (serviceLen+hostLen)*sizeof(WCHAR);
		//PWCHAR host = (PWCHAR)malloc(hostLen);
		//MultiByteToWideChar(CP_UTF8, 0, credssp->settings->ServerHostname, strlen(credssp->settings->ServerHostname), host, hostLen);
		//st = DsMakeSpn(L"TERMSRV", host, NULL, (credssp->settings->ServerPort == 3389) ? 0 : credssp->settings->ServerPort, NULL, &dwLen, NULL);
		credssp->ServicePrincipalName = (PWCHAR)malloc(dwLen+4);
		ZeroMemory(credssp->ServicePrincipalName, dwLen+4);
		StringCchPrintf(credssp->ServicePrincipalName, dwLen, L"%S%S", TERMSRV_SPN_PREFIX, strupr(credssp->settings->ServerHostname));
		//st = DsMakeSpn(L"TERMSRV", host, NULL, (credssp->settings->ServerPort == 3389) ? 0 : credssp->settings->ServerPort, NULL, &dwLen, credssp->ServicePrincipalName);
		//free(host);
	}
#else
	credssp->ServicePrincipalName = _wcsdup(L"TERMSRV/ad.dev.local");
#endif
#endif
#else
	credssp->ServicePrincipalName = spn;
#endif

	return 1;
}

/**
 * Initialize NTLMSSP authentication module (server).
 * @param credssp
 */

int credssp_ntlm_server_init(rdpCredssp* credssp)
{
	freerdp* instance;
	rdpSettings* settings = credssp->settings;
	instance = (freerdp*) settings->instance;

	sspi_SecBufferAlloc(&credssp->PublicKey, credssp->transport->TlsIn->PublicKeyLength);
	CopyMemory(credssp->PublicKey.pvBuffer, credssp->transport->TlsIn->PublicKey, credssp->transport->TlsIn->PublicKeyLength);

	return 1;
}


void LogSSPIError(SECURITY_STATUS sc)
{
	LOGMSG("SECURITY_STATUS: %#x - ", sc);
	switch (sc) {
	case SEC_E_QOP_NOT_SUPPORTED:
				LOGMSG("Neither confidentiality nor integrity are supported by the security context.\n");
				break;
	case SEC_E_INVALID_TOKEN:
				LOGMSG("No SECBUFFER_DATA type buffer was found.\n");
				break;
	case SEC_E_INVALID_HANDLE:
				LOGMSG("A context handle that is not valid was specified in the phContext parameter.\n");
				break;
	case SEC_E_INSUFFICIENT_MEMORY:
				LOGMSG("There is not enough memory available to complete the requested action.\n");
				break;
	case SEC_E_BUFFER_TOO_SMALL:
				LOGMSG("The output buffer is too small.\n");
				break;
	case SEC_E_CONTEXT_EXPIRED:
				LOGMSG("The application is referencing a context that has already been closed. A properly written application should not receive this error.\n");
				break;
	case SEC_E_CRYPTO_SYSTEM_INVALID:
				LOGMSG("The cipher chosen for the security context is not supported.\n");
				break;

			default:
				LOGMSG("Unknown Error: %#x\n", sc);
				break;
			}
}

int credssp_client_authenticate(rdpCredssp* credssp)
{
	ULONG cbMaxToken;
	ULONG fContextReq;
	ULONG pfContextAttr;
	SECURITY_STATUS status;
	SECURITY_STATUS ss;
	CredHandle credentials;
	TimeStamp expiration;
	PSecPkgInfo pPackageInfo;
	SecBuffer input_buffer;
	SecBuffer output_buffer;
	SecBufferDesc input_buffer_desc;
	SecBufferDesc output_buffer_desc;
	BOOL have_context;
	BOOL have_input_buffer;
	BOOL have_pub_key_auth;
	SecPkgContext_PackageInfo pkginfo;

	sspi_GlobalInit();

	if (credssp_ntlm_client_init(credssp) == 0)
		return 0;

#ifdef WITH_NATIVE_SSPI
	{
		HMODULE hSSPI;
		INIT_SECURITY_INTERFACE InitSecurityInterface;
		PSecurityFunctionTable pSecurityInterface = NULL;

		hSSPI = LoadLibrary(_T("secur32.dll"));

#ifdef UNICODE
		InitSecurityInterface = (INIT_SECURITY_INTERFACE) GetProcAddress(hSSPI, "InitSecurityInterfaceW");
#else
		InitSecurityInterface = (INIT_SECURITY_INTERFACE) GetProcAddress(hSSPI, "InitSecurityInterfaceA");
#endif
		credssp->table = (*InitSecurityInterface)();
	}
#else
	credssp->table = InitSecurityInterface();
#endif

	status = credssp->table->QuerySecurityPackageInfo(credssp->providerName, &pPackageInfo);
	//status = credssp->table->QuerySecurityPackageInfo(NLA_PKG_NAME, &pPackageInfo);

	if (status != SEC_E_OK)
	{
		//LOGMSG("QuerySecurityPackageInfo status: 0x%08X\n", status);
		LOGMSG("QuerySecurityPackageInfo status: 0x%08X\n", status);
		return 0;
	}

	cbMaxToken = pPackageInfo->cbMaxToken;

	//credssp->identity.Flags = SEC_WINNT_AUTH_IDENTITY_MARSHALLED | SEC_WINNT_AUTH_IDENTITY_ONLY | SEC_WINNT_AUTH_IDENTITY_UNICODE;
	//credssp->identity.Flags |= SEC_WINNT_AUTH_IDENTITY_ONLY;

	LOGMSG("%s - SPN: %S\n", __FUNCTION__, credssp->ServicePrincipalName);
	LOGMSG("%s - Security Package Name: %S\n", __FUNCTION__, pPackageInfo->Name);
	status = credssp->table->AcquireCredentialsHandle(NULL, pPackageInfo->Name,
		SECPKG_CRED_OUTBOUND, NULL, &credssp->identity, NULL, NULL, &credentials, &expiration);

	if (status != SEC_E_OK)
	{
		LOGMSG("AcquireCredentialsHandle status: 0x%08X\n", status);
		return 0;
	}

	have_context = FALSE;
	have_input_buffer = FALSE;
	have_pub_key_auth = FALSE;
	ZeroMemory(&input_buffer, sizeof(SecBuffer));
	ZeroMemory(&output_buffer, sizeof(SecBuffer));
	ZeroMemory(&credssp->ContextSizes, sizeof(SecPkgContext_Sizes));

	/*
	 * from tspkg.dll: 0x00000132
	 * ISC_REQ_MUTUAL_AUTH
	 * ISC_REQ_CONFIDENTIALITY
	 * ISC_REQ_USE_SESSION_KEY
	 * ISC_REQ_ALLOCATE_MEMORY
	 */

	switch (credssp->CredentialType) {
		case 1:
			LOGMSG("%s - Setting context request flags for CredentialType 1.\n", __FUNCTION__);
			fContextReq = ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR | ISC_REQ_MUTUAL_AUTH | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_USE_SESSION_KEY;
			break;

		case 2:
			LOGMSG("%s - Setting context request flags for CredentialType 2.\n", __FUNCTION__);
#if defined(USE_NEGOTIATE)
		// Flags for Negotiate
			//fContextReq = ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR | ISC_REQ_MUTUAL_AUTH | ISC_REQ_SEQUENCE_DETECT;
			//fContextReq = ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR | ISC_REQ_MUTUAL_AUTH | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_USE_SESSION_KEY | ISC_REQ_STREAM | ISC_REQ_DELEGATE; //Works
			fContextReq = ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR | ISC_REQ_MUTUAL_AUTH | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_USE_SESSION_KEY | ISC_REQ_REPLAY_DETECT | ISC_REQ_DELEGATE | ISC_REQ_USE_SUPPLIED_CREDS;

				//fContextReq = ISC_REQ_CONFIDENTIALITY | ISC_REQ_MUTUAL_AUTH | ISC_REQ_MANUAL_CRED_VALIDATION | ISC_REQ_SEQUENCE_DETECT;
				//fContextReq = ISC_REQ_CONFIDENTIALITY | ISC_REQ_MUTUAL_AUTH | ISC_REQ_USE_DCE_STYLE;
			//fContextReq = ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR | ISC_REQ_MUTUAL_AUTH | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_STREAM | ISC_REQ_DELEGATE;
		//fContextReq = ISC_REQ_CONFIDENTIALITY | ISC_REQ_CONNECTION | ISC_RET_EXTENDED_ERROR | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_MUTUAL_AUTH; //ISC_REQ_INTEGRITY; // | ISC_REQ_USE_DCE_STYLE;
	//fContextReq =                           ISC_REQ_DELEGATE | ISC_RET_EXTENDED_ERROR | ISC_REQ_MUTUAL_AUTH | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM; //v1
	//fContextReq = ISC_REQ_CONFIDENTIALITY | ISC_REQ_CONNECTION | ISC_REQ_DELEGATE | ISC_REQ_EXTENDED_ERROR | ISC_REQ_MUTUAL_AUTH | ISC_REQ_NO_INTEGRITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
	//fContextReq = ISC_REQ_CONFIDENTIALITY | ISC_REQ_DELEGATE | ISC_REQ_EXTENDED_ERROR | ISC_REQ_MUTUAL_AUTH | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT;
	//fContextReq = ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR | ISC_REQ_MUTUAL_AUTH | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_USE_SESSION_KEY;
	//fContextReq = ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR | ISC_REQ_MUTUAL_AUTH |                           ISC_REQ_SEQUENCE_DETECT | ISC_REQ_USE_SESSION_KEY;
#elif defined(USE_KERBEROS)
		// Flags for Kerberos
		//fContextReq = ISC_REQ_CONFIDENTIALITY | ISC_REQ_DELEGATE | ISC_REQ_EXTENDED_ERROR | ISC_REQ_STREAM |                                                                   ISC_REQ_SEQUENCE_DETECT | ISC_REQ_USE_SESSION_KEY | ISC_REQ_USE_SUPPLIED_CREDS ; //v1
		//fContextReq = ISC_REQ_CONFIDENTIALITY | ISC_REQ_DELEGATE | ISC_REQ_EXTENDED_ERROR | ISC_REQ_INTEGRITY | ISC_REQ_MUTUAL_AUTH | ISC_REQ_REPLAY_DETECT | ISC_REQ_STREAM | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_USE_SESSION_KEY;
		  fContextReq = ISC_REQ_CONFIDENTIALITY | ISC_REQ_DELEGATE | ISC_REQ_EXTENDED_ERROR | ISC_REQ_INTEGRITY |                       ISC_REQ_REPLAY_DETECT | ISC_REQ_STREAM | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_USE_SESSION_KEY;
#endif
			break;

		default:
			DebugBreak();
			break;
	}

	while (TRUE)
	{
		output_buffer_desc.ulVersion = SECBUFFER_VERSION;
		output_buffer_desc.cBuffers = 1;
		output_buffer_desc.pBuffers = &output_buffer;
		output_buffer.BufferType = SECBUFFER_TOKEN;
		output_buffer.cbBuffer = cbMaxToken;
		output_buffer.pvBuffer = malloc(output_buffer.cbBuffer);

		status = credssp->table->InitializeSecurityContext(&credentials,
				(have_context) ? &credssp->context : NULL,
				credssp->ServicePrincipalName, fContextReq, 0,
				SECURITY_NATIVE_DREP, (have_input_buffer) ? &input_buffer_desc : NULL,
				0, &credssp->context, &output_buffer_desc, &pfContextAttr, &expiration);

		LOGMSG("%s: InsitializeSecurityContext: status: %#x\n", __FUNCTION__, status);

		if (have_input_buffer && (input_buffer.pvBuffer != NULL))
		{
			free(input_buffer.pvBuffer);
			input_buffer.pvBuffer = NULL;
		}

		if ((status == SEC_I_COMPLETE_AND_CONTINUE) || (status == SEC_I_COMPLETE_NEEDED) || (status == SEC_E_OK))
		{
			LOGMSG("%s: Authentication Complete.\n", __FUNCTION__);
			fContextReq = pfContextAttr;
			LOGMSG("%s: ISC Context Attrs returned: %#x\n", __FUNCTION__, fContextReq);
			if (credssp->table->CompleteAuthToken != NULL)
				ss = credssp->table->CompleteAuthToken(&credssp->context, &output_buffer_desc);

			have_pub_key_auth = TRUE;

			if (credssp->table->QueryContextAttributes(&credssp->context, SECPKG_ATTR_SIZES, &credssp->ContextSizes) != SEC_E_OK)
			{
				LOGMSG("QueryContextAttributes SECPKG_ATTR_SIZES failure\n");
				return 0;
			}

			credssp->table->QueryContextAttributes(&credssp->context, SECPKG_ATTR_PACKAGE_INFO, &pkginfo);

			LOGMSG("%s: Context Package Name: %S\n", __FUNCTION__, pkginfo.PackageInfo->Name);
			//credssp->table->FreeContextBuffer(pkginfo);

			//credssp_encrypt_public_key_echo(credssp);
			//ss = credssp_encrypt_public_key_echo_nego(credssp);
			//if (ss != SEC_E_OK) {
				ss = credssp_encrypt_public_key_echo(credssp);
				if (ss != SEC_E_OK) {
					return 0;
				}
			//}

			if (status == SEC_I_COMPLETE_NEEDED)
				status = SEC_E_OK;
			else if (status == SEC_I_COMPLETE_AND_CONTINUE)
				status = SEC_I_CONTINUE_NEEDED;
		}

		/* send authentication token to server */

		switch (status) {
			case SEC_E_NO_AUTHENTICATING_AUTHORITY:
				LOGMSG("SEC_E_NO_AUTHENTICATING_AUTHORITY - No authority could be contacted for authentication.\n");
				break;

			case SEC_E_TARGET_UNKNOWN:
				LOGMSG("SEC_E_TARGET_UNKNOWN - The specified target is unknown or unreachable.\n");
				break;

			case SEC_E_UNSUPPORTED_FUNCTION:
				LOGMSG("SEC_E_UNSUPPORTED_FUNCTION - The function requested is not supported.\n");
				break;

			case SEC_E_WRONG_PRINCIPAL:
				LOGMSG("SEC_E_WRONG_PRINCIPAL - The target principal name is incorrect.\n");
				break;

			default:
				//if (output_buffer.cbBuffer > 0)
				{
					credssp->negoToken.pvBuffer = output_buffer.pvBuffer;
					credssp->negoToken.cbBuffer = output_buffer.cbBuffer;

	#ifdef WITH_DEBUG_CREDSSP
					LOGMSG("Sending Authentication Token\n");
					LOGMSG("%s: negotoken\n", __FUNCTION__);
					winpr_HexDump((PBYTE)credssp->negoToken.pvBuffer, credssp->negoToken.cbBuffer);
					LOGMSG("%s: pubkeyauth\n", __FUNCTION__);
					winpr_HexDump((PBYTE)credssp->pubKeyAuth.pvBuffer, credssp->pubKeyAuth.cbBuffer);
	#endif

					credssp_send(credssp);
					credssp_buffer_free(credssp);
				}
				break;
		}

		if (status != SEC_I_CONTINUE_NEEDED)
			break;

		/* receive server response and place in input buffer */

		input_buffer_desc.ulVersion = SECBUFFER_VERSION;
		input_buffer_desc.cBuffers = 1;
		input_buffer_desc.pBuffers = &input_buffer;
		input_buffer.BufferType = SECBUFFER_TOKEN;

		if (credssp_recv(credssp) < 0)
			return -1;

#ifdef WITH_DEBUG_CREDSSP
		LOGMSG("Receiving Authentication Token (%d)\n", (int) credssp->negoToken.cbBuffer);
		winpr_HexDump((PBYTE)credssp->negoToken.pvBuffer, credssp->negoToken.cbBuffer);
#endif

		input_buffer.pvBuffer = credssp->negoToken.pvBuffer;
		input_buffer.cbBuffer = credssp->negoToken.cbBuffer;

		have_input_buffer = TRUE;
		have_context = TRUE;
	}

	/* Encrypted Public Key +1 */
	if (credssp_recv(credssp) < 0)
		return -1;

	/* Verify Server Public Key Echo */

	status = credssp_decrypt_public_key_echo(credssp);
	//status = credssp_decrypt_public_key_echo_nego(credssp);
	credssp_buffer_free(credssp);

	if (status != SEC_E_OK)
	{
		LOGMSG("Could not verify public key echo!\n");
		return -1;
	}

	/* Send encrypted credentials */

	switch (credssp->CredentialType) {
		case 1:
		//case 2:
			status = credssp_encrypt_ts_credentials(credssp);
			break;

		case 2:
			//status = credssp_encrypt_ts_credentials_nego(credssp);
#if 1
			status = credssp_encrypt_ts_credentials(credssp);
#else
			status = SEC_E_OK;
#endif
			break;

		default:
			DebugBreak();
			break;
	}

	if (status != SEC_E_OK)
	{
		LOGMSG("credssp_encrypt_ts_credentials status: 0x%08X\n", status);
		LogSSPIError(status);
		return 0;
	}

	credssp_send(credssp);
	credssp_buffer_free(credssp);

	/* Free resources */

	credssp->table->FreeCredentialsHandle(&credentials);
	credssp->table->FreeContextBuffer(pPackageInfo);

	return 1;
}

/**
 * Authenticate with client using CredSSP (server).
 * @param credssp
 * @return 1 if authentication is successful
 */

int credssp_server_authenticate(rdpCredssp* credssp)
{
	UINT32 cbMaxToken;
	ULONG fContextReq;
	ULONG pfContextAttr;
	SECURITY_STATUS status;
	CredHandle credentials;
	TimeStamp expiration;
	PSecPkgInfo pPackageInfo;
	SecBuffer input_buffer;
	SecBuffer output_buffer;
	SecBufferDesc input_buffer_desc;
	SecBufferDesc output_buffer_desc;
	BOOL have_context;
	BOOL have_input_buffer;
	BOOL have_pub_key_auth;

	sspi_GlobalInit();

	if (credssp_ntlm_server_init(credssp) == 0)
		return 0;

#ifdef WITH_NATIVE_SSPI
	if (!credssp->SspiModule)
		credssp->SspiModule = _tcsdup(_T("secur32.dll"));
#endif

	if (credssp->SspiModule)
	{
		HMODULE hSSPI;
		INIT_SECURITY_INTERFACE pInitSecurityInterface;

		hSSPI = LoadLibrary(credssp->SspiModule);

		if (!hSSPI)
		{
			_tprintf(_T("Failed to load SSPI module: %s\n"), credssp->SspiModule);
			return 0;
		}

#ifdef UNICODE
		pInitSecurityInterface = (INIT_SECURITY_INTERFACE) GetProcAddress(hSSPI, "InitSecurityInterfaceW");
#else
		pInitSecurityInterface = (INIT_SECURITY_INTERFACE) GetProcAddress(hSSPI, "InitSecurityInterfaceA");
#endif

		credssp->table = (*pInitSecurityInterface)();
	}
#ifndef WITH_NATIVE_SSPI
	else
	{
		credssp->table = InitSecurityInterface();
	}
#endif

	status = credssp->table->QuerySecurityPackageInfo(NLA_PKG_NAME, &pPackageInfo);

	if (status != SEC_E_OK)
	{
		LOGMSG("QuerySecurityPackageInfo status: 0x%08X\n", status);
		return 0;
	}

	cbMaxToken = pPackageInfo->cbMaxToken;

	status = credssp->table->AcquireCredentialsHandle(NULL, NLA_PKG_NAME,
			SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &credentials, &expiration);

	if (status != SEC_E_OK)
	{
		LOGMSG("AcquireCredentialsHandle status: 0x%08X\n", status);
		return 0;
	}

	have_context = FALSE;
	have_input_buffer = FALSE;
	have_pub_key_auth = FALSE;
	ZeroMemory(&input_buffer, sizeof(SecBuffer));
	ZeroMemory(&output_buffer, sizeof(SecBuffer));
	ZeroMemory(&input_buffer_desc, sizeof(SecBufferDesc));
	ZeroMemory(&output_buffer_desc, sizeof(SecBufferDesc));
	ZeroMemory(&credssp->ContextSizes, sizeof(SecPkgContext_Sizes));

	/*
	 * from tspkg.dll: 0x00000112
	 * ASC_REQ_MUTUAL_AUTH
	 * ASC_REQ_CONFIDENTIALITY
	 * ASC_REQ_ALLOCATE_MEMORY
	 */

	fContextReq = 0;
	fContextReq |= ASC_REQ_MUTUAL_AUTH;
	fContextReq |= ASC_REQ_CONFIDENTIALITY;

	fContextReq |= ASC_REQ_CONNECTION;
	fContextReq |= ASC_REQ_USE_SESSION_KEY;

	fContextReq |= ASC_REQ_REPLAY_DETECT;
	fContextReq |= ASC_REQ_SEQUENCE_DETECT;

	fContextReq |= ASC_REQ_EXTENDED_ERROR;

	while (TRUE)
	{
		input_buffer_desc.ulVersion = SECBUFFER_VERSION;
		input_buffer_desc.cBuffers = 1;
		input_buffer_desc.pBuffers = &input_buffer;
		input_buffer.BufferType = SECBUFFER_TOKEN;

		/* receive authentication token */

		input_buffer_desc.ulVersion = SECBUFFER_VERSION;
		input_buffer_desc.cBuffers = 1;
		input_buffer_desc.pBuffers = &input_buffer;
		input_buffer.BufferType = SECBUFFER_TOKEN;

		if (credssp_recv(credssp) < 0)
			return -1;

#ifdef WITH_DEBUG_CREDSSP
		LOGMSG("Receiving Authentication Token\n");
		credssp_buffer_print(credssp);
#endif

		input_buffer.pvBuffer = credssp->negoToken.pvBuffer;
		input_buffer.cbBuffer = credssp->negoToken.cbBuffer;

		if (credssp->negoToken.cbBuffer < 1)
		{
			LOGMSG("CredSSP: invalid negoToken!\n");
			return -1;
		}

		output_buffer_desc.ulVersion = SECBUFFER_VERSION;
		output_buffer_desc.cBuffers = 1;
		output_buffer_desc.pBuffers = &output_buffer;
		output_buffer.BufferType = SECBUFFER_TOKEN;
		output_buffer.cbBuffer = cbMaxToken;
		output_buffer.pvBuffer = malloc(output_buffer.cbBuffer);

		status = credssp->table->AcceptSecurityContext(&credentials,
			have_context? &credssp->context: NULL,
			&input_buffer_desc, fContextReq, SECURITY_NATIVE_DREP, &credssp->context,
			&output_buffer_desc, &pfContextAttr, &expiration);

		credssp->negoToken.pvBuffer = output_buffer.pvBuffer;
		credssp->negoToken.cbBuffer = output_buffer.cbBuffer;

		if ((status == SEC_I_COMPLETE_AND_CONTINUE) || (status == SEC_I_COMPLETE_NEEDED))
		{
			if (credssp->table->CompleteAuthToken != NULL)
				credssp->table->CompleteAuthToken(&credssp->context, &output_buffer_desc);

			if (status == SEC_I_COMPLETE_NEEDED)
				status = SEC_E_OK;
			else if (status == SEC_I_COMPLETE_AND_CONTINUE)
				status = SEC_I_CONTINUE_NEEDED;
		}

		if (status == SEC_E_OK)
		{
			have_pub_key_auth = TRUE;

			if (credssp->table->QueryContextAttributes(&credssp->context, SECPKG_ATTR_SIZES, &credssp->ContextSizes) != SEC_E_OK)
			{
				LOGMSG("QueryContextAttributes SECPKG_ATTR_SIZES failure\n");
				return 0;
			}

			LOGMSG("%s: Decrypting PublicKey from server.\n", __FUNCTION__);
			if (credssp_decrypt_public_key_echo(credssp) != SEC_E_OK)
			{
				LOGMSG("Error: could not verify client's public key echo\n");
				return -1;
			}

			sspi_SecBufferFree(&credssp->negoToken);
			credssp->negoToken.pvBuffer = NULL;
			credssp->negoToken.cbBuffer = 0;

			LOGMSG("%s: Encrypting PublicKey from server.\n", __FUNCTION__);
			credssp_encrypt_public_key_echo(credssp);
		}

		if ((status != SEC_E_OK) && (status != SEC_I_CONTINUE_NEEDED))
		{
			LOGMSG("AcceptSecurityContext status: 0x%08X\n", status);
			return -1;
		}

		/* send authentication token */

#ifdef WITH_DEBUG_CREDSSP
		LOGMSG("Sending Authentication Token\n");
		credssp_buffer_print(credssp);
#endif

		credssp_send(credssp);
		credssp_buffer_free(credssp);

		if (status != SEC_I_CONTINUE_NEEDED)
			break;

		have_context = TRUE;
	}

	/* Receive encrypted credentials */

	if (credssp_recv(credssp) < 0)
		return -1;

	if (credssp_decrypt_ts_credentials(credssp) != SEC_E_OK)
	{
		LOGMSG("Could not decrypt TSCredentials status: 0x%08X\n", status);
		return 0;
	}

	if (status != SEC_E_OK)
	{
		LOGMSG("AcceptSecurityContext status: 0x%08X\n", status);
		return 0;
	}

	status = credssp->table->ImpersonateSecurityContext(&credssp->context);

	if (status != SEC_E_OK)
	{
		LOGMSG("ImpersonateSecurityContext status: 0x%08X\n", status);
		return 0;
	}
	else
	{
		status = credssp->table->RevertSecurityContext(&credssp->context);

		if (status != SEC_E_OK)
		{
			LOGMSG("RevertSecurityContext status: 0x%08X\n", status);
			return 0;
		}
	}

	credssp->table->FreeContextBuffer(pPackageInfo);

	return 1;
}

/**
 * Authenticate using CredSSP.
 * @param credssp
 * @return 1 if authentication is successful
 */

int credssp_authenticate(rdpCredssp* credssp)
{
	if (credssp->server)
		return credssp_server_authenticate(credssp);
	else
		return credssp_client_authenticate(credssp);
}

void ap_integer_increment_le(BYTE* number, int size)
{
	int index;

	for (index = 0; index < size; index++)
	{
		if (number[index] < 0xFF)
		{
			number[index]++;
			break;
		}
		else
		{
			number[index] = 0;
			continue;
		}
	}
}

void ap_integer_decrement_le(BYTE* number, int size)
{
	int index;

	for (index = 0; index < size; index++)
	{
		if (number[index] > 0)
		{
			number[index]--;
			break;
		}
		else
		{
			number[index] = 0xFF;
			continue;
		}
	}
}

SECURITY_STATUS credssp_encrypt_public_key_echo_nego(rdpCredssp* credssp)
{
	SecBuffer Buffers[4];
	SecBufferDesc Message;
	SECURITY_STATUS status;
	int public_key_length;
	SecPkgContext_StreamSizes ss;

	status = credssp->table->QueryContextAttributesW(&credssp->context, SECPKG_ATTR_STREAM_SIZES, &ss);

	public_key_length = credssp->PublicKey.cbBuffer;


	//sspi_SecBufferAlloc(&credssp->pubKeyAuth, credssp->ContextSizes.cbSecurityTrailer + credssp->ContextSizes.cbBlockSize + public_key_length);
	//sspi_SecBufferAlloc(&credssp->pubKeyAuth, credssp->ContextSizes.cbSecurityTrailer + public_key_length + sizeof(DWORD));
	//sspi_SecBufferAlloc(&credssp->pubKeyAuth, public_key_length + sizeof(DWORD));
	sspi_SecBufferAlloc(&credssp->pubKeyAuth, public_key_length);
#if 1
	Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
	Buffers[0].cbBuffer = 0; //credssp->ContextSizes.cbMaxToken;
	Buffers[0].pvBuffer = 0; //credssp->pubKeyAuth.pvBuffer;

	//Buffers[1].cbBuffer = credssp->ContextSizes.cbSecurityTrailer;
	//Buffers[1].pvBuffer = (BYTE*)Buffers[0].pvBuffer + Buffers[0].cbBuffer;

	Buffers[1].BufferType = SECBUFFER_DATA; /* TLS Public Key */
	Buffers[1].cbBuffer = credssp->pubKeyAuth.cbBuffer;
	Buffers[1].pvBuffer = (BYTE*)credssp->pubKeyAuth.pvBuffer; // + credssp->ContextSizes.cbMaxToken;
	CopyMemory(Buffers[1].pvBuffer, credssp->PublicKey.pvBuffer, credssp->PublicKey.cbBuffer);

	Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
	Buffers[2].cbBuffer = 0; //credssp->ContextSizes.cbBlockSize;
	Buffers[2].pvBuffer = 0; //malloc(credssp->ContextSizes.cbBlockSize); //(BYTE*)Buffers[1].pvBuffer + Buffers[1].cbBuffer;
	//ZeroMemory(Buffers[3].pvBuffer, Buffers[3].cbBuffer);

	Buffers[3].BufferType = SECBUFFER_EMPTY;
	Buffers[3].cbBuffer = 0;
	Buffers[3].pvBuffer = 0;
#else
	Buffers[0].BufferType = SECBUFFER_DATA; /* TLS Public Key */
	Buffers[0].cbBuffer = credssp->pubKeyAuth.cbBuffer;
	Buffers[0].pvBuffer = (BYTE*)credssp->pubKeyAuth.pvBuffer; // + credssp->ContextSizes.cbMaxToken;
	CopyMemory(Buffers[0].pvBuffer, credssp->PublicKey.pvBuffer, credssp->PublicKey.cbBuffer);

	Buffers[1].BufferType = SECBUFFER_STREAM_TRAILER;
	Buffers[1].cbBuffer = 0; //credssp->ContextSizes.cbBlockSize;
	Buffers[1].pvBuffer = 0; //malloc(credssp->ContextSizes.cbBlockSize); //(BYTE*)Buffers[1].pvBuffer + Buffers[1].cbBuffer;
	//ZeroMemory(Buffers[3].pvBuffer, Buffers[3].cbBuffer);

	Buffers[2].BufferType = SECBUFFER_EMPTY;
	Buffers[2].cbBuffer = 0;
	Buffers[2].pvBuffer = 0;
#endif

	if (credssp->server)
	{
		/* server echos the public key +1 */
		ap_integer_increment_le((BYTE*) Buffers[1].pvBuffer, Buffers[1].cbBuffer);
	}

	Message.cBuffers = 4;
	Message.ulVersion = SECBUFFER_VERSION;
	Message.pBuffers = (PSecBuffer) &Buffers;

	status = credssp->table->EncryptMessage(&credssp->context, /*SECQOP_WRAP_NO_ENCRYPT*/0, &Message, credssp->send_seq_num++);

	if (status != SEC_E_OK)
	{
		LOGMSG("EncryptMessage status: 0x%08X\n", status);
		LogSSPIError(status);
		return status;
	}

	return status;
} 

SECURITY_STATUS credssp_encrypt_public_key_echo(rdpCredssp* credssp)
{
	SecBuffer Buffers[2];
	SecBufferDesc Message;
	SECURITY_STATUS status;
	int public_key_length;
	PVOID pTemp = NULL;

	public_key_length = credssp->PublicKey.cbBuffer;

	Buffers[0].BufferType = SECBUFFER_TOKEN; /* Signature */
	Buffers[1].BufferType = SECBUFFER_DATA; /* TLS Public Key */
	//Buffers[2].BufferType = SECBUFFER_PADDING;

	//sspi_SecBufferAlloc(&credssp->pubKeyAuth, credssp->ContextSizes.cbSecurityTrailer + credssp->ContextSizes.cbMaxSignature + credssp->ContextSizes.cbBlockSize + public_key_length + 1024);
	//sspi_SecBufferAlloc(&credssp->pubKeyAuth, credssp->ContextSizes.cbSecurityTrailer + credssp->ContextSizes.cbBlockSize + public_key_length);
	//sspi_SecBufferAlloc(&credssp->pubKeyAuth, credssp->ContextSizes.cbMaxToken + public_key_length);
	//TODO (nik) Fix use of hardcoded token length
	//sspi_SecBufferAlloc(&credssp->pubKeyAuth, 0x3c + public_key_length);

	pTemp = malloc(credssp->ContextSizes.cbMaxToken + public_key_length);

	//Buffers[0].cbBuffer = 0x3c; //credssp->ContextSizes.cbMaxToken;
	Buffers[0].cbBuffer = credssp->ContextSizes.cbMaxToken;
	Buffers[0].pvBuffer = pTemp; //credssp->pubKeyAuth.pvBuffer;

	Buffers[1].cbBuffer = public_key_length;
	Buffers[1].pvBuffer = (BYTE*) pTemp /*credssp->pubKeyAuth.pvBuffer*/ + Buffers[0].cbBuffer;
	CopyMemory(Buffers[1].pvBuffer, credssp->PublicKey.pvBuffer, Buffers[1].cbBuffer);

	//Buffers[2].cbBuffer = credssp->ContextSizes.cbBlockSize;
	//Buffers[2].pvBuffer = (BYTE*)credssp->pubKeyAuth.pvBuffer + (Buffers[0].cbBuffer + Buffers[1].cbBuffer);

	if (credssp->server)
	{
		/* server echos the public key +1 */
		ap_integer_increment_le((BYTE*) Buffers[1].pvBuffer, Buffers[1].cbBuffer);
	}

	Message.cBuffers = 2;
	Message.ulVersion = SECBUFFER_VERSION;
	Message.pBuffers = (PSecBuffer) &Buffers;

	status = credssp->table->EncryptMessage(&credssp->context, /*SECQOP_WRAP_NO_ENCRYPT*/0, &Message, credssp->send_seq_num++);

	if (status != SEC_E_OK)
	{
		free(pTemp);
		LOGMSG("EncryptMessage status: 0x%08X\n", status);
		LogSSPIError(status);
		return status;
	}

	sspi_SecBufferAlloc(&credssp->pubKeyAuth, Buffers[0].cbBuffer + Buffers[1].cbBuffer);
	RtlCopyMemory(credssp->pubKeyAuth.pvBuffer, Buffers[0].pvBuffer, Buffers[0].cbBuffer);
	RtlCopyMemory((BYTE*)credssp->pubKeyAuth.pvBuffer + Buffers[0].cbBuffer, Buffers[1].pvBuffer, Buffers[1].cbBuffer);

	return status;
}

SECURITY_STATUS credssp_decrypt_public_key_echo(rdpCredssp* credssp)
{
	int length;
	BYTE* buffer;
	ULONG pfQOP = 0;
	BYTE* public_key1;
	BYTE* public_key2;
	int public_key_length;
	SecBuffer Buffers[2];
	SecBufferDesc Message;
	SECURITY_STATUS status;

	//if (credssp->PublicKey.cbBuffer + credssp->ContextSizes.cbMaxSignature != credssp->pubKeyAuth.cbBuffer)
	if (credssp->PublicKey.cbBuffer + 0x3c != credssp->pubKeyAuth.cbBuffer)
	{
		LOGMSG("unexpected pubKeyAuth buffer size:%d\n", (int) credssp->pubKeyAuth.cbBuffer);
		//return SEC_E_INVALID_TOKEN;
	}

	length = credssp->pubKeyAuth.cbBuffer;
	buffer = (BYTE*) malloc(length);
	CopyMemory(buffer, credssp->pubKeyAuth.pvBuffer, length);

	public_key_length = credssp->PublicKey.cbBuffer;

	Buffers[0].BufferType = SECBUFFER_TOKEN; /* Signature */
	Buffers[1].BufferType = SECBUFFER_DATA; /* Encrypted TLS Public Key */

	Buffers[0].cbBuffer = 0x3c; //credssp->ContextSizes.cbMaxSignature;
	Buffers[0].pvBuffer = buffer;

	Buffers[1].cbBuffer = length - 0x3c; //credssp->ContextSizes.cbMaxSignature;
	Buffers[1].pvBuffer = buffer + 0x3c; //credssp->ContextSizes.cbMaxSignature;

	Message.cBuffers = 2;
	Message.ulVersion = SECBUFFER_VERSION;
	Message.pBuffers = (PSecBuffer) &Buffers;

	status = credssp->table->DecryptMessage(&credssp->context, &Message, credssp->recv_seq_num++, &pfQOP);

	if (status != SEC_E_OK)
	{
		LOGMSG("DecryptMessage failure: 0x%08X\n", status);
		LogSSPIError(status);
		return status;
	}

	public_key1 = (BYTE*) credssp->PublicKey.pvBuffer;
	public_key2 = (BYTE*) Buffers[1].pvBuffer;

	if (!credssp->server)
	{
		/* server echos the public key +1 */
		ap_integer_decrement_le(public_key2, public_key_length);
	}

	if (memcmp(public_key1, public_key2, public_key_length) != 0)
	{
		LOGMSG("Could not verify server's public key echo\n");

		LOGMSG("Expected (length = %d):\n", public_key_length);
		winpr_HexDump(public_key1, public_key_length);

		LOGMSG("Actual (length = %d):\n", public_key_length);
		winpr_HexDump(public_key2, public_key_length);

		return SEC_E_MESSAGE_ALTERED; /* DO NOT SEND CREDENTIALS! */
	}

	free(buffer);

	return SEC_E_OK;
}




#if !defined(AT_KEYEXCHANGE)
#define AT_KEYEXCHANGE 1
#endif
#if !defined(AT_SIGNATURE)
#define AT_SIGNATURE 2
#endif
int credssp_sizeof_ts_cspdata_detail(rdpCredssp* credssp)
{
	int length = 0;
/*
	TSCspDataDetail ::= SEQUENCE {
        keySpec       [0] INTEGER,
        cardName      [1] OCTET STRING OPTIONAL,
        readerName    [2] OCTET STRING OPTIONAL,
        containerName [3] OCTET STRING OPTIONAL,
        cspName       [4] OCTET STRING OPTIONAL
	}
*/
  /*keySpec       [0] INTEGER,*/
	length += ber_sizeof_sequence_integer(1);

#if 0
	/*cardName      [1] OCTET STRING OPTIONAL,*/
	if (gSCCspData.pszCardName) {
		length += ber_sizeof_sequence_octet_string(gSCCspData.cbCardName);
	}
#endif

	/*readerName    [2] OCTET STRING OPTIONAL,*/
	if (gSCCspData.pszReaderName) {
		length += ber_sizeof_sequence_octet_string(gSCCspData.cbReaderName);
	}

  /*containerName [3] OCTET STRING OPTIONAL,*/
	if (gSCCspData.pszContainerName) {
		length += ber_sizeof_sequence_octet_string(gSCCspData.cbContainerName);
	}

	/*cspName       [4] OCTET STRING OPTIONAL*/
	if (gSCCspData.pszCspName) {
		length += ber_sizeof_sequence_octet_string(gSCCspData.cbCspName);
	}

	LOGMSG("%s: size of TSCspDataDetail: %d (%#x)\n", __FUNCTION__, length, length);

	return length;
}

int credssp_sizeof_ts_smartcard_creds(rdpCredssp* credssp)
{
	int length = 0;
	int cspdata_size = credssp_sizeof_ts_cspdata_detail(credssp);

	LOGMSG("%s: size of TSCspDataDetail: %d (%#x)\n", __FUNCTION__, cspdata_size, cspdata_size);
	length += ber_sizeof_sequence_octet_string(credssp->identity.PasswordLength * 2);
	length += ber_sizeof_sequence_octet_string(cspdata_size);
#if 0
	if (CredIsMarshaledCredential((LPCWSTR)credssp->identity.User)) {
		CRED_MARSHAL_TYPE cmType;
		void* cmData;
		PCERT_CREDENTIAL_INFO ci;
		CredUnmarshalCredential((LPCWSTR)credssp->identity.User, &cmType, &cmData);

		ci = (PCERT_CREDENTIAL_INFO)cmData;
		length += ber_sizeof_sequence_octet_string(ci->cbSize);
	}
#else
#if 0
	length += ber_sizeof_sequence_octet_string(credssp->identity.UserLength * 2);
#endif
#endif

	LOGMSG("%s: size of TSSmartCardCreds: %d (%#x)\n", __FUNCTION__, length, length);

	return length;
}

int credssp_sizeof_ts_password_creds(rdpCredssp* credssp)
{
	int length = 0;

	length += ber_sizeof_sequence_octet_string(credssp->identity.DomainLength * 2);
	length += ber_sizeof_sequence_octet_string(credssp->identity.UserLength * 2);
	length += ber_sizeof_sequence_octet_string(credssp->identity.PasswordLength * 2);

	return length;
}

void credssp_read_ts_password_creds(rdpCredssp* credssp, wStream* s)
{
	int length;

	/* TSPasswordCreds (SEQUENCE) */
	ber_read_sequence_tag(s, &length);

	/* [0] domainName (OCTET STRING) */
	ber_read_contextual_tag(s, 0, &length, TRUE);
	ber_read_octet_string_tag(s, &length);
	credssp->identity.DomainLength = (UINT32) length;
	credssp->identity.Domain = (UINT16*) malloc(length);
	CopyMemory(credssp->identity.Domain, Stream_Pointer(s), credssp->identity.DomainLength);
	Stream_Seek(s, credssp->identity.DomainLength);
	credssp->identity.DomainLength /= 2;

	/* [1] userName (OCTET STRING) */
	ber_read_contextual_tag(s, 1, &length, TRUE);
	ber_read_octet_string_tag(s, &length);
	credssp->identity.UserLength = (UINT32) length;
	credssp->identity.User = (UINT16*) malloc(length);
	CopyMemory(credssp->identity.User, Stream_Pointer(s), credssp->identity.UserLength);
	Stream_Seek(s, credssp->identity.UserLength);
	credssp->identity.UserLength /= 2;

	/* [2] password (OCTET STRING) */
	ber_read_contextual_tag(s, 2, &length, TRUE);
	ber_read_octet_string_tag(s, &length);
	credssp->identity.PasswordLength = (UINT32) length;
	credssp->identity.Password = (UINT16*) malloc(length);
	CopyMemory(credssp->identity.Password, Stream_Pointer(s), credssp->identity.PasswordLength);
	Stream_Seek(s, credssp->identity.PasswordLength);
	credssp->identity.PasswordLength /= 2;

	credssp->identity.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
}

int credssp_write_ts_password_creds(rdpCredssp* credssp, wStream* s)
{
	int size = 0;
	int innerSize = credssp_sizeof_ts_password_creds(credssp);

	/* TSPasswordCreds (SEQUENCE) */

	size += ber_write_sequence_tag(s, innerSize);

	/* [0] domainName (OCTET STRING) */
	size += ber_write_sequence_octet_string(s, 0, (BYTE*) credssp->identity.Domain, credssp->identity.DomainLength * 2);

	/* [1] userName (OCTET STRING) */
	size += ber_write_sequence_octet_string(s, 1, (BYTE*) credssp->identity.User, credssp->identity.UserLength * 2);

	/* [2] password (OCTET STRING) */
	size += ber_write_sequence_octet_string(s, 2, (BYTE*) credssp->identity.Password, credssp->identity.PasswordLength * 2);

	return size;
}

int credssp_write_ts_cspdata_detail(rdpCredssp* credssp, wStream* s)
{
	int size = 0;
	int innerSize = credssp_sizeof_ts_cspdata_detail(credssp);
	void *n = s->pointer;

	size += ber_write_sequence_tag(s, innerSize);
/*
	TSCspDataDetail ::= SEQUENCE {
        keySpec       [0] INTEGER,
        cardName      [1] OCTET STRING OPTIONAL,
        readerName    [2] OCTET STRING OPTIONAL,
        containerName [3] OCTET STRING OPTIONAL,
        cspName       [4] OCTET STRING OPTIONAL
	}
*/
	/* keySpec       [0] INTEGER */
	size += ber_write_sequence_integer(s, 0, AT_KEYEXCHANGE);

#if 0
	if (gSCCspData.pszCardName) {
		size += ber_write_sequence_octet_string(s, 1, (BYTE*)gSCCspData.pszCardName, gSCCspData.cbCardName);
	}
#endif

	if (gSCCspData.pszReaderName) {
		size += ber_write_sequence_octet_string(s, 2, (BYTE*)gSCCspData.pszReaderName, gSCCspData.cbReaderName);
	}

	if (gSCCspData.pszContainerName) {
		size += ber_write_sequence_octet_string(s, 3, (BYTE*)gSCCspData.pszContainerName, gSCCspData.cbContainerName);
	}

	if (gSCCspData.pszCspName) {
		size += ber_write_sequence_octet_string(s, 4, (BYTE*)gSCCspData.pszCspName, gSCCspData.cbCspName);
	}

	SaveBufferToFile("tscspdetail.ber", (PBYTE)n, size);

	return size;
}

int credssp_write_ts_smartcard_creds(rdpCredssp* credssp, wStream* s)
{
	int size = 0;

	int innerSize = credssp_sizeof_ts_smartcard_creds(credssp);
	int cspdataSize = credssp_sizeof_ts_cspdata_detail(credssp);

	void *n = s->pointer;

	size += ber_write_sequence_tag(s, innerSize);
/*
	TSSmartCardCreds ::= SEQUENCE {
        pin         [0] OCTET STRING,
        cspData     [1] TSCspDataDetail,
        userHint    [2] OCTET STRING OPTIONAL,
        domainHint  [3] OCTET STRING OPTIONAL
	}
*/
	/* pin         [0] OCTET STRING */
	size += ber_write_sequence_octet_string(s, 0, (BYTE*)credssp->identity.Password, credssp->identity.PasswordLength * 2);

	/* cspData     [1] TSCspDataDetail */
	//size += ber_write_sequence_header(s, 1, cspdataSize);
	size += ber_write_contextual_tag(s, 1, ber_sizeof_octet_string(cspdataSize), TRUE);
	//size += ber_write_contextual_tag(s, 1, ber_sizeof_sequence_octet_string(cspdataSize), TRUE);
	//size += ber_write_octet_string_tag(s, ber_sizeof_sequence(cspdataSize));
	size += credssp_write_ts_cspdata_detail(credssp, s);

#if 0
	if (CredIsMarshaledCredential((LPCWSTR)credssp->identity.User)) {
		CRED_MARSHAL_TYPE cmType;
		void* cmData;
		PCERT_CREDENTIAL_INFO ci;
		CredUnmarshalCredential((LPCWSTR)credssp->identity.User, &cmType, &cmData);

		ci = (PCERT_CREDENTIAL_INFO)cmData;
		size += ber_write_sequence_octet_string(s, 2, ci->rgbHashOfCert, ci->cbSize);
	}
#else
#if 0
	size += ber_write_sequence_octet_string(s, 2, (BYTE*)credssp->identity.User, credssp->identity.UserLength * 2);
#endif
#endif
	SaveBufferToFile("tssmartcardcreds.ber", (BYTE*)n, size);

	return size;
}

int credssp_sizeof_ts_credentials(rdpCredssp* credssp)
{
	int size = 0;

	size += ber_sizeof_integer(1);
	size += ber_sizeof_contextual_tag(ber_sizeof_integer(1));
	switch (credssp->CredentialType) {
		case 1:
			size += ber_sizeof_sequence_octet_string(ber_sizeof_sequence(credssp_sizeof_ts_password_creds(credssp)));
			break;

		case 2:
#if 1
			size += ber_sizeof_sequence_octet_string(ber_sizeof_sequence(credssp_sizeof_ts_smartcard_creds(credssp)));
#else
			//size += ber_sizeof_sequence_tag(ber_sizeof_contextual_tag(ber_sizeof_integer(1)));
			size += ber_sizeof_sequence(credssp_sizeof_ts_smartcard_creds(credssp));
			/* sequence length */
			size += ber_sizeof_sequence_tag(size);
#endif
			break;

		default:
			DebugBreak();
			break;
	}

	LOGMSG("credssp_sizeof_ts_credentials: size: %d %#x\n", size, size);

	return size;
}

void credssp_read_ts_credentials(rdpCredssp* credssp, PSecBuffer ts_credentials)
{
	wStream* s;
	int length;
	int ts_password_creds_length;

	s = Stream_New(ts_credentials->pvBuffer, ts_credentials->cbBuffer);

	/* TSCredentials (SEQUENCE) */
	ber_read_sequence_tag(s, &length);

	/* [0] credType (INTEGER) */
	ber_read_contextual_tag(s, 0, &length, TRUE);
	ber_read_integer(s, NULL);

	/* [1] credentials (OCTET STRING) */
	ber_read_contextual_tag(s, 1, &length, TRUE);
	ber_read_octet_string_tag(s, &ts_password_creds_length);

	credssp_read_ts_password_creds(credssp, s);

	Stream_Free(s, FALSE);
}

int credssp_write_ts_credentials(rdpCredssp* credssp, wStream* s)
{
	int size = 0;
	int innerSize = credssp_sizeof_ts_credentials(credssp);
	//void *n = s->pointer;

	int credSize;

	/* TSCredentials (SEQUENCE) */
	size += ber_write_sequence_tag(s, innerSize);

	switch (credssp->CredentialType) {
		case 1:
		//case 2:
			/* [0] credType (INTEGER) 1 - TSPasswordCreds  2 - TSSmartCardCreds*/
			size += ber_write_contextual_tag(s, 0, ber_sizeof_integer(1), TRUE);
			size += ber_write_integer(s, 1);

			/* [1] credentials (OCTET STRING) */
			credSize = ber_sizeof_sequence(credssp_sizeof_ts_password_creds(credssp));

			size += ber_write_contextual_tag(s, 1, ber_sizeof_octet_string(credSize), TRUE);
			size += ber_write_octet_string_tag(s, credSize);
			size += credssp_write_ts_password_creds(credssp, s);
			break;

		case 2:
			/* [0] credType (INTEGER) 1 - TSPasswordCreds  2 - TSSmartCardCreds*/
			size += ber_write_contextual_tag(s, 0, ber_sizeof_integer(1), TRUE);
			size += ber_write_integer(s, 2);

			/* [1] credentials (OCTET STRING) TSSmartCardCredentials */
			credSize = credssp_sizeof_ts_smartcard_creds(credssp);
			LOGMSG("%s: size of TSSmartCardCreds: %#x\n", __FUNCTION__, credSize);

			size += ber_write_contextual_tag(s, 1, ber_sizeof_sequence_octet_string(credSize), TRUE);
			size += ber_write_octet_string_tag(s, ber_sizeof_sequence(credSize));
			size += credssp_write_ts_smartcard_creds(credssp, s);
			break;

		default:
			break;
	}

	//SaveBufferToFile("tscredentials.ber", n, size);
	return size;
}

/**
 * Encode TSCredentials structure.
 * @param credssp
 */

void credssp_encode_ts_credentials(rdpCredssp* credssp)
{
	wStream* s;
	int length;

	length = ber_sizeof_sequence(credssp_sizeof_ts_credentials(credssp)) + 4;
	LOGMSG("%s: sizeof: %d\n", __FUNCTION__, length);
	sspi_SecBufferAlloc(&credssp->ts_credentials, length);

	s = Stream_New(credssp->ts_credentials.pvBuffer, length);
	credssp_write_ts_credentials(credssp, s);

	SaveBufferToFile("tscredentials.ber", s->buffer, length);
	Stream_Free(s, FALSE);
	//PrintHexDump(credssp->ts_credentials.cbBuffer, credssp->ts_credentials.pvBuffer);
	//SaveBufferToFile("tscredentials2.ber", credssp->ts_credentials.pvBuffer, credssp->ts_credentials.cbBuffer);
}

SECURITY_STATUS credssp_encrypt_ts_credentials_nego(rdpCredssp* credssp)
{
	//SecPkgContext_PackageInfo pkginfo;
	SecPkgContext_StreamSizes sizes;
	SecPkgContext_NegotiationInfo  SecPkgNegInfo;
	SecBuffer Buffers[4];
	SecBufferDesc Message;
	SECURITY_STATUS status;
	void* pTemp = NULL;
	int buffer_size = 0;
	int cur_offset = 0;

	//credssp->table->QueryContextAttributesW(&credssp->context, SECPKG_ATTR_PACKAGE_INFO, &pkginfo);

	status = credssp->table->QueryContextAttributesW(&credssp->context, SECPKG_ATTR_STREAM_SIZES, &sizes);

	status = credssp->table->QueryContextAttributesW(&credssp->context, SECPKG_ATTR_NEGOTIATION_INFO, &SecPkgNegInfo );

	LOGMSG("%s: CSSP: %S\n", __FUNCTION__, SecPkgNegInfo.PackageInfo->Name);

	credssp_encode_ts_credentials(credssp);

	buffer_size = credssp->ts_credentials.cbBuffer; // + (credssp->ContextSizes.cbSecurityTrailer * 2);

	pTemp = malloc(buffer_size);

	Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
	Buffers[0].cbBuffer = credssp->ContextSizes.cbSecurityTrailer;
	Buffers[0].pvBuffer = 0;//pTemp;

	Buffers[1].BufferType = SECBUFFER_DATA;  /* TSCredentials */
	Buffers[1].cbBuffer = buffer_size;
	Buffers[1].pvBuffer = (BYTE*)pTemp; // + Buffers[0].cbBuffer; //credssp->authInfo.pvBuffer;
	RtlCopyMemory(Buffers[1].pvBuffer, credssp->ts_credentials.pvBuffer, credssp->ts_credentials.cbBuffer);

	Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
	Buffers[2].cbBuffer = credssp->ContextSizes.cbSecurityTrailer;
	Buffers[2].pvBuffer = 0;//(BYTE*)pTemp + Buffers[0].cbBuffer + Buffers[1].cbBuffer;

	Buffers[3].BufferType = SECBUFFER_EMPTY;
	Buffers[3].cbBuffer = 0;
	Buffers[3].pvBuffer = 0;

	SaveBufferToFile("nego_credentials.ber", (BYTE*)credssp->ts_credentials.pvBuffer, credssp->ts_credentials.cbBuffer);
	//SaveBufferToFile("nego_authinfo.raw", (BYTE*)credssp->authInfo.pvBuffer, credssp->authInfo.cbBuffer);

	Message.cBuffers = 4;
	Message.ulVersion = SECBUFFER_VERSION;
	Message.pBuffers = (PSecBuffer) &Buffers;

	status = credssp->table->EncryptMessage(&credssp->context, SECQOP_WRAP_NO_ENCRYPT, &Message, credssp->send_seq_num++);

	if (SUCCEEDED(status)) {
	buffer_size = Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer + Buffers[3].cbBuffer;
	LOGMSG("%s: credssp->authInfo size: %d (%#x)\n", __FUNCTION__, buffer_size, buffer_size);
	sspi_SecBufferAlloc(&credssp->authInfo, buffer_size);

	if (Buffers[0].cbBuffer) {
		RtlCopyMemory(credssp->authInfo.pvBuffer, Buffers[0].pvBuffer, Buffers[0].cbBuffer);
		cur_offset += Buffers[0].cbBuffer;
	}

	if (Buffers[1].cbBuffer) {
		RtlCopyMemory((BYTE*)credssp->authInfo.pvBuffer+cur_offset, Buffers[1].pvBuffer, Buffers[1].cbBuffer);
		cur_offset += Buffers[1].cbBuffer;
	}

	if (Buffers[2].cbBuffer) {
		RtlCopyMemory((BYTE*)credssp->authInfo.pvBuffer+cur_offset, Buffers[2].pvBuffer, Buffers[2].cbBuffer);
		cur_offset += Buffers[2].cbBuffer;
	}

	if (Buffers[3].cbBuffer) {
		RtlCopyMemory((BYTE*)credssp->authInfo.pvBuffer+cur_offset, Buffers[3].pvBuffer, Buffers[3].cbBuffer);
		cur_offset += Buffers[3].cbBuffer;
	}
	}
	free(pTemp);

	SaveBufferToFile("nego_authinfo-encrypted.raw", (BYTE*)credssp->authInfo.pvBuffer, credssp->authInfo.cbBuffer);

	if (status != SEC_E_OK)
		return status;

	return SEC_E_OK;
}

SECURITY_STATUS credssp_encrypt_ts_credentials(rdpCredssp* credssp)
{
	SecBuffer Buffers[2];
	SecBufferDesc Message;
	SECURITY_STATUS status;
	int token_size;
	int buffer_size;
	void* pTemp = NULL;

	credssp_encode_ts_credentials(credssp);

	//TODO (nik) Fix use of hardcoded token size
	//token_size = 0x3c;
	//token_size = credssp->ContextSizes.cbSecurityTrailer;
	//token_size = credssp->ContextSizes.cbMaxSignature; //TOO SMALL
	token_size = credssp->ContextSizes.cbMaxToken;

	LOGMSG("%s: token_size: %d (%#x)\n", __FUNCTION__, token_size, token_size);

	Buffers[0].BufferType = SECBUFFER_TOKEN; /* Signature */
	Buffers[1].BufferType = SECBUFFER_DATA; /* TSCredentials */

	buffer_size = token_size + credssp->ts_credentials.cbBuffer;
	//buffer_size = credssp->ContextSizes.cbMaxToken + credssp->ts_credentials.cbBuffer;
	//sspi_SecBufferAlloc(&credssp->authInfo, credssp->ContextSizes.cbMaxSignature + credssp->ts_credentials.cbBuffer);
	//sspi_SecBufferAlloc(&credssp->authInfo, token_size + credssp->ts_credentials.cbBuffer);
	//sspi_SecBufferAlloc(&credssp->authInfo, buffer_size);
	//RtlZeroMemory(credssp->authInfo.pvBuffer, credssp->authInfo.cbBuffer);
	//LOGMSG("%s: credssp->authInfo size: %d\n", __FUNCTION__, credssp->authInfo.cbBuffer);

	pTemp = malloc(credssp->ContextSizes.cbMaxToken + credssp->ts_credentials.cbBuffer);
	RtlZeroMemory(pTemp, credssp->ContextSizes.cbMaxToken + credssp->ts_credentials.cbBuffer);

	Buffers[0].cbBuffer = token_size;
	Buffers[0].pvBuffer = pTemp;

	Buffers[1].cbBuffer = credssp->ts_credentials.cbBuffer;
#if defined(INCLUDE_MESSAGE_SIZE)
	Buffers[1].pvBuffer = (BYTE*)pTemp + Buffers[1].cbBuffer + sizeof(DWORD64); //malloc(credssp->ts_credentials.cbBuffer); //&((BYTE*) credssp->authInfo.pvBuffer)[Buffers[0].cbBuffer];
	RtlCopyMemory(Buffers[1].pvBuffer, credssp->ts_credentials.pvBuffer + sizeof(DWORD64), Buffers[1].cbBuffer);
#else
	Buffers[1].pvBuffer = (BYTE*)pTemp + Buffers[1].cbBuffer;
	RtlCopyMemory(Buffers[1].pvBuffer, credssp->ts_credentials.pvBuffer, Buffers[1].cbBuffer);
#endif

	SaveBufferToFile("credentials.ber", (PBYTE)credssp->ts_credentials.pvBuffer, credssp->ts_credentials.cbBuffer);
	SaveBufferToFile("credentials2.ber", (PBYTE)Buffers[1].pvBuffer, Buffers[1].cbBuffer);

	Message.cBuffers = 2;
	Message.ulVersion = SECBUFFER_VERSION;
	Message.pBuffers = (PSecBuffer) &Buffers;

	status = credssp->table->EncryptMessage(&credssp->context, /*SECQOP_WRAP_NO_ENCRYPT*/0, &Message, credssp->send_seq_num++);

#if defined(INCLUDE_MESSAGE_SIZE)
	buffer_size = Buffers[0].cbBuffer + Buffers[1].cbBuffer + sizeof(DWORD64);
#else
	buffer_size = Buffers[0].cbBuffer + Buffers[1].cbBuffer;
#endif

	sspi_SecBufferAlloc(&credssp->authInfo, buffer_size);

#if defined(INCLUDE_MESSAGE_SIZE)
	*((DWORD64 *)credssp->authInfo.pvBuffer) = Buffers[0].cbBuffer;
	RtlCopyMemory((BYTE*)credssp->authInfo.pvBuffer+sizeof(DWORD64), Buffers[0].pvBuffer, Buffers[0].cbBuffer);
	RtlCopyMemory((BYTE*)credssp->authInfo.pvBuffer+sizeof(DWORD64)+Buffers[0].cbBuffer, Buffers[1].pvBuffer, Buffers[1].cbBuffer);
#else
	RtlCopyMemory((BYTE*)credssp->authInfo.pvBuffer, Buffers[0].pvBuffer, Buffers[0].cbBuffer);
	RtlCopyMemory((BYTE*)credssp->authInfo.pvBuffer+Buffers[0].cbBuffer, Buffers[1].pvBuffer, Buffers[1].cbBuffer);
#endif
	free(pTemp);

	LOGMSG("%s: Adjusted Token Size: %d (%#x)\n", __FUNCTION__, Buffers[0].cbBuffer, Buffers[0].cbBuffer);

	SaveBufferToFile("authinfo-encrypted.raw", (PBYTE)credssp->authInfo.pvBuffer, credssp->authInfo.cbBuffer);

	if (status != SEC_E_OK)
		return status;

	return SEC_E_OK;
}

SECURITY_STATUS credssp_decrypt_ts_credentials(rdpCredssp* credssp)
{
	int length;
	BYTE* buffer;
	ULONG pfQOP;
	SecBuffer Buffers[2];
	SecBufferDesc Message;
	SECURITY_STATUS status;

	Buffers[0].BufferType = SECBUFFER_TOKEN; /* Signature */
	Buffers[1].BufferType = SECBUFFER_DATA; /* TSCredentials */

	if (credssp->authInfo.cbBuffer < 1)
	{
		LOGMSG("credssp_decrypt_ts_credentials missing authInfo buffer\n");
		return SEC_E_INVALID_TOKEN;
	}

	length = credssp->authInfo.cbBuffer;
	buffer = (BYTE*) malloc(length);
	CopyMemory(buffer, credssp->authInfo.pvBuffer, length);

	Buffers[0].cbBuffer = credssp->ContextSizes.cbMaxSignature;
	Buffers[0].pvBuffer = buffer;

	Buffers[1].cbBuffer = length - credssp->ContextSizes.cbMaxSignature;
	Buffers[1].pvBuffer = &buffer[credssp->ContextSizes.cbMaxSignature];

	Message.cBuffers = 2;
	Message.ulVersion = SECBUFFER_VERSION;
	Message.pBuffers = (PSecBuffer) &Buffers;

	status = credssp->table->DecryptMessage(&credssp->context, &Message, credssp->recv_seq_num++, &pfQOP);

	if (status != SEC_E_OK)
		return status;

	credssp_read_ts_credentials(credssp, &Buffers[1]);

	free(buffer);

	return SEC_E_OK;
}

int credssp_sizeof_nego_token(int length)
{
	length = ber_sizeof_octet_string(length);
	length += ber_sizeof_contextual_tag(length);
	return length;
}

int credssp_sizeof_nego_tokens(int length)
{
	length = credssp_sizeof_nego_token(length);
	length += ber_sizeof_sequence_tag(length);
	length += ber_sizeof_sequence_tag(length);
	length += ber_sizeof_contextual_tag(length);
	return length;
}

int credssp_sizeof_pub_key_auth(int length)
{
	length = ber_sizeof_octet_string(length);
	length += ber_sizeof_contextual_tag(length);
	return length;
}

int credssp_sizeof_auth_info(int length)
{
	length = ber_sizeof_octet_string(length);
	length += ber_sizeof_contextual_tag(length);
	return length;
}

int credssp_sizeof_ts_request(int length)
{
	length += ber_sizeof_integer(2);
	length += ber_sizeof_contextual_tag(3);
	return length;
}

/**
 * Send CredSSP message.
 * @param credssp
 */

void credssp_send(rdpCredssp* credssp)
{
	wStream* s;
	int length;
	int ts_request_length;
	int nego_tokens_length;
	int pub_key_auth_length;
	int auth_info_length;
	void* sstart;

	nego_tokens_length = (credssp->negoToken.cbBuffer > 0) ? credssp_sizeof_nego_tokens(credssp->negoToken.cbBuffer) : 0;
	pub_key_auth_length = (credssp->pubKeyAuth.cbBuffer > 0) ? credssp_sizeof_pub_key_auth(credssp->pubKeyAuth.cbBuffer) : 0;
	auth_info_length = (credssp->authInfo.cbBuffer > 0) ? credssp_sizeof_auth_info(credssp->authInfo.cbBuffer) : 0;

	LOGMSG("%s: nego_tokens_length: %d %#x\n", __FUNCTION__, nego_tokens_length, nego_tokens_length);
	LOGMSG("%s: pub_key_auth_length: %d %#x\n", __FUNCTION__, pub_key_auth_length, pub_key_auth_length);
	LOGMSG("%s: auth_info_length: %d %#x\n", __FUNCTION__, auth_info_length, auth_info_length);

	length = nego_tokens_length + pub_key_auth_length + auth_info_length;

	LOGMSG("%s: length: %d %#x\n", __FUNCTION__, length, length);

	ts_request_length = credssp_sizeof_ts_request(length);

	LOGMSG("%s: ts_request_length: %d %#x\n", __FUNCTION__, ts_request_length, ts_request_length);

	s = Stream_New(NULL, ber_sizeof_sequence(ts_request_length));
	sstart = s->buffer;

	/* TSRequest */
	ber_write_sequence_tag(s, ts_request_length); /* SEQUENCE */

	/* [0] version */
	ber_write_contextual_tag(s, 0, 3, TRUE);
	ber_write_integer(s, 2); /* INTEGER */

	/* [1] negoTokens (NegoData) */
	if (nego_tokens_length > 0)
	{
		length = nego_tokens_length;

		length -= ber_write_contextual_tag(s, 1, ber_sizeof_sequence(ber_sizeof_sequence(ber_sizeof_sequence_octet_string(credssp->negoToken.cbBuffer))), TRUE); /* NegoData */
		length -= ber_write_sequence_tag(s, ber_sizeof_sequence(ber_sizeof_sequence_octet_string(credssp->negoToken.cbBuffer))); /* SEQUENCE OF NegoDataItem */
		length -= ber_write_sequence_tag(s, ber_sizeof_sequence_octet_string(credssp->negoToken.cbBuffer)); /* NegoDataItem */
		length -= ber_write_sequence_octet_string(s, 0, (const BYTE*) credssp->negoToken.pvBuffer, credssp->negoToken.cbBuffer); /* OCTET STRING */

		// assert length == 0
	}

	/* [2] authInfo (OCTET STRING) */
	if (auth_info_length > 0)
	{
		length = auth_info_length;
		length -= ber_write_sequence_octet_string(s, 2, (const BYTE*)credssp->authInfo.pvBuffer, credssp->authInfo.cbBuffer);

		// assert length == 0
	}

	/* [3] pubKeyAuth (OCTET STRING) */
	if (pub_key_auth_length > 0)
	{
		length = pub_key_auth_length;
		length -= ber_write_sequence_octet_string(s, 3, (const BYTE*)credssp->pubKeyAuth.pvBuffer, credssp->pubKeyAuth.cbBuffer);

		// assert length == 0
	}

	Stream_SealLength(s);

	{
		char t[16] = {0};
		sprintf(t, "tsrequest-%d.ber", save_ts_request++);
		LOGMSG("%s: saving tsrequest buffer: %s\n", __FUNCTION__, t);
		SaveBufferToFile(t, (BYTE*)sstart, s->length);
	}

	transport_write(credssp->transport, s);

	Stream_Free(s, TRUE);
}

/**
 * Receive CredSSP message.
 * @param credssp
 * @return
 */

int credssp_recv(rdpCredssp* credssp)
{
	wStream* s;
	int length;
	int status;
	UINT32 version;

	s = Stream_New(NULL, 4096);

	status = transport_read(credssp->transport, s);
	Stream_Length(s) = status;

	if (status < 0)
	{
		LOGMSG("credssp_recv() error: %d\n", status);
		Stream_Free(s, TRUE);
		return -1;
	}

	/* TSRequest */
	if(!ber_read_sequence_tag(s, &length) ||
		!ber_read_contextual_tag(s, 0, &length, TRUE) ||
		!ber_read_integer(s, &version))
	{
		Stream_Free(s, TRUE);
		return -1;
	}

	/* [1] negoTokens (NegoData) */
	if (ber_read_contextual_tag(s, 1, &length, TRUE) != FALSE)
	{
		if (!ber_read_sequence_tag(s, &length) || /* SEQUENCE OF NegoDataItem */
			!ber_read_sequence_tag(s, &length) || /* NegoDataItem */
			!ber_read_contextual_tag(s, 0, &length, TRUE) || /* [0] negoToken */
			!ber_read_octet_string_tag(s, &length) || /* OCTET STRING */
			Stream_GetRemainingLength(s) < length)
		{
			Stream_Free(s, TRUE);
			return -1;
		}
		sspi_SecBufferAlloc(&credssp->negoToken, length);
		Stream_Read(s, credssp->negoToken.pvBuffer, length);
		credssp->negoToken.cbBuffer = length;
	}

	/* [2] authInfo (OCTET STRING) */
	if (ber_read_contextual_tag(s, 2, &length, TRUE) != FALSE)
	{
		if(!ber_read_octet_string_tag(s, &length) || /* OCTET STRING */
			Stream_GetRemainingLength(s) < length)
		{
			Stream_Free(s, TRUE);
			return -1;
		}
		sspi_SecBufferAlloc(&credssp->authInfo, length);
		Stream_Read(s, credssp->authInfo.pvBuffer, length);
		credssp->authInfo.cbBuffer = length;
	}

	/* [3] pubKeyAuth (OCTET STRING) */
	if (ber_read_contextual_tag(s, 3, &length, TRUE) != FALSE)
	{
		if(!ber_read_octet_string_tag(s, &length) || /* OCTET STRING */
			Stream_GetRemainingLength(s) < length)
		{
			Stream_Free(s, TRUE);
			return -1;
		}
		sspi_SecBufferAlloc(&credssp->pubKeyAuth, length);
		Stream_Read(s, credssp->pubKeyAuth.pvBuffer, length);
		credssp->pubKeyAuth.cbBuffer = length;
	}

	Stream_Free(s, TRUE);

	return 0;
}

void credssp_buffer_print(rdpCredssp* credssp)
{
	if (credssp->negoToken.cbBuffer > 0)
	{
		LOGMSG("CredSSP.negoToken (length = %d):\n", (int) credssp->negoToken.cbBuffer);
		winpr_HexDump(credssp->negoToken.pvBuffer, credssp->negoToken.cbBuffer);
	}

	if (credssp->pubKeyAuth.cbBuffer > 0)
	{
		LOGMSG("CredSSP.pubKeyAuth (length = %d):\n", (int) credssp->pubKeyAuth.cbBuffer);
		winpr_HexDump(credssp->pubKeyAuth.pvBuffer, credssp->pubKeyAuth.cbBuffer);
	}

	if (credssp->authInfo.cbBuffer > 0)
	{
		LOGMSG("CredSSP.authInfo (length = %d):\n", (int) credssp->authInfo.cbBuffer);
		winpr_HexDump(credssp->authInfo.pvBuffer, credssp->authInfo.cbBuffer);
	}
}

void credssp_buffer_free(rdpCredssp* credssp)
{
	sspi_SecBufferFree(&credssp->negoToken);
	sspi_SecBufferFree(&credssp->pubKeyAuth);
	sspi_SecBufferFree(&credssp->authInfo);
}

/**
 * Create new CredSSP state machine.
 * @param transport
 * @return new CredSSP state machine.
 */

rdpCredssp* credssp_new(freerdp* instance, rdpTransport* transport, rdpSettings* settings)
{
	rdpCredssp* credssp;
	credssp = (rdpCredssp*) malloc(sizeof(rdpCredssp));
	ZeroMemory(credssp, sizeof(rdpCredssp));

	if (credssp != NULL)
	{
		HKEY hKey;
		LONG status;
		DWORD dwType;
		DWORD dwSize;

		credssp->instance = instance;
		credssp->settings = settings;
		credssp->server = settings->ServerMode;
		credssp->transport = transport;
		credssp->CredentialType = settings->CredentialsType;

		switch (settings->CredentialsType) {
			case 1:
				credssp->providerName = _wcsdup(L"NTLM");
				credssp->CredentialType = 1;
				break;

			case 2:

#if defined(USE_NEGOTIATE)
				credssp->providerName = _wcsdup(L"Negotiate");
#elif defined(USE_KERBEROS)
				credssp->providerName = _wcsdup(L"Kerberos");
#else
#error "Must define USE_NEGOTIATE or USE_KERBEROS"
#endif
				credssp->CredentialType = 2;
				break;

			default:
				break;
		}

		credssp->send_seq_num = 0;
		credssp->recv_seq_num = 0;
		ZeroMemory(&credssp->negoToken, sizeof(SecBuffer));
		ZeroMemory(&credssp->pubKeyAuth, sizeof(SecBuffer));
		ZeroMemory(&credssp->authInfo, sizeof(SecBuffer));
		SecInvalidateHandle(&credssp->context);

#if 0 // BOMGAR
		if (credssp->server)
		{
			status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("Software\\FreeRDP\\Server"),
					0, KEY_READ | KEY_WOW64_64KEY, &hKey);

			if (status == ERROR_SUCCESS)
			{
				status = RegQueryValueEx(hKey, _T("SspiModule"), NULL, &dwType, NULL, &dwSize);

				if (status == ERROR_SUCCESS)
				{
					credssp->SspiModule = (LPTSTR) malloc(dwSize + sizeof(TCHAR));

					status = RegQueryValueEx(hKey, _T("SspiModule"), NULL, &dwType,
							(BYTE*) credssp->SspiModule, &dwSize);

					if (status == ERROR_SUCCESS)
					{
						_tprintf(_T("Using SSPI Module: %s\n"), credssp->SspiModule);
						RegCloseKey(hKey);
					}
				}
			}
		}
#endif // BOMGAR
	}

	return credssp;
}

/**
 * Free CredSSP state machine.
 * @param credssp
 */

void credssp_free(rdpCredssp* credssp)
{
	if (credssp != NULL)
	{
		if (credssp->table)
			credssp->table->DeleteSecurityContext(&credssp->context);

		sspi_SecBufferFree(&credssp->PublicKey);
		sspi_SecBufferFree(&credssp->ts_credentials);

		free(credssp->ServicePrincipalName);

		free(credssp->identity.User);
		free(credssp->identity.Domain);
		free(credssp->identity.Password);
		free(credssp);
	}
}
