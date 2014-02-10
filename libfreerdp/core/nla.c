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

#ifdef WIN32
#define ALLOW_SSPI_MODULE_OVERRIDE
#endif

#ifdef WITH_DEBUG_NLA
#define WITH_DEBUG_CREDSSP
#endif

#ifdef WITH_NATIVE_SSPI
#if defined(USE_NEGOTIATE_SSP)
#define NLA_PKG_NAME NEGOSSP_NAME
#else
#define NLA_PKG_NAME NTLMSP_NAME
#endif
#else
 /* non native sspi, use NTLM */
 #define NLA_PKG_NAME NTLMSP_NAME
#endif

#if defined(WITH_DEBUG_NLA)
int save_ts_request = 0;
#endif

#define TERMSRV_SPN_PREFIX "TERMSRV/"

#ifdef WITH_DEBUG_NLA
#define DEBUG_NLA(fmt, ...) DEBUG_CLASS(NLA, fmt, ## __VA_ARGS__)
#else
#define DEBUG_NLA(fmt, ...) DEBUG_NULL(fmt, ## __VA_ARGS__)
#endif

#ifdef WITH_DEBUG_CREDSSP
#define DEBUG_CREDSSP(fmt, ...) DEBUG_CLASS(CREDSSP, fmt, ## __VA_ARGS__)
#else
#define DEBUG_CREDSSP(fmt, ...) DEBUG_NULL(fmt, ## __VA_ARGS__)
#endif


void credssp_send(rdpCredssp* credssp);
int credssp_recv(rdpCredssp* credssp);
void credssp_buffer_print(rdpCredssp* credssp);
void credssp_buffer_free(rdpCredssp* credssp);
SECURITY_STATUS credssp_encrypt_public_key_echo(rdpCredssp* credssp);
SECURITY_STATUS credssp_decrypt_public_key_echo(rdpCredssp* credssp);
SECURITY_STATUS credssp_encrypt_ts_credentials(rdpCredssp* credssp);
SECURITY_STATUS credssp_decrypt_ts_credentials(rdpCredssp* credssp);

void credssp_encode_ts_credentials(rdpCredssp* credssp);

#define ber_sizeof_sequence_octet_string(length) ber_sizeof_contextual_tag(ber_sizeof_octet_string(length)) + ber_sizeof_octet_string(length)
#define ber_sizeof_sequence_integer(i) ber_sizeof_contextual_tag(ber_sizeof_integer(i)) + ber_sizeof_integer(i)
#define ber_write_sequence_octet_string(stream, context, value, length) ber_write_contextual_tag(stream, context, ber_sizeof_octet_string(length), TRUE) + ber_write_octet_string(stream, value, length)
#define ber_write_sequence_integer(stream, context, value) ber_write_contextual_tag(stream, context, ber_sizeof_integer(value), TRUE) + ber_write_integer(stream, value)
#define ber_write_sequence_header(stream, context, length) ber_write_contextual_tag(stream, context, ber_sizeof_sequence_octet_string(length), TRUE) + ber_write_octet_string_tag(stream, ber_sizeof_sequence(length))

#if defined(WITH_DEBUG_NLA)
void SaveBufferToFile(const char* filename, const PBYTE data, int length)
{
	FILE *fp;

	fp = fopen(filename, "wb");
	if (fp != NULL) {
		fwrite(data, length, 1, fp);
		fclose(fp);
	}
}
#endif

/**
 * Initialize NTLMSSP authentication module (client).
 * @param credssp
 */

int credssp_ntlm_client_init(rdpCredssp* credssp)
{
	BOOL PromptPassword;
	rdpTls* tls = NULL;
	freerdp* instance;
	rdpSettings* settings;

	PromptPassword = FALSE;
	settings = credssp->settings;
	instance = (freerdp*) settings->instance;

	if ((!settings->Password) || (!settings->Username)
			|| (!strlen(settings->Password)) || (!strlen(settings->Username)))
	{
		PromptPassword = TRUE;
	}

#ifndef _WIN32
	if (PromptPassword)
	{
		if (settings->RestrictedAdminModeRequired)
		{
			if ((settings->PasswordHash) && (strlen(settings->PasswordHash) > 0))
				PromptPassword = FALSE;
		}
	}
#endif

	if (PromptPassword)
	{
		if (instance->Authenticate)
		{
			BOOL proceed = instance->Authenticate(instance,
					&settings->Username, &settings->Password, &settings->Domain);

			if (!proceed)
			{
				connectErrorCode = CANCELEDBYUSER;
				return 0;
			}

		}
	}

	switch (settings->CredentialsType) {
	case 1:
		credssp->providerName = _tcsdup(NTLMSP_NAME);
		break;

	case 2:
		credssp->providerName = _tcsdup(NEGOSSP_NAME);
		break;

	default:
		DEBUG_ERROR("Unhandled CredentialType: %d", settings->CredentialsType);
		return 0;
	}

	sspi_SetAuthIdentity(&(credssp->identity), settings->Username, settings->Domain, settings->Password);

#ifndef _WIN32
	{
		SEC_WINNT_AUTH_IDENTITY* identity = &(credssp->identity);

		if (settings->RestrictedAdminModeRequired)
		{
			if (settings->PasswordHash)
			{
				if (strlen(settings->PasswordHash) == 32)
				{
					if (identity->Password)
						free(identity->Password);

					identity->PasswordLength = ConvertToUnicode(CP_UTF8, 0,
							settings->PasswordHash, -1, &identity->Password, 0) - 1;

					/**
					 * Multiply password hash length by 64 to obtain a length exceeding
					 * the maximum (256) and use it this for hash identification in WinPR.
					 */
					identity->PasswordLength = 32 * 64; /* 2048 */
				}
			}
		}
	}
#endif

#ifdef WITH_DEBUG_NLA
#ifdef UNICODE
	DEBUG_NLA("User: %S Domain: %S Password: %S", credssp->identity.User, credssp->identity.Domain, credssp->identity.Password);
#else
	DEBUG_NLA("User: %s Domain: %s Password: %s", (char*) credssp->identity.User, (char*) credssp->identity.Domain, (char*) credssp->identity.Password);
#endif // UNICODE
#endif // WITH_DEBUG_NLA

	if (credssp->transport->layer == TRANSPORT_LAYER_TLS)
	{
		tls = credssp->transport->TlsIn;
	}
	else if (credssp->transport->layer == TRANSPORT_LAYER_TSG_TLS)
	{
		tls = credssp->transport->TsgTls;
	}
	else
	{
		fprintf(stderr, "Unknown NLA transport layer\n");
		return 0;
	}

	sspi_SecBufferAlloc(&credssp->PublicKey, tls->PublicKeyLength);
	CopyMemory(credssp->PublicKey.pvBuffer, tls->PublicKey, tls->PublicKeyLength);

#ifdef UNICODE
	{
		const int hostLen = strlen(credssp->settings->ServerHostname);
		const int serviceLen = sizeof(TERMSRV_SPN_PREFIX);
		const DWORD dwLen = (serviceLen+hostLen)*sizeof(WCHAR);
		credssp->ServicePrincipalName = (PWCHAR)malloc(dwLen+4);
		ZeroMemory(credssp->ServicePrincipalName, dwLen+4);
		swprintf(credssp->ServicePrincipalName, dwLen, L"%S%S", TERMSRV_SPN_PREFIX, strupr(credssp->settings->ServerHostname));
	}
#else
	{
		const int length = sizeof(TERMSRV_SPN_PREFIX) + strlen(settings->ServerHostname);
		credssp->ServicePrincipalName = (SEC_CHAR*) malloc(length + 1);
		_snprintf(credssp->ServicePrincipalName, length, "%s%s", TERMSRV_SPN_PREFIX, settings->ServerHostname);
	}
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
	char msg[2048] = {0};
	static const int msgSize = ARRAYSIZE(msg);
	int x = 0;

	x = _snprintf(&msg[0], msgSize, "SECURITY_STATUS: %#x - ", sc);
	switch (sc) {
	case SEC_E_QOP_NOT_SUPPORTED:
		x += _snprintf(&msg[x], msgSize-x, "Neither confidentiality nor integrity are supported by the security context.");
		break;
	case SEC_E_INVALID_TOKEN:
		x += _snprintf(&msg[x], msgSize-x, "No SECBUFFER_DATA type buffer was found.");
		break;
	case SEC_E_INVALID_HANDLE:
		x += _snprintf(&msg[x], msgSize-x, "A context handle that is not valid was specified in the phContext parameter.");
		break;
	case SEC_E_INSUFFICIENT_MEMORY:
		x += _snprintf(&msg[x], msgSize-x, "There is not enough memory available to complete the requested action.");
		break;
	case SEC_E_BUFFER_TOO_SMALL:
		x += _snprintf(&msg[x], msgSize-x, "The output buffer is too small.");
		break;
	case SEC_E_CONTEXT_EXPIRED:
		x += _snprintf(&msg[x], msgSize-x, "The application is referencing a context that has already been closed. A properly written application should not receive this error.");
		break;
	case SEC_E_CRYPTO_SYSTEM_INVALID:
		x += _snprintf(&msg[x], msgSize-x, "The cipher chosen for the security context is not supported.");
		break;

	default:
		x += _snprintf(&msg[x], msgSize-x, "Unknown Error: %#x", sc);
		break;
	}

	DEBUG_NLA("%s", msg);
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

	sspi_GlobalInit();

	if (credssp_ntlm_client_init(credssp) == 0)
		return 0;

#ifdef WITH_NATIVE_SSPI
	{
		HMODULE hSSPI;
		INIT_SECURITY_INTERFACE InitSecurityInterface;
		PSecurityFunctionTable pSecurityInterface = NULL;

		hSSPI = LoadLibrary(credssp->SspiModule);

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

	if (status != SEC_E_OK)
	{
		DEBUG_ERROR("QuerySecurityPackageInfo status: 0x%08X", status);
		return 0;
	}

	cbMaxToken = pPackageInfo->cbMaxToken;

	DEBUG_NLA("SPN: %S", (wchar_t*)credssp->ServicePrincipalName);
	DEBUG_NLA("Security Package Name: %S", (wchar_t*)pPackageInfo->Name);

	status = credssp->table->AcquireCredentialsHandle(NULL, pPackageInfo->Name,
		SECPKG_CRED_OUTBOUND, NULL, &credssp->identity, NULL, NULL, &credentials, &expiration);

	if (status != SEC_E_OK)
	{
		DEBUG_ERROR("AcquireCredentialsHandle status: 0x%08X", status);
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

	switch (credssp->settings->CredentialsType) {
		case 1:
			DEBUG_NLA("Setting context request flags for CredentialType 1.");
			fContextReq = ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR | ISC_REQ_MUTUAL_AUTH | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_USE_SESSION_KEY;
			break;

		case 2:
			DEBUG_NLA("Setting context request flags for CredentialType 2.");
		// Flags for Negotiate
			fContextReq = ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR | ISC_REQ_MUTUAL_AUTH | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_USE_SESSION_KEY | ISC_REQ_REPLAY_DETECT | ISC_REQ_DELEGATE | ISC_REQ_USE_SUPPLIED_CREDS;
			break;

		default:
			DEBUG_ERROR("Unhandled CredentialType: %d", credssp->settings->CredentialsType);
			return 0;
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

		DEBUG_NLA("InsitializeSecurityContext: status: %#x", status);

		if (have_input_buffer && (input_buffer.pvBuffer != NULL))
		{
			free(input_buffer.pvBuffer);
			input_buffer.pvBuffer = NULL;
		}

		if ((status == SEC_I_COMPLETE_AND_CONTINUE) || (status == SEC_I_COMPLETE_NEEDED) || (status == SEC_E_OK))
		{
			DEBUG_NLA("Authentication Complete.");
			fContextReq = pfContextAttr;
			DEBUG_NLA("ISC Context Attrs returned: %#lx", fContextReq);
			if (credssp->table->CompleteAuthToken != NULL)
				ss = credssp->table->CompleteAuthToken(&credssp->context, &output_buffer_desc);

			have_pub_key_auth = TRUE;

			if (credssp->table->QueryContextAttributes(&credssp->context, SECPKG_ATTR_SIZES, &credssp->ContextSizes) != SEC_E_OK)
			{
				DEBUG_ERROR("QueryContextAttributes SECPKG_ATTR_SIZES failure");
				return 0;
			}

			ss = credssp_encrypt_public_key_echo(credssp);
			if (ss != SEC_E_OK) {
				return 0;
			}

			if (status == SEC_I_COMPLETE_NEEDED)
				status = SEC_E_OK;
			else if (status == SEC_I_COMPLETE_AND_CONTINUE)
				status = SEC_I_CONTINUE_NEEDED;
		}

		/* send authentication token to server */
		/* set the negoToken point now so credssp_buffer_free() will cleanup the output_buffer */
		credssp->negoToken.pvBuffer = output_buffer.pvBuffer;
		credssp->negoToken.cbBuffer = output_buffer.cbBuffer;

		switch (status) {
			case SEC_E_NO_AUTHENTICATING_AUTHORITY:
				DEBUG_ERROR("SEC_E_NO_AUTHENTICATING_AUTHORITY - No authority could be contacted for authentication.");
				break;

			case SEC_E_TARGET_UNKNOWN:
				DEBUG_ERROR("SEC_E_TARGET_UNKNOWN - The specified target is unknown or unreachable.");
				break;

			case SEC_E_UNSUPPORTED_FUNCTION:
				DEBUG_ERROR("SEC_E_UNSUPPORTED_FUNCTION - The function requested is not supported.");
				break;

			case SEC_E_WRONG_PRINCIPAL:
				DEBUG_ERROR("SEC_E_WRONG_PRINCIPAL - The target principal name is incorrect.");
				break;

			default:
#ifdef WITH_DEBUG_CREDSSP
				{
					const int len = 1024 + ((credssp->negoToken.cbBuffer + credssp->pubKeyAuth.cbBuffer) * 4);
					char* buf = (char*)malloc(len);
					int x = 0;

					ZeroMemory(buf, len);

					x = _snprintf(buf, len, "Sending Authentication Token\nnegotoken\n");
					x += winpr_HexDumpToBuffer(buf+x, len-x, (PBYTE)credssp->negoToken.pvBuffer, credssp->negoToken.cbBuffer);
					x += _snprintf(buf+x, len-x, "pubkeyauth\n");
					x += winpr_HexDumpToBuffer(buf+x, len-x, (PBYTE)credssp->pubKeyAuth.pvBuffer, credssp->pubKeyAuth.cbBuffer);

					DEBUG_CREDSSP("%s", buf);

					free(buf);
					buf = NULL;
				}
#endif

				credssp_send(credssp);
				break;
		}

		credssp_buffer_free(credssp);

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
		{
			const int len = (credssp->negoToken.cbBuffer*4) + 1024;
			char* buf = (char*)malloc(len);
			int x = 0;

			ZeroMemory(buf, len);

			x = _snprintf(buf, len, "Receiving Authentication Token (%d)\n", (int) credssp->negoToken.cbBuffer);
			x += winpr_HexDumpToBuffer(buf+x, len-x, (PBYTE)credssp->negoToken.pvBuffer, credssp->negoToken.cbBuffer);

			DEBUG_CREDSSP("%s", buf);
			free(buf);
		}
#endif

		input_buffer.pvBuffer = credssp->negoToken.pvBuffer;
		input_buffer.cbBuffer = credssp->negoToken.cbBuffer;

		have_input_buffer = TRUE;
		have_context = TRUE;
	} // end while(TRUE)

	/* Encrypted Public Key +1 */
	if (credssp_recv(credssp) < 0)
		return -1;

	/* Verify Server Public Key Echo */
	status = credssp_decrypt_public_key_echo(credssp);
	credssp_buffer_free(credssp);

	if (status != SEC_E_OK)
	{
		DEBUG_ERROR("Could not verify public key echo!");
		return -1;
	}

	/* Send encrypted credentials */
	switch (credssp->settings->CredentialsType) {
		case 1:
			status = credssp_encrypt_ts_credentials(credssp);
			break;

		case 2:
			status = credssp_encrypt_ts_credentials(credssp);
			break;

		default:
			DEBUG_ERROR("Unhandled CredentialType: %d", credssp->settings->CredentialsType);
			return -1;
	}

	if (status != SEC_E_OK)
	{
		DEBUG_ERROR("credssp_encrypt_ts_credentials status: 0x%08X", status);
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

// TODO validate client SC authentication support against freerdp server
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
			DEBUG_ERROR("Failed to load SSPI module: %s", credssp->SspiModule);
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
		DEBUG_ERROR("QuerySecurityPackageInfo status: 0x%08X", status);
		return 0;
	}

	cbMaxToken = pPackageInfo->cbMaxToken;

	status = credssp->table->AcquireCredentialsHandle(NULL, NLA_PKG_NAME,
			SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &credentials, &expiration);

	if (status != SEC_E_OK)
	{
		DEBUG_ERROR("AcquireCredentialsHandle status: 0x%08X", status);
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
		DEBUG_CREDSSP("Receiving Authentication Token");
		credssp_buffer_print(credssp);
#endif

		input_buffer.pvBuffer = credssp->negoToken.pvBuffer;
		input_buffer.cbBuffer = credssp->negoToken.cbBuffer;

		if (credssp->negoToken.cbBuffer < 1)
		{
			DEBUG_ERROR("CredSSP: invalid negoToken!");
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
				DEBUG_ERROR("QueryContextAttributes SECPKG_ATTR_SIZES failure");
				return 0;
			}

			DEBUG_CREDSSP("Decrypting PublicKey from server.");
			if (credssp_decrypt_public_key_echo(credssp) != SEC_E_OK)
			{
				DEBUG_ERROR("Error: could not verify client's public key echo");
				return -1;
			}

			sspi_SecBufferFree(&credssp->negoToken);
			credssp->negoToken.pvBuffer = NULL;
			credssp->negoToken.cbBuffer = 0;

			DEBUG_CREDSSP("Encrypting PublicKey from server.");
			credssp_encrypt_public_key_echo(credssp);
		}

		if ((status != SEC_E_OK) && (status != SEC_I_CONTINUE_NEEDED))
		{
			DEBUG_ERROR("AcceptSecurityContext status: 0x%08X", status);
			return -1; /* Access Denied */
		}

		/* send authentication token */

#ifdef WITH_DEBUG_CREDSSP
		DEBUG_CREDSSP("Sending Authentication Token");
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
		DEBUG_ERROR("Could not decrypt TSCredentials status: 0x%08X\n", status);
		return 0;
	}

	if (status != SEC_E_OK)
	{
		DEBUG_ERROR("AcceptSecurityContext status: 0x%08X", status);
		return 0;
	}

	status = credssp->table->ImpersonateSecurityContext(&credssp->context);

	if (status != SEC_E_OK)
	{
		DEBUG_ERROR("ImpersonateSecurityContext status: 0x%08X", status);
		return 0;
	}
	else
	{
		status = credssp->table->RevertSecurityContext(&credssp->context);

		if (status != SEC_E_OK)
		{
			DEBUG_ERROR("RevertSecurityContext status: 0x%08X", status);
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

SECURITY_STATUS credssp_encrypt_public_key_echo(rdpCredssp* credssp)
{
	SecBuffer Buffers[2];
	SecBufferDesc Message;
	SECURITY_STATUS status;
	PVOID pTemp = NULL;

	const int public_key_length = credssp->PublicKey.cbBuffer;
	const int cbpTemp = public_key_length + credssp->ContextSizes.cbMaxToken;

	Buffers[0].BufferType = SECBUFFER_TOKEN; /* Signature */
	Buffers[1].BufferType = SECBUFFER_DATA; /* TLS Public Key */

	pTemp = malloc(cbpTemp);
	ZeroMemory(pTemp, cbpTemp);

	Buffers[0].cbBuffer = credssp->ContextSizes.cbMaxToken;
	Buffers[0].pvBuffer = pTemp;

	Buffers[1].cbBuffer = public_key_length;
	Buffers[1].pvBuffer = (BYTE*) pTemp  + Buffers[0].cbBuffer;
	CopyMemory(Buffers[1].pvBuffer, credssp->PublicKey.pvBuffer, Buffers[1].cbBuffer);

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
		DEBUG_ERROR("EncryptMessage status: 0x%08X", status);
		LogSSPIError(status);
		return status;
	}

	/* store the signature size for decryption */
	/* the MS RDP server will not accept starting the encrypted buffer
	   with the size of the signature, so we store it.  This allows us
	   to use NTLMSSP or KEGBEROS
	*/
	credssp->cbSignature = Buffers[0].cbBuffer;

	sspi_SecBufferAlloc(&credssp->pubKeyAuth, Buffers[0].cbBuffer + Buffers[1].cbBuffer);
	CopyMemory(credssp->pubKeyAuth.pvBuffer, Buffers[0].pvBuffer, Buffers[0].cbBuffer);
	CopyMemory((BYTE*)credssp->pubKeyAuth.pvBuffer + Buffers[0].cbBuffer, Buffers[1].pvBuffer, Buffers[1].cbBuffer);

	SecureZeroMemory(pTemp, cbpTemp);
	free(pTemp);
	pTemp = NULL;

	return status;
}

SECURITY_STATUS credssp_decrypt_public_key_echo(rdpCredssp* credssp)
{
	BYTE* buffer;
	ULONG pfQOP = 0;
	BYTE* public_key1;
	BYTE* public_key2;
	int public_key_length;
	SecBuffer Buffers[2];
	SecBufferDesc Message;
	SECURITY_STATUS status;

	if (credssp->PublicKey.cbBuffer + credssp->cbSignature != credssp->pubKeyAuth.cbBuffer)
	{
		DEBUG_ERROR("unexpected pubKeyAuth buffer size: %d (0x%ld) bytes", (int) credssp->pubKeyAuth.cbBuffer, credssp->pubKeyAuth.cbBuffer);
		return SEC_E_INVALID_TOKEN;
	}

	/* decrypt in place */
	buffer = (BYTE*)credssp->pubKeyAuth.pvBuffer;

	public_key_length = credssp->PublicKey.cbBuffer;

	Buffers[0].BufferType = SECBUFFER_TOKEN; /* Signature */
	Buffers[1].BufferType = SECBUFFER_DATA; /* Encrypted TLS Public Key */

	Buffers[0].cbBuffer = credssp->cbSignature;
	Buffers[0].pvBuffer = buffer;

	Buffers[1].cbBuffer = credssp->pubKeyAuth.cbBuffer - credssp->cbSignature;
	Buffers[1].pvBuffer = buffer + credssp->cbSignature;

	Message.cBuffers = 2;
	Message.ulVersion = SECBUFFER_VERSION;
	Message.pBuffers = (PSecBuffer) &Buffers;

	status = credssp->table->DecryptMessage(&credssp->context, &Message, credssp->recv_seq_num++, &pfQOP);

	if (status != SEC_E_OK)
	{
		DEBUG_ERROR("DecryptMessage failure: 0x%08X", status);
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
		char buf[4096] = {0};
		static const int bufSize = ARRAYSIZE(buf);
		int x = 0;

		x = _snprintf(&buf[x], bufSize, "Could not verify server's public key echo\nExpected (length = %d):\n", public_key_length);
		x += winpr_HexDumpToBuffer(&buf[x], bufSize-x, public_key1, public_key_length);
		x += _snprintf(&buf[x],  bufSize-x, "Actual (length = %d):\n", public_key_length);
		x += winpr_HexDumpToBuffer(&buf[x], bufSize-x, public_key2, public_key_length);
		DEBUG_CREDSSP("%s", buf);

		return SEC_E_MESSAGE_ALTERED; /* DO NOT SEND CREDENTIALS! */
	}

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
	/* packet captures using mstsc.exe have shown this is not sent */
	/*cardName      [1] OCTET STRING OPTIONAL,*/
	if (credssp->settings->SmartCard_CSP_Data.pszCardName) {
		length += ber_sizeof_sequence_octet_string(gSCCspData.cbCardName);
	}
#endif

	/*readerName    [2] OCTET STRING OPTIONAL,*/
	if (credssp->settings->SmartCard_CSP_Data.pszReaderName) {
		length += ber_sizeof_sequence_octet_string(credssp->settings->SmartCard_CSP_Data.cbReaderName);
	}

  /*containerName [3] OCTET STRING OPTIONAL,*/
	if (credssp->settings->SmartCard_CSP_Data.pszContainerName) {
		length += ber_sizeof_sequence_octet_string(credssp->settings->SmartCard_CSP_Data.cbContainerName);
	}

	/*cspName       [4] OCTET STRING OPTIONAL*/
	if (credssp->settings->SmartCard_CSP_Data.pszCspName) {
		length += ber_sizeof_sequence_octet_string(credssp->settings->SmartCard_CSP_Data.cbCspName);
	}

	DEBUG_CREDSSP("size of TSCspDataDetail: %d (%#x)", length, length);

	return length;
}

int credssp_sizeof_ts_smartcard_creds(rdpCredssp* credssp)
{
	int length = 0;
	int cspdata_size = credssp_sizeof_ts_cspdata_detail(credssp);

	DEBUG_CREDSSP("size of TSCspDataDetail: %d (%#x)", cspdata_size, cspdata_size);
	length += ber_sizeof_sequence_octet_string(credssp->identity.PasswordLength * 2);
	length += ber_sizeof_sequence_octet_string(cspdata_size);
	DEBUG_CREDSSP("size of TSSmartCardCreds: %d (%#x)", length, length);

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
	/* packet captures using mstsc.exe have shown this is not sent */
	if (credssp->settings->SmartCard_CSP_Data.pszCardName) {
		size += ber_write_sequence_octet_string(s, 1, (BYTE*)credssp->settings->SmartCard_CSP_Data.pszCardName, credssp->settings->SmartCard_CSP_Data.cbCardName);
	}
#endif

	if (credssp->settings->SmartCard_CSP_Data.pszReaderName) {
		size += ber_write_sequence_octet_string(s, 2, (BYTE*)credssp->settings->SmartCard_CSP_Data.pszReaderName, credssp->settings->SmartCard_CSP_Data.cbReaderName);
	}

	if (credssp->settings->SmartCard_CSP_Data.pszContainerName) {
		size += ber_write_sequence_octet_string(s, 3, (BYTE*)credssp->settings->SmartCard_CSP_Data.pszContainerName, credssp->settings->SmartCard_CSP_Data.cbContainerName);
	}

	if (credssp->settings->SmartCard_CSP_Data.pszCspName) {
		size += ber_write_sequence_octet_string(s, 4, (BYTE*)credssp->settings->SmartCard_CSP_Data.pszCspName, credssp->settings->SmartCard_CSP_Data.cbCspName);
	}

#if defined(WITH_DEBUG_CREDSSP)
	{
		void *n = s->pointer-size;
		SaveBufferToFile("tscspdetail.ber", (PBYTE)n, size);
	}
#endif

	return size;
}

int credssp_write_ts_smartcard_creds(rdpCredssp* credssp, wStream* s)
{
	int size = 0;

	int innerSize = credssp_sizeof_ts_smartcard_creds(credssp);
	int cspdataSize = credssp_sizeof_ts_cspdata_detail(credssp);

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
	size += ber_write_contextual_tag(s, 1, ber_sizeof_octet_string(cspdataSize), TRUE);
	size += credssp_write_ts_cspdata_detail(credssp, s);

#if defined(WITH_DEBUG_CREDSSP)
	{
		void *n = s->pointer-size;
		SaveBufferToFile("tssmartcardcreds.ber", (BYTE*)n, size);
	}
#endif

	return size;
}

int credssp_sizeof_ts_credentials(rdpCredssp* credssp)
{
	int size = 0;

	size += ber_sizeof_integer(1);
	size += ber_sizeof_contextual_tag(ber_sizeof_integer(1));
	switch (credssp->settings->CredentialsType) {
		case 1:
			size += ber_sizeof_sequence_octet_string(ber_sizeof_sequence(credssp_sizeof_ts_password_creds(credssp)));
			break;

		case 2:
			size += ber_sizeof_sequence_octet_string(ber_sizeof_sequence(credssp_sizeof_ts_smartcard_creds(credssp)));
			break;

		default:
			DEBUG_ERROR("Unhandled CredentialType: %d", credssp->settings->CredentialsType);
			return 0;
	}

	DEBUG_CREDSSP("credssp_sizeof_ts_credentials: size: %d %#x", size, size);

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

	switch (credssp->settings->CredentialsType) {
		case 1:
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
			DEBUG_CREDSSP("size of TSSmartCardCreds: %#x", credSize);

			size += ber_write_contextual_tag(s, 1, ber_sizeof_sequence_octet_string(credSize), TRUE);
			size += ber_write_octet_string_tag(s, ber_sizeof_sequence(credSize));
			size += credssp_write_ts_smartcard_creds(credssp, s);
			break;

		default:
			DEBUG_ERROR("Unhandled CredentialType: %d", credssp->settings->CredentialsType);
			return 0;
	}

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
	int DomainLength;
	int UserLength;
	int PasswordLength;

	DomainLength = credssp->identity.DomainLength;
	UserLength = credssp->identity.UserLength;
	PasswordLength = credssp->identity.PasswordLength;

	if (credssp->settings->RestrictedAdminModeRequired)
	{
		credssp->identity.DomainLength = 0;
		credssp->identity.UserLength = 0;
		credssp->identity.PasswordLength = 0;
	}

	length = ber_sizeof_sequence(credssp_sizeof_ts_credentials(credssp)) + 4;
	DEBUG_CREDSSP("sizeof: %d", length);
	sspi_SecBufferAlloc(&credssp->ts_credentials, length);

	s = Stream_New((BYTE*)credssp->ts_credentials.pvBuffer, length);
	credssp_write_ts_credentials(credssp, s);

	if (credssp->settings->RestrictedAdminModeRequired)
	{
		credssp->identity.DomainLength = DomainLength;
		credssp->identity.UserLength = UserLength;
		credssp->identity.PasswordLength = PasswordLength;
	}

#if defined(WITH_DEBUG_CREDSSP)
	SaveBufferToFile("tscredentials.ber", s->buffer, length);
#endif

	Stream_Free(s, FALSE);
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

	token_size = credssp->ContextSizes.cbMaxToken;

	DEBUG_CREDSSP("token_size: %d (%#x)", token_size, token_size);

	Buffers[0].BufferType = SECBUFFER_TOKEN; /* Signature */
	Buffers[1].BufferType = SECBUFFER_DATA; /* TSCredentials */

	buffer_size = token_size + credssp->ts_credentials.cbBuffer;
	pTemp = malloc(credssp->ContextSizes.cbMaxToken + credssp->ts_credentials.cbBuffer);
	ZeroMemory(pTemp, credssp->ContextSizes.cbMaxToken + credssp->ts_credentials.cbBuffer);

	Buffers[0].cbBuffer = token_size;
	Buffers[0].pvBuffer = pTemp;

	Buffers[1].cbBuffer = credssp->ts_credentials.cbBuffer;
#if defined(INCLUDE_MESSAGE_SIZE)
	Buffers[1].pvBuffer = (BYTE*)pTemp + Buffers[1].cbBuffer + sizeof(DWORD64);
	CopyMemory(Buffers[1].pvBuffer, credssp->ts_credentials.pvBuffer + sizeof(DWORD64), Buffers[1].cbBuffer);
#else
	Buffers[1].pvBuffer = (BYTE*)pTemp + Buffers[1].cbBuffer;
	CopyMemory(Buffers[1].pvBuffer, credssp->ts_credentials.pvBuffer, Buffers[1].cbBuffer);
#endif

#if defined(WITH_DEBUG_CREDSSP)
	SaveBufferToFile("credentials.ber", (PBYTE)credssp->ts_credentials.pvBuffer, credssp->ts_credentials.cbBuffer);
	SaveBufferToFile("credentials2.ber", (PBYTE)Buffers[1].pvBuffer, Buffers[1].cbBuffer);
#endif

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
	CopyMemory((BYTE*)credssp->authInfo.pvBuffer+sizeof(DWORD64), Buffers[0].pvBuffer, Buffers[0].cbBuffer);
	CopyMemory((BYTE*)credssp->authInfo.pvBuffer+sizeof(DWORD64)+Buffers[0].cbBuffer, Buffers[1].pvBuffer, Buffers[1].cbBuffer);
#else
	CopyMemory((BYTE*)credssp->authInfo.pvBuffer, Buffers[0].pvBuffer, Buffers[0].cbBuffer);
	CopyMemory((BYTE*)credssp->authInfo.pvBuffer+Buffers[0].cbBuffer, Buffers[1].pvBuffer, Buffers[1].cbBuffer);
#endif
	free(pTemp);

	DEBUG_CREDSSP("Adjusted Token Size: %ld (%#lx)", Buffers[0].cbBuffer, Buffers[0].cbBuffer);

#if defined(WITH_DEBUG_CREDSSP)
	SaveBufferToFile("authinfo-encrypted.raw", (PBYTE)credssp->authInfo.pvBuffer, credssp->authInfo.cbBuffer);
#endif

	if (status != SEC_E_OK) {
		return status;
	}

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
		DEBUG_ERROR("credssp_decrypt_ts_credentials missing authInfo buffer");
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

	DEBUG_CREDSSP("nego_tokens_length: %d %#x", nego_tokens_length, nego_tokens_length);
	DEBUG_CREDSSP("pub_key_auth_length: %d %#x", pub_key_auth_length, pub_key_auth_length);
	DEBUG_CREDSSP("auth_info_length: %d %#x", auth_info_length, auth_info_length);

	length = nego_tokens_length + pub_key_auth_length + auth_info_length;

	DEBUG_CREDSSP("length: %d %#x", length, length);

	ts_request_length = credssp_sizeof_ts_request(length);

	DEBUG_CREDSSP("ts_request_length: %d %#x", ts_request_length, ts_request_length);

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

#if defined(WITH_DEBUG_NLA)
	{
		char t[16] = {0};
		_snprintf(t, ARRAYSIZE(t), "tsrequest-%d.ber", save_ts_request++);
		DEBUG_CREDSSP("saving tsrequest buffer: %s", t);
		SaveBufferToFile(t, (BYTE*)sstart, s->length);
	}
#endif

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
		DEBUG_ERROR("credssp_recv() error: %d", status);
		Stream_Free(s, TRUE);
		return -1;
	}

	/* TSRequest */
	if(!ber_read_sequence_tag(s, &length) ||
		!ber_read_contextual_tag(s, 0, &length, TRUE) ||
		!ber_read_integer(s, &version))
	{
		DEBUG_ERROR("Invalid TSRequest message");
		winpr_HexDump(Stream_Buffer(s), Stream_Length(s));
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
			DEBUG_ERROR("Invalid TSRequest message.  Failed to parse NegoData.");
			winpr_HexDump(Stream_Buffer(s), Stream_Length(s));
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
			DEBUG_ERROR("Invalid TSRequest message.  Failed to parse authInfo.");
			winpr_HexDump(Stream_Buffer(s), Stream_Length(s));
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
			DEBUG_ERROR("Invalid TSRequest message.  Failed to parse pubKeyAuth.");
			winpr_HexDump(Stream_Buffer(s), Stream_Length(s));
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
	char buf[4096] = {0};
	static const int bufSize = ARRAYSIZE(buf);
	int x = 0;

	if (credssp->negoToken.cbBuffer > 0)
	{
		x = _snprintf(&buf[0], bufSize, "CredSSP.negoToken (length = %d):", (int) credssp->negoToken.cbBuffer);
		x += winpr_HexDumpToBuffer(&buf[x], bufSize-x, (BYTE*)credssp->negoToken.pvBuffer, credssp->negoToken.cbBuffer);
		DEBUG_CREDSSP("%s", buf);
	}

	if (credssp->pubKeyAuth.cbBuffer > 0)
	{
		x = _snprintf(&buf[0], bufSize, "CredSSP.pubKeyAuth (length = %d):", (int) credssp->pubKeyAuth.cbBuffer);
		x += winpr_HexDumpToBuffer(&buf[x], bufSize-x, (BYTE*)credssp->pubKeyAuth.pvBuffer, credssp->pubKeyAuth.cbBuffer);
		DEBUG_CREDSSP("%s", buf);
	}

	if (credssp->authInfo.cbBuffer > 0)
	{
		x = _snprintf(&buf[0], bufSize, "CredSSP.authInfo (length = %d):", (int) credssp->authInfo.cbBuffer);
		x += winpr_HexDumpToBuffer(&buf[x], bufSize-x, (BYTE*)credssp->authInfo.pvBuffer, credssp->authInfo.cbBuffer);
		DEBUG_CREDSSP("%s", buf);
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

		credssp->instance = instance;
		credssp->settings = settings;
		credssp->server = settings->ServerMode;
		credssp->transport = transport;

		credssp->send_seq_num = 0;
		credssp->recv_seq_num = 0;
		ZeroMemory(&credssp->negoToken, sizeof(SecBuffer));
		ZeroMemory(&credssp->pubKeyAuth, sizeof(SecBuffer));
		ZeroMemory(&credssp->authInfo, sizeof(SecBuffer));
		SecInvalidateHandle(&credssp->context);

#if defined(ALLOW_SSPI_MODULE_OVERRIDE)
		{
			HKEY hKey;
			LONG status;
			status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("Software\\FreeRDP\\Server"),
				0, KEY_READ | KEY_WOW64_64KEY, &hKey);

			if (status == ERROR_SUCCESS)
			{
				DWORD dwSize;
				DWORD dwType;

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

		if (! credssp->SspiModule) {
			credssp->SspiModule = _tcsdup(_T("secur32.dll"));
		}
#else
		credssp->SspiModule = _tcsdup(_T("secur32.dll"));
#endif
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
		if (credssp->SspiModule) {
			free(credssp->SspiModule);
		}

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
