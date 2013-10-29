/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Smartcard Device Service Virtual Channel
 *
 * Copyright (C) Alexi Volkov <alexi@myrealbox.com> 2006
 * Copyright 2011 O.S. Systems Software Ltda.
 * Copyright 2011 Anthony Tong <atong@trustedcs.com>
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <strings.h>
#endif

#if defined(USE_PCSC)
#define BOOL PCSC_BOOL
#include <PCSC/pcsclite.h>
#include <PCSC/reader.h>
#include <PCSC/winscard.h>
#undef BOOL
#else
#include <winscard.h>
#ifndef MAX_ATR_SIZE
#define MAX_ATR_SIZE 33
#endif
//#ifndef UINT32
//#define UINT32 UINT
//#endif
char* pcsc_stringify_error(const long pcscError);
#endif


#include <winpr/wtypes.h>
#include <winpr/crt.h>
#include <winpr/print.h>
#include <winpr/stream.h>

#include <freerdp/freerdp.h>
#include <freerdp/channels/rdpdr.h>
#include <freerdp/utils/svc_plugin.h>

#include "smartcard_main.h"

/* [MS-RDPESC] 3.1.4 */
#define SCARD_IOCTL_ESTABLISH_CONTEXT		0x00090014	/* EstablishContext */
#define SCARD_IOCTL_RELEASE_CONTEXT		0x00090018	/* ReleaseContext */
#define SCARD_IOCTL_IS_VALID_CONTEXT		0x0009001C	/* IsValidContext */
#define SCARD_IOCTL_LIST_READER_GROUPS_A		0x00090020	/* ListReaderGroupsA */
#define SCARD_IOCTL_LIST_READER_GROUPS_W		0x00090024	/* ListReaderGroupsW */
#define SCARD_IOCTL_LIST_READERS_A		0x00090028	/* ListReadersA */
#define SCARD_IOCTL_LIST_READERS_W		0x0009002C	/* ListReadersW */
#define SCARD_IOCTL_INTRODUCE_READER_GROUP_A	0x00090050	/* IntroduceReaderGroupA */
#define SCARD_IOCTL_INTRODUCE_READER_GROUP_W	0x00090054	/* IntroduceReaderGroupW */
#define SCARD_IOCTL_FORGET_READER_GROUP_A		0x00090058	/* ForgetReaderA */
#define SCARD_IOCTL_FORGET_READER_GROUP_W		0x0009005C	/* ForgetReaderW */
#define SCARD_IOCTL_INTRODUCE_READER_A		0x00090060	/* IntroduceReaderA */
#define SCARD_IOCTL_INTRODUCE_READER_W		0x00090064	/* IntroduceReaderW */
#define SCARD_IOCTL_FORGET_READER_A		0x00090068	/* IntroduceReaderA */
#define SCARD_IOCTL_FORGET_READER_W		0x0009006C	/* IntroduceReaderW */
#define SCARD_IOCTL_ADD_READER_TO_GROUP_A		0x00090070	/* AddReaderToGroupA */
#define SCARD_IOCTL_ADD_READER_TO_GROUP_W		0x00090074	/* AddReaderToGroupW */
#define SCARD_IOCTL_REMOVE_READER_FROM_GROUP_A	0x00090078	/* RemoveReaderFromGroupA */
#define SCARD_IOCTL_REMOVE_READER_FROM_GROUP_W	0x0009007C	/* RemoveReaderFromGroupW */
#define SCARD_IOCTL_GET_STATUS_CHANGE_A		0x000900A0	/* GetStatusChangeA */
#define SCARD_IOCTL_GET_STATUS_CHANGE_W		0x000900A4	/* GetStatusChangeW */
#define SCARD_IOCTL_CANCEL			0x000900A8	/* Cancel */
#define SCARD_IOCTL_CONNECT_A			0x000900AC	/* ConnectA */
#define SCARD_IOCTL_CONNECT_W			0x000900B0	/* ConnectW */
#define SCARD_IOCTL_RECONNECT			0x000900B4	/* Reconnect */
#define SCARD_IOCTL_DISCONNECT			0x000900B8	/* Disconnect */
#define SCARD_IOCTL_BEGIN_TRANSACTION		0x000900BC	/* BeginTransaction */
#define SCARD_IOCTL_END_TRANSACTION		0x000900C0	/* EndTransaction */
#define SCARD_IOCTL_STATE			0x000900C4	/* State */
#define SCARD_IOCTL_STATUS_A			0x000900C8	/* StatusA */
#define SCARD_IOCTL_STATUS_W			0x000900CC	/* StatusW */
#define SCARD_IOCTL_TRANSMIT			0x000900D0	/* Transmit */
#define SCARD_IOCTL_CONTROL			0x000900D4	/* Control */
#define SCARD_IOCTL_GETATTRIB			0x000900D8	/* GetAttrib */
#define SCARD_IOCTL_SETATTRIB			0x000900DC	/* SetAttrib */
#define SCARD_IOCTL_ACCESS_STARTED_EVENT	0x000900E0	/* SCardAccessStartedEvent */
#define SCARD_IOCTL_LOCATE_CARDS_BY_ATR		0x000900E8	/* LocateCardsByATR */

/* Decode Win CTL_CODE values */
#define WIN_CTL_FUNCTION(ctl_code)		((ctl_code & 0x3FFC) >> 2)
#define WIN_CTL_DEVICE_TYPE(ctl_code)		(ctl_code >> 16)

#define WIN_FILE_DEVICE_SMARTCARD		0x00000031

const char* ioctlToName(UINT ioctl_code);
const char* Stream_HexDump(wStream *s);

static UINT32 handle_CommonTypeHeader(SMARTCARD_DEVICE* scard, IRP* irp, size_t *inlen)
{
	static const int kCommonTypeHeaderLength = 8;
	UINT8 version;
	UINT8 endianess;
	UINT16 header_length;

	assert(scard);
	assert(irp);
	assert(irp->input);
	assert(inlen);

	if (Stream_GetRemainingLength(irp->input) < kCommonTypeHeaderLength)
	{
		DEBUG_ERROR("length violation %d [%d]\n%s", kCommonTypeHeaderLength, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}

#if defined(WITH_DEBUG_SCARD) && defined(DEBUG_SCARD_COMMON_HEADER)
	{
		char buf[2048] = {0};
		int x = 0;
		x += sprintf(&buf[x], "\nCommonTypeHeader\nCurrent offset: %#x\n", Stream_Pointer(irp->input)-Stream_Buffer(irp->input));
		x += winpr_HexDumpToBuffer(&buf[x], Stream_Pointer(irp->input), kCommonTypeHeaderLength);
		DEBUG_SCARD("%s", buf);
	}
#endif

	/* Process CommonTypeHeader */
	Stream_Read_UINT8(irp->input, version);
	Stream_Read_UINT8(irp->input, endianess);
	Stream_Read_UINT16(irp->input, header_length);
	Stream_Seek(irp->input, 4);

	DEBUG_SCARD("version: %#x endianess: %#x header_length: %#x", version , endianess, header_length);

	if (0x01 != version)
	{
		DEBUG_ERROR("unsupported header version %d\n%s", version, Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}
	if (0x10 != endianess)
	{
		DEBUG_ERROR("unsupported endianess %d\n%s", endianess, Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}
	if (0x08 != header_length)
	{
		DEBUG_ERROR("unsupported header length %d\n%s", header_length, Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}

	assert(*inlen >= kCommonTypeHeaderLength);
	*inlen -= kCommonTypeHeaderLength;

	DEBUG_SCARD("Consumed %d bytes", kCommonTypeHeaderLength);

	return 0;
}

static UINT32 handle_PrivateTypeHeader(SMARTCARD_DEVICE* scard, IRP* irp, size_t *inlen)
{
	static const int kPrivateTypeHeaderLength = 8;
	UINT32 len;

	assert(scard);
	assert(irp);
	assert(irp->input);
	assert(inlen);

	if (Stream_GetRemainingLength(irp->input) < kPrivateTypeHeaderLength)
	{
		DEBUG_ERROR("length violation %d [%d]\n%s", kPrivateTypeHeaderLength, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}

	/* Process PrivateTypeHeader */
	Stream_Read_UINT32(irp->input, len);
	Stream_Seek_UINT32(irp->input);

#if defined(WITH_DEBUG_SCARD) && defined(DEBUG_SCARD_PRIVATE_TYPE_HEADER)
	{
		char buf[2048] ={0};
		int x = 0;
		x += sprintf(&buf[x], "\nPrivate Header Length: %#x\nCurrent Stream Offset: %#x\n", len, Stream_Pointer(irp->input)-Stream_Buffer(irp->input));
		x += winpr_HexDumpToBuffer(&buf[x], Stream_Pointer(irp->input)-kPrivateTypeHeaderLength, len);
		DEBUG_SCARD("%s", buf);
	}
#endif

	/* Assure the remaining length is as expected. */
	if (len < Stream_GetRemainingLength(irp->input))
	{
		DEBUG_WARN("missing payload %d [%d]\n%s", len, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}

	assert(*inlen >= kPrivateTypeHeaderLength);
	*inlen -= kPrivateTypeHeaderLength;

	DEBUG_SCARD("Consumed %d bytes", kPrivateTypeHeaderLength);

	return 0;
}

/* Consumes 8 bytes */
static UINT32 handle_Context(SMARTCARD_DEVICE* scard, IRP* irp, size_t *inlen)
{
	UINT32 len;
	int bytesConsumed = 0;

	assert(scard);
	assert(irp);
	assert(irp->input);
	assert(inlen);

	if (Stream_GetRemainingLength(irp->input) < 4)
	{
		DEBUG_ERROR("length violation %d [%d]\n%s", 4, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}

	/* Process PrivateTypeHeader */
	Stream_Read_UINT32(irp->input, len); /* get length of header */
	bytesConsumed += 4;
	if (Stream_GetRemainingLength(irp->input) < len)
	{
		DEBUG_ERROR("length violation %d [%d]\n%s", len, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}

#if defined(WITH_DEBUG_SCARD) && defined(DEBUG_SCARD_DUMP_CONTEXT)
	{
		char buf[2048] ={0};
		int x = 0;
		x += sprintf(buf, "Context Dump: Offset: %#x\n", Stream_Pointer(irp->input)-Stream_Buffer(irp->input));
		x += winpr_HexDumpToBuffer(&buf[x], Stream_Pointer(irp->input)-4, len+bytesConsumed);
		DEBUG_SCARD("%s", buf);
	}
#endif

	Stream_Seek_UINT32(irp->input);
	bytesConsumed += 4;

#if defined(WITH_DEBUG_SCARD) && defined(DEBUG_SCARD_DUMP_CONTEXT)
	{
		char buf[2048] ={0};
		int x = 0;
		x += sprintf(&buf[x], "\nContext Header Length: %#x\nCurrent Stream Offset: %#x\n", len, Stream_Pointer(irp->input)-Stream_Buffer(irp->input));
		x += winpr_HexDumpToBuffer(&buf[x], Stream_Pointer(irp->input)-bytesConsumed, bytesConsumed);
		DEBUG_SCARD("%s", buf);
	}
#endif

	if (len > Stream_GetRemainingLength(irp->input))
	{
		DEBUG_ERROR("length violation %d [%d]\n%s", len, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}

	assert(*inlen >= bytesConsumed);
	*inlen -= bytesConsumed;

	DEBUG_SCARD("Consumed %d bytes", bytesConsumed);

	return 0;
}

/* Consumes 16 bytes */
static UINT32 handle_CardHandle(SMARTCARD_DEVICE* scard, IRP* irp, size_t *inlen)
{
	UINT32 status;
	UINT32 len;
	int bytesConsumed = 0;

	assert(scard);
	assert(irp);
	assert(irp->input);
	assert(inlen);

	status = handle_Context(scard, irp, inlen); /* consumes 8 bytes */
	if (status)
		return status;

	if (Stream_GetRemainingLength(irp->input) < 4)
	{
		DEBUG_WARN("length violation %d [%d]\n%s", 4, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Read_UINT32(irp->input, len); /* handle size */
	bytesConsumed += 4;
	if (Stream_GetRemainingLength(irp->input) < len)
	{
		DEBUG_WARN("length violation %d [%d]\n%s", len, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Seek_UINT32(irp->input); /* skip over the card handle ptr */
	bytesConsumed += 4;

#if defined(WITH_DEBUG_SCARD) && defined(DEBUG_SCARD_DUMP_CARD_HANDLE)
	{
		char buf[2048] = {0};
		int x = 0;
		x += sprintf(&buf[x], "\nCard Handle Length: %#x\nCurrent Stream Offset: %#x\n", len, Stream_Pointer(irp->input)-Stream_Buffer(irp->input));
		x += winpr_HexDumpToBuffer(&buf[x], Stream_Pointer(irp->input)-bytesConsumed, bytesConsumed);
		DEBUG_SCARD("%s", buf);
	}
#endif

	assert(*inlen >= bytesConsumed);
	*inlen -= bytesConsumed;

	DEBUG_SCARD("Consumed %d bytes", bytesConsumed);

	return 0;
}

/* Consumes 8 bytes 32bit or 12 bytes 64bit */
static UINT32 handle_RedirContextRef(SMARTCARD_DEVICE* scard, IRP* irp,
		size_t *inlen, SCARDCONTEXT* hContext)
{
	UINT32 len;
	int bytesConsumed = 0;

	assert(scard);
	assert(irp);
	assert(irp->input);
	assert(inlen);
	assert(hContext);

	/* Extract context handle. */
	if (Stream_GetRemainingLength(irp->input) < 4)
	{
		DEBUG_ERROR("length violation %d [%d] - expecting 4 bytes for context handle size\n%s", 4, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}

	//DEBUG_SCARD("Offset before size read: %#x", Stream_Pointer(irp->input)-Stream_Buffer(irp->input));
	Stream_Read_UINT32(irp->input, len);
	bytesConsumed += 4;
	//DEBUG_SCARD("Offset after size read:  %#x", Stream_Pointer(irp->input)-Stream_Buffer(irp->input));
	if (len != 4 && len != 8)
	{
		//TODO (nik) fix warning message, last parameter
		//DEBUG_WARN("length violation %d [%d] - context size should be 4 or 8 bytes", len, sizeof(*hContext));
		DEBUG_ERROR("length violation %d [%d] - context size should be 4 or 8 bytes\n%s", len, sizeof(*hContext), Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}

	DEBUG_SCARD("Context size: %#x", len);
	switch(len) {
	case 4:
		Stream_Read_UINT32(irp->input, *hContext);
		break;

	case 8:
		Stream_Read_UINT64(irp->input, *hContext);
		break;

	default:
		DEBUG_ERROR("length violation %d [%d]", len, Stream_GetRemainingLength(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}

	bytesConsumed += len;

#if defined(WITH_DEBUG_SCARD) && defined(DEBUG_SCARD_DUMP_CARD_REF)
	{
		char buf[2048] = {0};
		int x = 0;
		x += sprintf(&buf[x], "\nContext Handle Length: %#x\nCurrent Stream Offset: %#x\n", len, Stream_Pointer(irp->input)-Stream_Buffer(irp->input));
		x += winpr_HexDumpToBuffer(&buf[x], Stream_Pointer(irp->input)-bytesConsumed, bytesConsumed);
		DEBUG_SCARD("%s", buf);
	}
#endif

	DEBUG_SCARD("hContext=0x%p", *hContext);

	//assert(*inlen >= bytesConsumed);
	if (*inlen < bytesConsumed) {
		DEBUG_WARN("bufer check? inlen: %#x bytesConsumed: %#x", inlen, bytesConsumed);
	}
	*inlen -= bytesConsumed;

	DEBUG_SCARD("Consumed %d bytes", bytesConsumed);

	return 0;
}

/* Consumes 8 bytes 32bit or 12 bytes 64bit */
static UINT32 handle_RedirHandleRef(SMARTCARD_DEVICE* scard, IRP* irp,
		size_t *inlen, SCARDCONTEXT* hContext, SCARDHANDLE *hHandle)
{
	UINT32 len, status;
	int bytesConsumed = 0;

	status = handle_RedirContextRef(scard, irp, inlen, hContext);
	if (status)
		return status;

	/* validate presence of handle size */
	if (Stream_GetRemainingLength(irp->input) < 4)
	{
		DEBUG_ERROR("length violation %d [%d]\n%s", 4, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Read_UINT32(irp->input, len);
	bytesConsumed += 4;
	if (len != 4 && len != 8)
	{
		//DEBUG_WARN("length violation %d [%d]", len, sizeof(*hHandle));
		DEBUG_ERROR("length violation %d [%d] - context size should be 4 or 8 bytes\n%s", len, sizeof(*hContext), Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}

	if (Stream_GetRemainingLength(irp->input) < len)
	{
		DEBUG_ERROR("length violation %d [%d]\n%s", len, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}

	DEBUG_SCARD("Card Handle size: %#x", len);
	switch (len) {
	case 4:
		Stream_Read_UINT32(irp->input, *hHandle);
		break;

	case 8:
		Stream_Read_UINT64(irp->input, *hHandle);
		break;

	default:
		return SCARD_F_INTERNAL_ERROR;
	}

	bytesConsumed += len;

#if defined(WITH_DEBUG_SCARD) && defined(DEBUG_SCARD_DUMP_REDIR_HANDLE)
	{
		char buf[2048] = {0};
		int x = 0;

		x += sprintf(&buf[x], "\nCard Handle Length: %#x\nCurrent Stream Offset: %#x\n", len, Stream_Pointer(irp->input)-Stream_Buffer(irp->input));
		x += winpr_HexDumpToBuffer(&buf[x], Stream_Pointer(irp->input)-bytesConsumed, bytesConsumed);
		DEBUG_SCARD("%s", buf);
	}
#endif

DEBUG_SCARD("hCard=0x%p", *hHandle);

	assert(*inlen >= bytesConsumed);
	*inlen -= bytesConsumed;

	DEBUG_SCARD("Consumed %d bytes", bytesConsumed);
	return 0;
}

static BOOL check_reader_is_forwarded(SMARTCARD_DEVICE *scard, const char *readerName)
{
	BOOL rc = TRUE;
	char *name = _strdup(readerName);
	char *str, *strpos=NULL, *strstatus=NULL;
	long pos, status, cpos, ret;

	assert(scard);
	assert(readerName);

	/* Extract the name, position and status from the data provided. */
	str = strtok(name, " ");
	while(str)
	{
		strpos = strstatus;
		strstatus = str;
		str = strtok(NULL, " ");
	} 

	if (!strpos)
		goto finally;

	pos = strtol(strpos, NULL, 10);
	
	if ( strpos && strstatus )
	{
		/* Check, if the name of the reader matches. */
		if (scard->name &&  strncmp(scard->name, readerName, strlen(scard->name)))
			rc = FALSE;

		/* Check, if the position matches. */
		if (scard->path)
		{
			ret = sscanf(scard->path, "%ld", &cpos);
			if ((1 == ret) && (cpos != pos))
				rc = FALSE;
		}
	}
	else
		DEBUG_WARN("unknown reader format '%s'", readerName);

finally:
	free(name);

	if (!rc)
		DEBUG_WARN("reader '%s' not forwarded", readerName);
	
	return rc;
}

static BOOL check_handle_is_forwarded(SMARTCARD_DEVICE *scard,
		SCARDHANDLE hCard, SCARDCONTEXT hContext)
{
	BOOL rc = FALSE;
	LONG status;
	DWORD state = 0, protocol = 0;
	DWORD readerLen;
	DWORD atrLen = MAX_ATR_SIZE;
	char* readerName = NULL;
	BYTE pbAtr[MAX_ATR_SIZE];

	assert(scard);
	assert(hCard);

#ifdef SCARD_AUTOALLOCATE
	readerLen = SCARD_AUTOALLOCATE;
#else
	readerLen = 256;
	readerName = malloc(readerLen);
#endif

	status = SCardStatusA(hCard, (LPSTR) &readerName, &readerLen, &state, &protocol, pbAtr, &atrLen);
	if (status == SCARD_S_SUCCESS)
	{
		rc = check_reader_is_forwarded(scard, readerName);
		if (!rc)
			DEBUG_WARN("Reader '%s' not forwarded!", readerName);
	}

#ifdef SCARD_AUTOALLOCATE
	SCardFreeMemory(hContext, readerName);
#else
	free(readerName);
#endif

	return rc;
}

static UINT32 smartcard_output_string(IRP* irp, char* src, BOOL wide)
{
	BYTE* p;
	UINT32 len;

	p = Stream_Pointer(irp->output);
	len = strlen(src) + 1;

	if (wide)
	{
		int i;

		for (i = 0; i < len; i++ )
		{
			p[2 * i] = src[i] < 0 ? '?' : src[i];
			p[2 * i + 1] = '\0';
		}

		len *= 2;
	}
	else
	{
		memcpy(p, src, len);
	}

	Stream_Seek(irp->output, len);
	return len;
}

static UINT32 smartcard_output_stringW(IRP* irp, const wchar_t* src, int length)
{
	length += 2; /*unicode null*/
	Stream_Write(irp->output, src, length);
	return length;
}


static void smartcard_output_alignment(IRP* irp, UINT32 seed)
{
	const UINT32 field_lengths = 20;/* Remove the lengths of the fields
					 * RDPDR_HEADER, DeviceID,
					 * CompletionID, and IoStatus
					 * of Section 2.2.1.5.5 of MS-RDPEFS.
					 */
	UINT32 size = Stream_GetPosition(irp->output) - field_lengths;
	UINT32 add = (seed - (size % seed)) % seed;

	if (add > 0) {
		DEBUG_SCARD("Adding %d pad bytes to output stream", add);
		Stream_Zero(irp->output, add);
	}
}

static void smartcard_output_repos(IRP* irp, UINT32 written)
{
	UINT32 add = (4 - (written % 4)) % 4;

	if (add > 0) {
		DEBUG_SCARD("Adding %d pad bytes to output stream", add );
		Stream_Zero(irp->output, add);
	}
}

static UINT32 smartcard_output_return(IRP* irp, UINT32 status)
{
	Stream_Zero(irp->output, 256);
	return status;
}

static void smartcard_output_buffer_limit(IRP* irp, char* buffer, unsigned int length, unsigned int highLimit)
{
	int header = (length < 0) ? (0) : ((length > highLimit) ? (highLimit) : (length));

	Stream_Write_UINT32(irp->output, header);

	if (length <= 0)
	{
		Stream_Write_UINT32(irp->output, 0);
	}
	else
	{
		assert(NULL != buffer);
		if (header < length)
			length = header;

		Stream_Write(irp->output, buffer, length);
		smartcard_output_repos(irp, length);
	}
}

static void smartcard_output_buffer(IRP* irp, char* buffer, unsigned int length)
{
	smartcard_output_buffer_limit(irp, buffer, length, 0x7FFFFFFF);
}

static void smartcard_output_buffer_start_limit(IRP* irp, int length, int highLimit)
{
	int header = (length < 0) ? (0) : ((length > highLimit) ? (highLimit) : (length));

	Stream_Write_UINT32(irp->output, header);
	Stream_Write_UINT32(irp->output, 0x00000001);	/* Magic DWORD - any non zero */
}

static void smartcard_output_buffer_start(IRP* irp, int length)
{
	smartcard_output_buffer_start_limit(irp, length, 0x7FFFFFFF);
}

static UINT32 smartcard_input_string(IRP* irp, char** dest, UINT32 dataLength, BOOL wide)
{
	char* buffer;
	size_t bufferSize;

	bufferSize = wide ? (2 * dataLength) : dataLength;
	buffer = (char*)malloc(bufferSize + 2); /* reserve 2 bytes for the '\0' */

	Stream_Read(irp->input, buffer, bufferSize);

	if (wide)
	{
		int i;
		for (i = 0; i < dataLength; i++)
		{
			if ((buffer[2 * i] < 0) || (buffer[2 * i + 1] != 0))
				buffer[i] = '?';
			else
				buffer[i] = buffer[2 * i];
		}
	}

	buffer[dataLength] = '\0';
	*dest = buffer;

	return bufferSize;
}

static void smartcard_input_repos(IRP* irp, UINT32 read)
{
	UINT32 add = 4 - (read % 4);

	if (add < 4 && add > 0) {
		DEBUG_SCARD("Seeking pad bytes: %d", add);
		Stream_Seek(irp->input, add);
	}
}

static UINT32 smartcard_input_reader_name(IRP* irp, char** dest, BOOL wide)
{
	UINT32 dataLength;

	assert(irp);
	assert(dest);

	if (Stream_GetRemainingLength(irp->input) < 12)
	{
		DEBUG_ERROR("length violation %d [%d] - expecting 12 more bytes in stream\n%s", 12, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Seek(irp->input, 8);
	Stream_Read_UINT32(irp->input, dataLength);

	if (Stream_GetRemainingLength(irp->input) < dataLength)
	{
		DEBUG_ERROR("length violation %d [%d]\n%s", dataLength, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}

	DEBUG_SCARD("datalength %d", dataLength);
	smartcard_input_repos(irp, smartcard_input_string(irp, dest, dataLength, wide));

	return 0;
}

static UINT32 smartcard_map_state(UINT32 state)
{
	/* is this mapping still needed? */

	if (state & SCARD_SPECIFIC)
		state = 0x00000006;
	else if (state & SCARD_NEGOTIABLE)
		state = 0x00000006;
	else if (state & SCARD_POWERED)
		state = 0x00000004;
	else if (state & SCARD_SWALLOWED)
		state = 0x00000003;
	else if (state & SCARD_PRESENT)
		state = 0x00000002;
	else if (state & SCARD_ABSENT)
		state = 0x00000001;
	else
		state = 0x00000000;

	return state;
}

static const char* SCOPE_DESC[] = {"SCARD_SCOPE_USER","SCARD_SCOPE_TERMINAL","SCARD_SCOPE_SYSTEM",""};
static UINT32 handle_EstablishContext(SMARTCARD_DEVICE* scard, IRP* irp, size_t inlen)
{
	UINT32 status;
	UINT32 scope;
	int s = 0;
	SCARDCONTEXT hContext = -1;

	status = handle_CommonTypeHeader(scard, irp, &inlen);
	if (status)
		return status;

	status = handle_PrivateTypeHeader(scard, irp, &inlen);
	if (status)
		return status;

	/* Ensure, that the capacity expected is actually available. */
	if (Stream_GetRemainingLength(irp->input) < 4)
	{
		DEBUG_ERROR("length violation %d [%d]\n%s", 4, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}

	/* Read the scope from the stream. */
	Stream_Read_UINT32(irp->input, scope);

	/*SCARD_SCOPE_USER -> 0   */
	/*SCARD_SCOPE_SYSTEM -> 2 */

	DEBUG_SCARD("scope: %s", SCOPE_DESC[scope]);

	status = SCardEstablishContext(scope, NULL, NULL, &hContext);

	Stream_Write_UINT32(irp->output, sizeof(hContext));	// cbContext
	Stream_Write_UINT32(irp->output, 0x020000); /* NDR offset ptr */

	Stream_Write_UINT32(irp->output, sizeof(hContext));

	switch(sizeof(hContext)) {
	case 4:
		Stream_Write_UINT32(irp->output, hContext);
		break;

	case 8:
		Stream_Write_UINT64(irp->output, hContext);
		break;
	}

	DEBUG_SCARD("hContext: 0x%p", hContext);

	/* TODO: store hContext in allowed context list */
	if (SCARD_S_SUCCESS != status) {
		DEBUG_ERROR("%s (0x%08x)", pcsc_stringify_error(status), (unsigned) status);
	}

	smartcard_output_alignment(irp, 8);
	return status;
}

static UINT32 handle_ReleaseContext(SMARTCARD_DEVICE* scard, IRP* irp, size_t inlen)
{
	UINT32 status;
	SCARDCONTEXT hContext = -1;

	status = handle_CommonTypeHeader(scard, irp, &inlen);
	if (status)
		return status;

	status = handle_PrivateTypeHeader(scard, irp, &inlen);
	if (status)
		return status;

	status = handle_Context(scard, irp, &inlen);
	if (status)
		return status;

	status = handle_RedirContextRef(scard, irp, &inlen, &hContext);
	if (status)
		return status;

	status = SCardReleaseContext(hContext);

	if (status) {
		DEBUG_ERROR("%s (0x%08x)", pcsc_stringify_error(status), (unsigned) status);
	} else {
		DEBUG_SCARD("success 0x%p", hContext);
	}

	smartcard_output_alignment(irp, 8);

	return status;
}

static UINT32 handle_IsValidContext(SMARTCARD_DEVICE* scard, IRP* irp, size_t inlen)
{
	UINT32 status;
	SCARDCONTEXT hContext;

	status = handle_CommonTypeHeader(scard, irp, &inlen);
	if (status)
		return status;

	status = handle_PrivateTypeHeader(scard, irp, &inlen);
	if (status)
		return status;

	status = handle_Context(scard, irp, &inlen);
	if (status)
		return status;

	status = handle_RedirContextRef(scard, irp, &inlen, &hContext);
	if (status)
		return status;

	status = SCardIsValidContext(hContext);

	if (status) {
		DEBUG_ERROR("Failure: %s (0x%08x)", pcsc_stringify_error(status), (unsigned) status);
	} else {
		DEBUG_SCARD("Success context: 0x%08x", (unsigned) hContext);
	}

	smartcard_output_alignment(irp, 8);

	return status;
}

static UINT32 handle_ListReaders(SMARTCARD_DEVICE* scard, IRP* irp,
		size_t inlen, BOOL wide)
{
	UINT32 status;
	SCARDCONTEXT hContext;
	DWORD dwReaders = 0;
	UINT32 readersIsNull;
	char *readerList = NULL, *walker;
	DWORD elemLength, dataLength;
	int pos, poslen1, poslen2, allowed_pos;

	status = handle_CommonTypeHeader(scard, irp, &inlen);
	if (status)
		goto finish;

	status = handle_PrivateTypeHeader(scard, irp, &inlen);
	if (status)
		goto finish;

	status = handle_Context(scard, irp, &inlen);
	if (status)
		goto finish;

	/* Ensure, that the capacity expected is actually available. */
	if (Stream_GetRemainingLength(irp->input) < 0x10)
	{
		DEBUG_ERROR("length violation %d [%d]\n%s", 0x10, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		status = SCARD_F_INTERNAL_ERROR;
		goto finish;
	}

	/* UINT32 NumBytes */
	/* UINT32 ptrGroups */
	Stream_Seek(irp->input, 8);
	/* UINT32 readersIsNull */
	Stream_Read_UINT32(irp->input, readersIsNull);
	/* UINT32 unused */
	Stream_Seek(irp->input, 4);

	/* Read RedirScardcontextRef */
	status = handle_RedirContextRef(scard, irp, &inlen, &hContext);
	if (status)
		goto finish;

	/* ignore rest of [MS-RDPESC] 2.2.2.4 ListReaders_Call */

	if (readersIsNull == 1) {
		status = SCardListReadersA(hContext, NULL, NULL, &dataLength);
		DEBUG_SCARD("Requesting size only. Size: %#x", dataLength);
	} else {
#ifdef SCARD_AUTOALLOCATE
		dwReaders = SCARD_AUTOALLOCATE;
		status = SCardListReadersA(hContext, NULL, (LPSTR) &readerList, &dwReaders);
#else
		status = SCardListReadersA(hContext, NULL, NULL, &dwReaders);

		readerList = malloc(dwReaders);
		status = SCardListReadersA(hContext, NULL, readerList, &dwReaders);
#endif
	}

	if (status != SCARD_S_SUCCESS)
	{
		DEBUG_ERROR("Failure: %s (0x%08x)", pcsc_stringify_error(status), (unsigned) status);
		goto finish;
	} else {
		DEBUG_SCARD("SCardListReadersA Success. Context: %p", hContext);
	}

/*	DEBUG_SCARD("Success 0x%08x %d %d", (unsigned) hContext, (unsigned) cchReaders, (int) strlen(readerList));*/

	poslen1 = Stream_GetPosition(irp->output);
	Stream_Seek_UINT32(irp->output);

	//TODO (nik) What is this???
	//Stream_Write_UINT32(irp->output, 0x01760650);
	Stream_Write_UINT32(irp->output, 0x0020000); /* NDR offset ptr */

	poslen2 = Stream_GetPosition(irp->output);
	Stream_Seek_UINT32(irp->output);

	if (readersIsNull == 0 ) {
		walker = readerList;
		dataLength = 0;

		/* Smartcards can be forwarded by position and name. */
		allowed_pos = -1;
		if (scard->path)
			if (1 != sscanf(scard->path, "%d", &allowed_pos))
				allowed_pos = -1;

		pos = 0;
		while (1)
		{
			elemLength = strlen(walker);
			if (elemLength == 0)
				break;

			DEBUG_SCARD("Reader: %s", walker);
			/* Ignore readers not forwarded. */
			if ((allowed_pos < 0) || (pos == allowed_pos))
			{
				if (!scard->name || strstr(walker, scard->name)) {
					DEBUG_SCARD("Adding Reader: [%#x] %s", elemLength, walker);
					dataLength += smartcard_output_string(irp, walker, wide);
				}
			}
			walker += elemLength + 1;
			pos ++;
		}
	} else {
		Stream_Zero(irp->output, dataLength);
	}

	// TODO (nik) is the value of wide really needed here?  This is sending a 1 byte null?
	//dataLength += smartcard_output_string(irp, "\0", wide);
	dataLength += smartcard_output_string(irp, "\0", 0);

	pos = Stream_GetPosition(irp->output);

	Stream_SetPosition(irp->output, poslen1);
	Stream_Write_UINT32(irp->output, dataLength);
	Stream_SetPosition(irp->output, poslen2);
	Stream_Write_UINT32(irp->output, dataLength);

	Stream_SetPosition(irp->output, pos);

	smartcard_output_repos(irp, dataLength);
	smartcard_output_alignment(irp, 8);

finish:
	if (readerList)
	{
#ifdef SCARD_AUTOALLOCATE
		SCardFreeMemory(hContext, readerList);
#else
		free(readerList);
#endif
	}

	return status;
}

static UINT32 handle_ListReadersW(SMARTCARD_DEVICE* scard, IRP* irp, size_t inlen)
{
	UINT32 status;
	SCARDCONTEXT hContext;
	DWORD dwReaders;
	wchar_t *readerList = NULL, *walker;
	DWORD elemLength, dataLength;
	int pos, poslen1, poslen2, allowed_pos;
	wchar_t scardName[512] = {0};
	UINT32 readersIsNull;

	status = handle_CommonTypeHeader(scard, irp, &inlen);
	if (status)
		goto finish;

	status = handle_PrivateTypeHeader(scard, irp, &inlen);
	if (status)
		goto finish;

	status = handle_Context(scard, irp, &inlen);
	if (status)
		goto finish;

	/* Ensure, that the capacity expected is actually available. */
	if (Stream_GetRemainingLength(irp->input) < 0x10)
	{
		DEBUG_ERROR("length violation %d [%d]%s\n", 0x10, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		status = SCARD_F_INTERNAL_ERROR;
		goto finish;
	}

#if defined(WITH_DEBUG_SCARD) && 0
	{
		char buf[2048] = {0};
		int x = 0;

		x = sprintf(buf, "Buffer before context: (0x10)\nOffset: %#x\n", Stream_Pointer(irp->input)-Stream_Buffer(irp->input));
		x += winpr_HexDumpToBuffer(&buf[x], Stream_Pointer(irp->input), 0x10);
		DEBUG_SCARD("%s", buf);
	}
#endif

	/* UINT32 NumBytes */
	/* UINT32 ptrGroups */
	Stream_Seek(irp->input, 8);
	/* UINT32 readersIsNull */
	Stream_Read_UINT32(irp->input, readersIsNull);
	/* UINT32 unused */
	Stream_Seek(irp->input, 4);

	/* Read RedirScardcontextRef */
	status = handle_RedirContextRef(scard, irp, &inlen, &hContext);
	if (status)
		goto finish;

	/* ignore rest of [MS-RDPESC] 2.2.2.4 ListReaders_Call */

	if (readersIsNull == 1 ) {
		status = SCardListReadersW(hContext, NULL, NULL, &dataLength);
		DEBUG_SCARD("Requesting size only. Size: %#x", dataLength);
	} else {
#ifdef SCARD_AUTOALLOCATE
		dwReaders = SCARD_AUTOALLOCATE;
		status = SCardListReadersW(hContext, NULL, (LPWSTR) &readerList, &dwReaders);
#else
		status = SCardListReadersW(hContext, NULL, NULL, &dwReaders);

		readerList = malloc(dwReaders);
		status = SCardListReadersW(hContext, NULL, readerList, &dwReaders);
#endif
	}

	if (status != SCARD_S_SUCCESS)
	{
		DEBUG_ERROR("Failure: %s (0x%08x)", pcsc_stringify_error(status), (unsigned) status);
		goto finish;
	} else {
		DEBUG_SCARD("SCardListReadersW Success. Context: %p", hContext);
	}

/*	DEBUG_SCARD("Success 0x%08x %d %d", (unsigned) hContext, (unsigned) cchReaders, (int) strlen(readerList));*/

	poslen1 = Stream_GetPosition(irp->output);
	Stream_Seek_UINT32(irp->output);

	//TODO (nik) What is for????
	//Stream_Write_UINT32(irp->output, 0x01760650);
	Stream_Write_UINT32(irp->output, 0x0020000); /* ndr array offset */

	poslen2 = Stream_GetPosition(irp->output);
	Stream_Seek_UINT32(irp->output);

	if (readersIsNull == 0) {
		walker = readerList;
		dataLength = 2;

		/* Smartcards can be forwarded by position and name. */
		allowed_pos = -1;
		if (scard->path)
			if (1 != sscanf(scard->path, "%d", &allowed_pos))
				allowed_pos = -1;

		mbstowcs(scardName, scard->name, 512);
		pos = 0;
		while (1)
		{
			int byteLength = 0;
			elemLength = wcslen(walker);
			if (elemLength == 0)
				break;

			byteLength = (elemLength+1)*2;

			DEBUG_SCARD("Reader: %S", walker);
			/* Ignore readers not forwarded. */
			if ((allowed_pos < 0) || (pos == allowed_pos))
			{
				if (!scard->name || wcsstr(walker, scardName)) {
					DEBUG_SCARD("Adding Reader: [%#x] %S", byteLength, walker);
					Stream_Write(irp->output, walker, byteLength);
					/*
					{
						int pad = (-byteLength)&3;
						DEBUG_SCARD("Padding byteLength with %d bytes", pad);
						Stream_Zero(irp->output, pad);
						byteLength += pad;
					}
					*/
					dataLength += byteLength;
				}
			}
			walker += elemLength + 1;
			pos ++;
		}
	} else {
		Stream_Zero(irp->output, dataLength);
	}

	//TODO (nik) does the spec call for a wide null here?
	//dataLength += smartcard_output_string(irp, "\0", FALSE);
	//dataLength += 2;
	//Stream_Write_UINT16(irp->output, 0x0000);

	DEBUG_SCARD("datalength: %d", dataLength);

	pos = Stream_GetPosition(irp->output);

	Stream_SetPosition(irp->output, poslen1);
	Stream_Write_UINT32(irp->output, dataLength);
	Stream_SetPosition(irp->output, poslen2);
	Stream_Write_UINT32(irp->output, dataLength);

	Stream_SetPosition(irp->output, pos);

	smartcard_output_repos(irp, dataLength);
	smartcard_output_alignment(irp, 8);

finish:
	if (readerList)
	{
#ifdef SCARD_AUTOALLOCATE
		SCardFreeMemory(hContext, readerList);
#else
		free(readerList);
#endif
	}

	return status;
}

static UINT32 handle_GetStatusChange(SMARTCARD_DEVICE* scard, IRP* irp, size_t inlen, BOOL wide)
{
	int i;
	LONG status;
	SCARDCONTEXT hContext;
	DWORD dwTimeout = 0;
	DWORD readerCount = 0;
	SCARD_READERSTATEA *readerStates = NULL, *cur;

	status = handle_CommonTypeHeader(scard, irp, &inlen);
	if (status)
		goto finish;

	status = handle_PrivateTypeHeader(scard, irp, &inlen);
	if (status)
		goto finish;

	status = handle_Context(scard, irp, &inlen);
	if (status)
		goto finish;

	/* Ensure, that the capacity expected is actually available. */
	if (Stream_GetRemainingLength(irp->input) < 12)
	{
		DEBUG_ERROR("length violation %d [%d]\n%s", 12, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		status =SCARD_F_INTERNAL_ERROR;
		goto finish;
	}

	Stream_Read_UINT32(irp->input, dwTimeout);
	Stream_Read_UINT32(irp->input, readerCount);
	Stream_Seek_UINT32(irp->input); /* Skip 4 bytes following reader count */

	/* Get context */
	status = handle_RedirContextRef(scard, irp, &inlen, &hContext);
	if (status)
		goto finish;

	/* Skip ReaderStateConformant */
	if (Stream_GetRemainingLength(irp->input) < 4 )
	{
		DEBUG_ERROR("length violation %d [%d]\n%s", 4, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		status = SCARD_F_INTERNAL_ERROR;
		goto finish;
	}
	Stream_Seek(irp->input, 4);

	DEBUG_SCARD("context: 0x%08x, timeout: 0x%08x, count: %d", (unsigned) hContext, (unsigned) dwTimeout, (int) readerCount);

	if (readerCount > 0)
	{
		readerStates = (PSCARD_READERSTATEA)malloc(readerCount * sizeof(SCARD_READERSTATEA));
		ZeroMemory(readerStates, readerCount * sizeof(SCARD_READERSTATEA));

		for (i = 0; i < readerCount; i++)
		{
			cur = &readerStates[i];

			if (Stream_GetRemainingLength(irp->input) < 52 )
			{
				DEBUG_ERROR("length violation %d [%d]\n%s", 52, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
				status = SCARD_F_INTERNAL_ERROR;
				goto finish;
			}

			Stream_Seek(irp->input, 4);

			/*
			 * TODO: on-wire is little endian; need to either
			 * convert to host endian or fix the headers to
			 * request the order we want
			 */
			Stream_Read_UINT32(irp->input, cur->dwCurrentState);
			Stream_Read_UINT32(irp->input, cur->dwEventState);
			Stream_Read_UINT32(irp->input, cur->cbAtr);
			Stream_Read(irp->input, cur->rgbAtr, 32);

			Stream_Seek(irp->input, 4);

			/* reset high bytes? */
			cur->dwCurrentState &= 0x0000FFFF;
			cur->dwEventState = 0;
		}

		DEBUG_SCARD("Loading reader states");
		for (i = 0; i < readerCount; i++)
		{
			UINT32 dataLength;
			cur = &readerStates[i];

			if (Stream_GetRemainingLength(irp->input) < 12 )
			{
				DEBUG_ERROR("length violation %d [%d]", 12, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
				status = SCARD_F_INTERNAL_ERROR;
				goto finish;
			}

			Stream_Seek(irp->input, 8);
			Stream_Read_UINT32(irp->input, dataLength);

			if (Stream_GetRemainingLength(irp->input) < dataLength )
			{
				DEBUG_ERROR("length violation %d [%d]\n%s", dataLength, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
				status = SCARD_F_INTERNAL_ERROR;
				goto finish;
			}
			smartcard_input_repos(irp, smartcard_input_string(irp, (char **) &cur->szReader, dataLength, wide));

			DEBUG_SCARD("[%d] \"%s\" user: 0x%08x, state: 0x%08x, event: 0x%08x", i, cur->szReader ? cur->szReader : "NULL", (unsigned) cur->pvUserData, (unsigned) cur->dwCurrentState, (unsigned) cur->dwEventState);

			if (!cur->szReader)
			{
				DEBUG_WARN("cur->szReader=%p", cur->szReader);
				continue;
			}
			if (strcmp(cur->szReader, "\\\\?PnP?\\Notification") == 0)
				cur->dwCurrentState |= SCARD_STATE_IGNORE;
		}
	}
	else
	{
		readerStates = NULL;
	}

	status = SCardGetStatusChangeA(hContext, (DWORD) dwTimeout, readerStates, (DWORD) readerCount);

	if (status != SCARD_S_SUCCESS) {
		DEBUG_ERROR("SCardGetStatusChange: Failure: %s (0x%08x)", pcsc_stringify_error(status), (unsigned) status);
	} else {
		DEBUG_SCARD("SCardGetStatusChange: Success Context: %p", hContext);
	}

	Stream_Write_UINT32(irp->output, readerCount);
	//TODO (nik) What is the for? Why a hardcoded value?
	// I don't see this defined in the MS-RDPESC IDL?
	//Stream_Write_UINT32(irp->output, 0x00084dd8);
	Stream_Write_UINT32(irp->output, 0x00020000);
	Stream_Write_UINT32(irp->output, readerCount);

	for (i = 0; i < readerCount; i++)
	{
		cur = &readerStates[i];

		DEBUG_SCARD("Setting resposne values \"%s\"\n\tuser: 0x%08x, state: 0x%08x, event: 0x%08x", cur->szReader ? cur->szReader : "NULL", (unsigned) cur->pvUserData, (unsigned) cur->dwCurrentState, (unsigned) cur->dwEventState);

		/* TODO: do byte conversions if necessary */
		Stream_Write_UINT32(irp->output, cur->dwCurrentState);
		Stream_Write_UINT32(irp->output, cur->dwEventState);
		Stream_Write_UINT32(irp->output, cur->cbAtr);
		Stream_Write(irp->output, cur->rgbAtr, cur->cbAtr);

		/* pad up to 36 bytes */
		Stream_Zero(irp->output, 36-cur->cbAtr);

		free((void *)cur->szReader);
	}

	smartcard_output_alignment(irp, 8);

finish:
	if (readerStates)
		free(readerStates);

	return status;
}

static UINT32 handle_GetStatusChangeW(SMARTCARD_DEVICE* scard, IRP* irp, size_t inlen)
{
	int i;
	LONG status;
	SCARDCONTEXT hContext;
	DWORD dwTimeout = 0;
	DWORD readerCount = 0;
	SCARD_READERSTATE *readerStates = NULL, *cur;

	status = handle_CommonTypeHeader(scard, irp, &inlen);
	if (status)
		goto finish;

	status = handle_PrivateTypeHeader(scard, irp, &inlen);
	if (status)
		goto finish;

	status = handle_Context(scard, irp, &inlen);
	if (status)
		goto finish;

	/* Ensure, that the capacity expected is actually available. */
	if (Stream_GetRemainingLength(irp->input) < 12)
	{
		DEBUG_WARN("length violation %d [%d] - expecting 12 more bytes in stream\n%s", 12, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		status =SCARD_F_INTERNAL_ERROR;
		goto finish;
	}

	Stream_Read_UINT32(irp->input, dwTimeout);
	Stream_Read_UINT32(irp->input, readerCount);
	Stream_Seek_UINT32(irp->input);

	/* Get context */
	status = handle_RedirContextRef(scard, irp, &inlen, &hContext);
	if (status)
		goto finish;

	/* Skip ReaderStateConformant */
	if (Stream_GetRemainingLength(irp->input) < 4 )
	{
		DEBUG_ERROR("length violation %d [%d] - expecting 4 more bytes in the stream\n%s", 4, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		status = SCARD_F_INTERNAL_ERROR;
		goto finish;
	}
	Stream_Seek(irp->input, 4);

	DEBUG_SCARD("context: 0x%p timeout: 0x%08x, count: %d", hContext, dwTimeout, readerCount);

	if (readerCount > 0)
	{
		readerStates = (PSCARD_READERSTATEW)malloc(readerCount * sizeof(SCARD_READERSTATEW));
		ZeroMemory(readerStates, readerCount * sizeof(SCARD_READERSTATEW));

		for (i = 0; i < readerCount; i++)
		{
			cur = &readerStates[i];

			if (Stream_GetRemainingLength(irp->input) < 52 )
			{
				DEBUG_ERROR("length violation %d [%d] - expecting 52 more bytes in the stream\n%s", 52, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
				status = SCARD_F_INTERNAL_ERROR;
				goto finish;
			}

			Stream_Seek(irp->input, 4);

			/*
			 * TODO: on-wire is little endian; need to either
			 * convert to host endian or fix the headers to
			 * request the order we want
			 */
			Stream_Read_UINT32(irp->input, cur->dwCurrentState);
			Stream_Read_UINT32(irp->input, cur->dwEventState);
			Stream_Read_UINT32(irp->input, cur->cbAtr);
			Stream_Read(irp->input, cur->rgbAtr, cur->cbAtr);

			/* pad up to 36 bytes, per MS-RDPESC IDL */
			Stream_Seek(irp->input, 36-cur->cbAtr);

			/* reset high bytes? */
			//TODO (nik) why?
			cur->dwCurrentState &= 0x0000FFFF;
			cur->dwEventState = 0;
		}

		DEBUG_SCARD("Loading reader states");
		for (i = 0; i < readerCount; i++)
		{
			UINT32 dataLength;
			cur = &readerStates[i];

			if (Stream_GetRemainingLength(irp->input) < 12 )
			{
				DEBUG_ERROR("length violation %d [%d]\n%s", 12, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
				status = SCARD_F_INTERNAL_ERROR;
				goto finish;
			}

			Stream_Seek(irp->input, 8);
			Stream_Read_UINT32(irp->input, dataLength);

			dataLength *= 2;

			if (Stream_GetRemainingLength(irp->input) < dataLength )
			{
				DEBUG_ERROR("length violation %d [%d]\n%s", dataLength, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
				status = SCARD_F_INTERNAL_ERROR;
				goto finish;
			}
			smartcard_input_repos(irp, smartcard_input_string(irp, (char **) &cur->szReader, dataLength, FALSE));

			DEBUG_SCARD("[%d] \"%S\" user: 0x%08x, state: 0x%08x, event: 0x%08x", i, cur->szReader ? cur->szReader : L"NULL", (unsigned) cur->pvUserData, (unsigned) cur->dwCurrentState, (unsigned) cur->dwEventState);

			if (!cur->szReader)
			{
				DEBUG_WARN("cur->szReader=%p", cur->szReader);
				continue;
			}
			if (wcscmp(cur->szReader, L"\\\\?PnP?\\Notification") == 0)
				cur->dwCurrentState |= SCARD_STATE_IGNORE;
		}
	}
	else
	{
		readerStates = NULL;
	}

	status = SCardGetStatusChangeW(hContext, (DWORD) dwTimeout, readerStates, (DWORD) readerCount);

	if (status != SCARD_S_SUCCESS) {
		DEBUG_ERROR("SCardGetStatusChange: Failure: %s (0x%08x)", pcsc_stringify_error(status), (unsigned) status);
	} else {
		DEBUG_SCARD("SCardGetStatusChange: Success Context: %p", hContext);
	}

	Stream_Write_UINT32(irp->output, readerCount);
	//TODO(nik) What is the for? Hardcoded value?
	// I don't see this defined in the MS-RDPESC IDL?
	//Stream_Write_UINT32(irp->output, 0x00084dd8);
	Stream_Write_UINT32(irp->output, 0x00020000); /* NDR offset ptr */
	Stream_Write_UINT32(irp->output, readerCount); /* NDR element count */

	for (i = 0; i < readerCount; i++)
	{
		cur = &readerStates[i];

		DEBUG_SCARD("Setting resposne values \"%S\"\n\tuser: 0x%08x, state: 0x%08x, event: 0x%08x", cur->szReader ? cur->szReader : L"NULL", (unsigned) cur->pvUserData, (unsigned) cur->dwCurrentState, (unsigned) cur->dwEventState);

		/* TODO: do byte conversions if necessary */
		Stream_Write_UINT32(irp->output, cur->dwCurrentState);
		Stream_Write_UINT32(irp->output, cur->dwEventState);
		Stream_Write_UINT32(irp->output, cur->cbAtr);
		Stream_Write(irp->output, cur->rgbAtr, cur->cbAtr);

		Stream_Zero(irp->output, 36-cur->cbAtr);

		free((void *)cur->szReader);
	}

	smartcard_output_alignment(irp, 8);

finish:
	if (readerStates)
		free(readerStates);

	return status;
}

static UINT32 handle_Cancel(SMARTCARD_DEVICE *scard, IRP* irp, size_t inlen)
{
	LONG status;
	SCARDCONTEXT hContext;

	status = handle_CommonTypeHeader(scard, irp, &inlen);
	if (status)
		return status;

	status = handle_PrivateTypeHeader(scard, irp, &inlen);
	if (status)
		return status;

	status = handle_Context(scard, irp, &inlen);
	if (status)
		return status;

	status = handle_RedirContextRef(scard, irp, &inlen, &hContext);
	if (status)
		return status;

	status = SCardCancel(hContext);

	if (status != SCARD_S_SUCCESS) {
		DEBUG_ERROR("Failure: %s (0x%08x)", pcsc_stringify_error(status), (unsigned) status);
	} else {
		DEBUG_SCARD("Success context: 0x%08x %s", (unsigned) hContext, pcsc_stringify_error(status));
	}

	smartcard_output_alignment(irp, 8);

	return status;
}

static UINT32 handle_Connect(SMARTCARD_DEVICE* scard, IRP* irp, size_t inlen, BOOL wide)
{
	LONG status;
	SCARDCONTEXT hContext;
	char* readerName = NULL;
	DWORD dwShareMode = 0;
	DWORD dwPreferredProtocol = 0;
	DWORD dwActiveProtocol = 0;
	SCARDHANDLE hCard;

	status = handle_CommonTypeHeader(scard, irp, &inlen);
	if (status)
		goto finish;

	status = handle_PrivateTypeHeader(scard, irp, &inlen);
	if (status)
		goto finish;

	/* Skip ptrReader */
	if (Stream_GetRemainingLength(irp->input) < 4)
	{
		DEBUG_ERROR("Length violadion %d [%d]\n%s", 4, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		status = SCARD_F_INTERNAL_ERROR;
		goto finish;
	}
	Stream_Seek(irp->input, 4);

	/* Read common data */
	status = handle_Context(scard, irp, &inlen);
	if (status)
		goto finish;
	
	if (Stream_GetRemainingLength(irp->input) < 8)
	{
		DEBUG_ERROR("Length violadion %d [%d]\n%s", 8, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		status = SCARD_F_INTERNAL_ERROR;
		goto finish;
	}

	Stream_Read_UINT32(irp->input, dwShareMode);
	Stream_Read_UINT32(irp->input, dwPreferredProtocol);

	status = smartcard_input_reader_name(irp, &readerName, wide);
	if (status)
		goto finish;
	
	status = handle_RedirContextRef(scard, irp, &inlen, &hContext);
	if (status)
		goto finish;

	DEBUG_SCARD("(context: 0x%p, share: 0x%08x, proto: 0x%08x, reader: \"%s\")",
		hContext, (unsigned) dwShareMode,
		(unsigned) dwPreferredProtocol, readerName ? readerName : "NULL");

	if (!check_reader_is_forwarded(scard, readerName))
	{
		DEBUG_ERROR("Reader '%s' not forwarded!", readerName);
		status = SCARD_E_INVALID_TARGET;
		goto finish;
	}

	status = SCardConnectA(hContext, readerName, (DWORD) dwShareMode,
		(DWORD) dwPreferredProtocol, &hCard, (DWORD *) &dwActiveProtocol);

	if (status != SCARD_S_SUCCESS) {
		DEBUG_ERROR("Failure: %s 0x%08x", pcsc_stringify_error(status), (unsigned) status);
	} else {
		DEBUG_SCARD("Success. Context: 0x%p Card Handle: 0x%p", hContext, hCard);
	}

	/* following was decoded from packet capture since current docuementation does not seem
	   to support this order */
	Stream_Zero(irp->output, 8); /* wire capture shows 8 0 bytes here? */
	Stream_Write_UINT32(irp->output, sizeof(hCard)); /*card handele size*/
	Stream_Write_UINT32(irp->output, 0x00020000); /* ndr offset ptr */
	Stream_Write_UINT32(irp->output, dwActiveProtocol); /* active protocol */
	Stream_Write_UINT32(irp->output, sizeof(hCard)); /* ndr length */
	switch (sizeof(hCard)) {
	case 4:
		Stream_Write_UINT32(irp->output, hCard);
		break;

	case 8:
		Stream_Write_UINT64(irp->output, hCard);
		break;

	default:
		DEBUG_ERROR("Unsupported SCARDHANDLE size? %#x", sizeof(hCard));
		status = SCARD_F_INTERNAL_ERROR;
		goto finish;
	}


	smartcard_output_alignment(irp, 8);

finish:
	if (readerName)
		free(readerName);

	return status;
}

static UINT32 handle_Reconnect(SMARTCARD_DEVICE* scard, IRP* irp, size_t inlen)
{
	LONG status;
	SCARDCONTEXT hContext;
	SCARDHANDLE hCard;
	DWORD dwShareMode = 0;
	DWORD dwPreferredProtocol = 0;
	DWORD dwInitialization = 0;
	DWORD dwActiveProtocol = 0;

	status = handle_CommonTypeHeader(scard, irp, &inlen);
	if (status)
		return status;

	status = handle_PrivateTypeHeader(scard, irp, &inlen);
	if (status)
		return status;

	status = handle_CardHandle(scard, irp, &inlen);
	if (status)
		return status;

	if (Stream_GetRemainingLength(irp->input) < 12)
	{
		DEBUG_ERROR("length violation %d [%d]\n%s", 12, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Read_UINT32(irp->input, dwShareMode);
	Stream_Read_UINT32(irp->input, dwPreferredProtocol);
	Stream_Read_UINT32(irp->input, dwInitialization);

	status = handle_RedirHandleRef(scard, irp, &inlen, &hContext, &hCard);
	if (status)
		return status;

	DEBUG_SCARD("(context: 0x%p, hcard: 0x%p, share: 0x%08x, proto: 0x%08x, init: 0x%08x)",
		hContext, hCard, (unsigned) dwShareMode, (unsigned) dwPreferredProtocol, (unsigned) dwInitialization);

	if (!check_handle_is_forwarded(scard, hCard, hContext))
	{
		DEBUG_ERROR("invalid handle %p [%p]", hCard, hContext);
		return SCARD_E_INVALID_TARGET;
	}

	status = SCardReconnect(hCard, (DWORD) dwShareMode, (DWORD) dwPreferredProtocol,
	    (DWORD) dwInitialization, (LPDWORD) &dwActiveProtocol);

	if (status != SCARD_S_SUCCESS) {
		DEBUG_ERROR("Failure: %s (0x%08x)", pcsc_stringify_error(status), (unsigned) status);
	} else {
		DEBUG_SCARD("Success (proto: 0x%08x)", (unsigned) dwActiveProtocol);
	}

	Stream_Write_UINT32(irp->output, dwActiveProtocol);
	smartcard_output_alignment(irp, 8);

	return status;
}

static UINT32 handle_Disconnect(SMARTCARD_DEVICE* scard, IRP* irp, size_t inlen)
{
	LONG status;
	SCARDCONTEXT hContext;
	SCARDHANDLE hCard;
	DWORD dwDisposition = 0;

	status = handle_CommonTypeHeader(scard, irp, &inlen);
	if (status)
		return status;

	status = handle_PrivateTypeHeader(scard, irp, &inlen);
	if (status)
		return status;

	status = handle_CardHandle(scard, irp, &inlen);
	if (status)
		return status;

	if (Stream_GetRemainingLength(irp->input) < 4)
	{
		DEBUG_ERROR("length violation %d [%d]\n%s", 4, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Read_UINT32(irp->input, dwDisposition);
	
	status = handle_RedirHandleRef(scard, irp, &inlen, &hContext, &hCard);
	if (status)
		return status;

	DEBUG_SCARD("(context: 0x%p, hcard: 0x%08x, disposition: 0x%08x)", hContext, hCard, dwDisposition);

	if (!check_handle_is_forwarded(scard, hCard, hContext))
	{
		DEBUG_ERROR("invalid handle %p [%p]", hCard, hContext);
		return SCARD_E_INVALID_TARGET;
	}

	status = SCardDisconnect(hCard, (DWORD) dwDisposition);

	if (status != SCARD_S_SUCCESS) {
		DEBUG_ERROR("Failure: %s (0x%08x)", pcsc_stringify_error(status), (unsigned) status);
	} else {
		DEBUG_SCARD("SCardDisconnect Success");
	}

	smartcard_output_alignment(irp, 8);

	return status;
}

static UINT32 handle_BeginTransaction(SMARTCARD_DEVICE* scard, IRP* irp, size_t inlen)
{
	LONG status;
	SCARDHANDLE hCard;
	SCARDCONTEXT hContext;

	status = handle_CommonTypeHeader(scard, irp, &inlen);
	if (status)
		return status;

	status = handle_PrivateTypeHeader(scard, irp, &inlen);
	if (status)
		return status;


	status = handle_CardHandle(scard, irp, &inlen);
	if (status)
		return status;

	if (Stream_GetRemainingLength(irp->input) < 4)
	{
		DEBUG_ERROR("length violation %d [%d]\n%s", 4, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}
	Stream_Seek(irp->input, 4);

	status = handle_RedirHandleRef(scard, irp, &inlen, &hContext, &hCard);
	if (status)
		return status;

	if (!check_handle_is_forwarded(scard, hCard, hContext))
	{
		DEBUG_ERROR("invalid handle %p [%p]", hCard, hContext);
		return SCARD_E_INVALID_TARGET;
	}

	status = SCardBeginTransaction(hCard);

	if (status != SCARD_S_SUCCESS) {
		DEBUG_ERROR("Failure: %s (0x%08x)", pcsc_stringify_error(status), (unsigned) status);
	} else {
		DEBUG_SCARD("SCardBeginTransaction Success. Context: %p, Card: %p", hContext, hCard);
	}

	smartcard_output_alignment(irp, 8);

	return status;
}

static UINT32 handle_EndTransaction(SMARTCARD_DEVICE* scard, IRP* irp, size_t inlen)
{
	LONG status;
	SCARDHANDLE hCard;
	SCARDCONTEXT hContext;
	DWORD dwDisposition = 0;

	status = handle_CommonTypeHeader(scard, irp, &inlen);
	if (status)
		return status;

	status = handle_PrivateTypeHeader(scard, irp, &inlen);
	if (status)
		return status;

	status = handle_CardHandle(scard, irp, &inlen);
	if (status)
		return status;

	if (Stream_GetRemainingLength(irp->input) < 4)
	{
		DEBUG_ERROR("length violation %d [%d]\n%s", 4, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}
	Stream_Read_UINT32(irp->input, dwDisposition);

	status = handle_RedirHandleRef(scard, irp, &inlen, &hContext, &hCard);
	if (status)
		return status;

	if (!check_handle_is_forwarded(scard, hCard, hContext))
	{
		DEBUG_ERROR("invalid handle %p [%p]", hCard, hContext);
		return SCARD_E_INVALID_TARGET;
	}

	status = SCardEndTransaction(hCard, dwDisposition);

	if (status != SCARD_S_SUCCESS) {
		DEBUG_ERROR("Failure: %s (0x%08x)", pcsc_stringify_error(status), (unsigned) status);
	} else {
		DEBUG_SCARD("SCardEndTransaction Success. Context: %p, Card: %p", hContext, hCard);
	}

	smartcard_output_alignment(irp, 8);

	return status;
}

static UINT32 handle_State(SMARTCARD_DEVICE* scard, IRP* irp, size_t inlen)
{
	LONG status;
	SCARDHANDLE hCard;
	SCARDCONTEXT hContext;
	DWORD state = 0, protocol = 0;
	DWORD readerLen;
	DWORD atrLen = MAX_ATR_SIZE;
	char* readerName = NULL;
	BYTE pbAtr[MAX_ATR_SIZE];

#ifdef WITH_DEBUG_SCARD
	int i;
#endif

	status = handle_CommonTypeHeader(scard, irp, &inlen);
	if (status)
		goto finish;

	status = handle_PrivateTypeHeader(scard, irp, &inlen);
	if (status)
		goto finish;

	status = handle_CardHandle(scard, irp, &inlen);
	if (status)
		goto finish;

	if (Stream_GetRemainingLength(irp->input) < 8)
	{
		DEBUG_ERROR("length violation %d [%d]\n%s", 8, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		status = SCARD_F_INTERNAL_ERROR;
		goto finish;
	}

	Stream_Seek(irp->input, 4);
	Stream_Seek_UINT32(irp->input);	/* atrLen */
	inlen -= 8;

	status = handle_RedirHandleRef(scard, irp, &inlen, &hContext, &hCard);
	if (status)
		goto finish;

	if (!check_handle_is_forwarded(scard, hCard, hContext))
	{
		DEBUG_ERROR("invalid handle %p [%p]", hCard, hContext);
		status = SCARD_E_INVALID_TARGET;
		goto finish;
	}

#ifdef SCARD_AUTOALLOCATE
	readerLen = SCARD_AUTOALLOCATE;

	status = SCardStatusA(hCard, (LPSTR) &readerName, &readerLen, &state, &protocol, pbAtr, &atrLen);
#else
	readerLen = 256;
	readerName = malloc(readerLen);

	status = SCardStatusA(hCard, (LPSTR) readerName, &readerLen, &state, &protocol, pbAtr, &atrLen);
#endif

	if (status != SCARD_S_SUCCESS)
	{
		DEBUG_ERROR("Failure: %s (0x%08x)", pcsc_stringify_error(status), (unsigned) status);
		status = smartcard_output_return(irp, status);
		goto finish;
	}

	DEBUG_SCARD("SCardStatusA Success (hcard: 0x%08x len: %d state: 0x%08x, proto: 0x%08x)",
		(unsigned) hCard, (int) atrLen, (unsigned) state, (unsigned) protocol);

#ifdef WITH_DEBUG_SCARD
	{
		char buf[128] = {0};
		int x = 0;
		x += sprintf(buf, "       ATR: ");
		for (i = 0; i < atrLen; i++)
			x += sprintf(&buf[x], "%02x%c", pbAtr[i], (i == atrLen - 1) ? ' ' : ':');
		DEBUG_SCARD("%s", buf);
	}
#endif

	state = smartcard_map_state(state);

	Stream_Write_UINT32(irp->output, state);
	Stream_Write_UINT32(irp->output, protocol);
	Stream_Write_UINT32(irp->output, atrLen);
	//TODO (nik) what is this hardcoded value for? number of atr's?
	Stream_Write_UINT32(irp->output, 0x00000001);
	Stream_Write_UINT32(irp->output, atrLen);
	Stream_Write(irp->output, pbAtr, atrLen);

	smartcard_output_repos(irp, atrLen);
	smartcard_output_alignment(irp, 8);

finish:
	if (readerName)
	{
#ifdef SCARD_AUTOALLOCATE
		SCardFreeMemory(hContext, readerName);
#else
		free(readerName);
#endif
	}

	return status;
}

static DWORD handle_Status(SMARTCARD_DEVICE *scard, IRP* irp, size_t inlen, BOOL wide)
{
	LONG status;
	SCARDHANDLE hCard;
	SCARDCONTEXT hContext;
	DWORD state, protocol;
	DWORD readerLen = 0;
	DWORD atrLen = MAX_ATR_SIZE;
	char* readerName = NULL;
	BYTE *pbAtr = NULL;
	UINT32 dataLength = 0;
	int pos, poslen1, poslen2;

#ifdef WITH_DEBUG_SCARD
	int i;
#endif

	status = handle_CommonTypeHeader(scard, irp, &inlen);
	if (status)
		goto finish;

	status = handle_PrivateTypeHeader(scard, irp, &inlen);
	if (status)
		goto finish;

	status = handle_CardHandle(scard, irp, &inlen);
	if (status)
		goto finish;

	if (Stream_GetRemainingLength(irp->input) < 12)
	{
		DEBUG_ERROR("length violation %d [%d]\n%s", 12, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		status = SCARD_F_INTERNAL_ERROR;
		goto finish;
	}
	Stream_Seek(irp->input, 4);
	Stream_Read_UINT32(irp->input, readerLen);
	Stream_Read_UINT32(irp->input, atrLen);
	
	status = handle_RedirHandleRef(scard, irp, &inlen, &hContext, &hCard);
	if (status)
		goto finish;

	if (!check_handle_is_forwarded(scard, hCard, hContext))
	{
		DEBUG_ERROR("invalid handle %p [%p]", hCard, hContext);
		status = SCARD_E_INVALID_TARGET;
		goto finish;
	}

	pbAtr = (BYTE*)malloc(sizeof(BYTE) * atrLen);
#ifdef SCARD_AUTOALLOCATE
	readerLen = SCARD_AUTOALLOCATE;

	status = SCardStatusA(hCard, (LPSTR) &readerName, &readerLen, &state, &protocol, pbAtr, &atrLen);
#else
	readerLen = 256;
	readerName = malloc(readerLen);

	status = SCardStatusA(hCard, (LPSTR) readerName, &readerLen, &state, &protocol, pbAtr, &atrLen);
#endif

	if (status != SCARD_S_SUCCESS)
	{
		DEBUG_ERROR("Failure: %s (0x%08x)", pcsc_stringify_error(status), (unsigned) status);
		status = smartcard_output_return(irp, status);
		goto finish;
	}

	DEBUG_SCARD("SCardStatusA Success (Context: %p Card: %p state: 0x%08x, proto: 0x%08x) Reader: \"%s\"", hContext, hCard, (unsigned) state, (unsigned) protocol, readerName ? readerName : "NULL");

#ifdef WITH_DEBUG_SCARD
	{
		char buf[128] = {0};
		int x = 0;
		x += sprintf(buf, "       ATR: ");
		for (i = 0; i < atrLen; i++)
			x += sprintf(&buf[x], "%02x%c", pbAtr[i], (i == atrLen - 1) ? ' ' : ':');
		DEBUG_SCARD("%s", buf);
	}
#endif

	state = smartcard_map_state(state);

	poslen1 = Stream_GetPosition(irp->output);
	Stream_Write_UINT32(irp->output, readerLen);
	//TODO (nik) what is this hardcoded value for?
	Stream_Write_UINT32(irp->output, 0x00020000);
	Stream_Write_UINT32(irp->output, state);
	Stream_Write_UINT32(irp->output, protocol);
	Stream_Write(irp->output, pbAtr, atrLen);

	if (atrLen < 32)
		Stream_Zero(irp->output, 32 - atrLen);
	Stream_Write_UINT32(irp->output, atrLen);

	poslen2 = Stream_GetPosition(irp->output);
	Stream_Write_UINT32(irp->output, readerLen);

	if (readerName)
		dataLength += smartcard_output_string(irp, readerName, wide);
	dataLength += smartcard_output_string(irp, "\0", wide);
	smartcard_output_repos(irp, dataLength);

	pos = Stream_GetPosition(irp->output);
	Stream_SetPosition(irp->output, poslen1);
	Stream_Write_UINT32(irp->output,dataLength);
	Stream_SetPosition(irp->output, poslen2);
	Stream_Write_UINT32(irp->output,dataLength);
	Stream_SetPosition(irp->output, pos);

	smartcard_output_alignment(irp, 8);

finish:
	if (readerName)
	{
#ifdef SCARD_AUTOALLOCATE
		SCardFreeMemory(hContext, readerName); 
#else
		free(readerName);
#endif
	}

	if (pbAtr)
		free(pbAtr);

	return status;
}

static void Stream_Dump(wStream *s)
{
	size_t size = Stream_GetRemainingLength(s);
	int i;
	char buf[4096] = {0};
	int x = 0;

	x = sprintf(buf, "Current Offset: %#x\n", Stream_Pointer(s)-Stream_Buffer(s));
	x += sprintf(&buf[x], "-------------------------- Start [%s] [%zd] ------------------------",
			__func__, size);
	for(i=0; i<size; i++)
	{
		x += sprintf(&buf[x], "%02X", s->pointer[i]);
		if (i % 80 == 0)
			x += sprintf(&buf[x], "\n");
	}
	x += sprintf(&buf[x], "\n");
	x += sprintf(&buf[x], "-------------------------- End [%s] ------------------------", __func__);
	fprintf(stderr, "%s\n", buf);
	fflush(stderr);
}

const char* Stream_HexDump(wStream *s)
{
#if defined(WITH_DEBUG_SCARD)
/* This does return a pointer to a local variable, which should be ok under debug builds */
	//size_t size = Stream_GetRemainingLength(s);
	size_t size = Stream_Length(s);
	int i;
	char buf[4096] = {0};
	int x = 0;

	x = sprintf(buf, "\nCurrent Offset: %#x\n", Stream_Pointer(s)-Stream_Buffer(s));
	x += sprintf(&buf[x], "-------------------------- Start [%s] [%zd] ------------------------\n", __func__, size);
#if 0
	for(i=0; i<size; i++)
	{
		x += sprintf(&buf[x], "%02X", s->pointer[i]);
		if (i % 80 == 0)
			x += sprintf(&buf[x], "\n");
	}
#else
	x += winpr_HexDumpToBuffer(&buf[x], Stream_Buffer(s), size);
#endif
	//x += sprintf(&buf[x], "\n");
	x += sprintf(&buf[x], "-------------------------- End [%s] ------------------------", __func__);

	return buf;
#else
	return "";
#endif
}


static UINT32 handle_Transmit(SMARTCARD_DEVICE* scard, IRP* irp, size_t inlen)
{
	LONG status;
	SCARDHANDLE hCard;
	SCARDCONTEXT hContext;
	UINT32 pioSendPciBufferPtr;
	UINT32 ptrSendBuffer;
	UINT32 ptrIoRecvPciBuffer;
	UINT32 recvBufferIsNULL;
	UINT32 linkedLen;
	void *tmp;
	union
	{
		SCARD_IO_REQUEST *rq;
		UINT32 *u32;
		void *v;
	} ioSendPci, ioRecvPci;

	SCARD_IO_REQUEST *pPioRecvPci = NULL;
	DWORD cbSendLength = 0, cbRecvLength = 0;
	BYTE *sendBuf = NULL, *recvBuf = NULL;

	UINT32 context_size;
	UINT32 context_ptr;
	UINT32 card_size;
	UINT32 card_ptr;

	ioSendPci.v = NULL;
	ioRecvPci.v = NULL;

	status = handle_CommonTypeHeader(scard, irp, &inlen);
	if (status)
		goto finish;

	status = handle_PrivateTypeHeader(scard, irp, &inlen);
	if (status)
		goto finish;

	if (Stream_GetRemainingLength(irp->input) < 32)
	{
		DEBUG_ERROR("length violation %d [%d]%s\n", 32, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		status = SCARD_F_INTERNAL_ERROR;
		goto finish;
	}

	// handle context ptr
	Stream_Read_UINT32(irp->input, context_size);
	Stream_Read_UINT32(irp->input, context_ptr);

/*
	status = handle_CardHandle(scard, irp, &inlen);
	if (status)
		goto finish;
*/
	// handle card ptr
	Stream_Read_UINT32(irp->input, card_size);
	Stream_Read_UINT32(irp->input, card_ptr);

	ioSendPci.v = malloc(sizeof(SCARD_IO_REQUEST));
	ioRecvPci.v = malloc(sizeof(SCARD_IO_REQUEST));

	Stream_Read_UINT32(irp->input, ioSendPci.rq->dwProtocol);
	Stream_Read_UINT32(irp->input, ioSendPci.rq->cbPciLength);
	Stream_Read_UINT32(irp->input, pioSendPciBufferPtr);

	Stream_Read_UINT32(irp->input, cbSendLength);
	Stream_Read_UINT32(irp->input, ptrSendBuffer);
	Stream_Read_UINT32(irp->input, ptrIoRecvPciBuffer);
	Stream_Read_UINT32(irp->input, recvBufferIsNULL);
	Stream_Read_UINT32(irp->input, cbRecvLength);

	status = handle_RedirHandleRef(scard, irp, &inlen, &hContext, &hCard);
	if (status)
		goto finish;

	DEBUG_SCARD("dwProtocol=%X, cbPciLength=%d, pioSendPciBufferPtr=%d, cbSendLength=%d, ptrSendBuffer=%d, ptrIoRecvPciBuffer=%d, recvBufferIsNULL=%d, cbRecvLength=%d",
	ioSendPci.rq->dwProtocol,
	ioSendPci.rq->cbPciLength,
	pioSendPciBufferPtr,
	cbSendLength,
	ptrSendBuffer,
	ptrIoRecvPciBuffer,
	recvBufferIsNULL,
	cbRecvLength);

	Stream_Dump(irp->input);

	/* Check, if there is data available from the ipSendPci element */
	if (pioSendPciBufferPtr)
	{
		if (Stream_GetRemainingLength(irp->input) < 8)
		{
			DEBUG_ERROR("length violation %d [%d]\n%s", 8, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
			status = SCARD_F_INTERNAL_ERROR;
			goto finish;
		}
		Stream_Read_UINT32(irp->input, linkedLen);

		if (Stream_GetRemainingLength(irp->input) < ioSendPci.rq->cbPciLength)
		{
			DEBUG_ERROR("length violation %d [%d]\n%s", ioSendPci.rq->cbPciLength, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
			status = SCARD_F_INTERNAL_ERROR;
			goto finish;
		}
		
		/* For details see 2.2.1.8 SCardIO_Request in MS-RDPESC and
		 * http://msdn.microsoft.com/en-us/library/windows/desktop/aa379807%28v=vs.85%29.aspx
		 */
		if (linkedLen < ioSendPci.rq->cbPciLength - sizeof(SCARD_IO_REQUEST))
		{
			DEBUG_ERROR("SCARD_IO_REQUEST with invalid extra byte length %d [%d]\n%s", ioSendPci.rq->cbPciLength - sizeof(SCARD_IO_REQUEST), linkedLen, Stream_HexDump(irp->input));
			status = SCARD_F_INTERNAL_ERROR;
			goto finish;
		}
		tmp = realloc(ioSendPci.v, ioSendPci.rq->cbPciLength);
		if (!tmp)
			goto finish;
		ioSendPci.v = tmp;

		Stream_Read(irp->input, &ioSendPci.rq[1], ioSendPci.rq->cbPciLength);
	}
	else
		ioSendPci.rq->cbPciLength = sizeof(SCARD_IO_REQUEST);

	/* Check, if there is data available from the SendBufferPointer */
	if (ptrSendBuffer)
	{
		if (Stream_GetRemainingLength(irp->input) < 4)
		{
			DEBUG_ERROR("length violation %d [%d]\n%s", 4, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
			status = SCARD_F_INTERNAL_ERROR;
			goto finish;
		}
		Stream_Read_UINT32(irp->input, linkedLen);

		/* Just check for too few bytes, there may be more actual
		 * data than is used due to padding. */
		if (linkedLen < cbSendLength)
		{
			DEBUG_ERROR("SendBuffer invalid byte length %d [%d]\n%s", cbSendLength, linkedLen, Stream_HexDump(irp->input));
			status = SCARD_F_INTERNAL_ERROR;
			goto finish;
		}
		if (Stream_GetRemainingLength(irp->input) < cbSendLength)
		{
			DEBUG_ERROR("length violation %d [%d]\n%s", cbSendLength, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
			status = SCARD_F_INTERNAL_ERROR;
			goto finish;
		}
		sendBuf = (BYTE*)malloc(cbSendLength);
		Stream_Read(irp->input, sendBuf, cbSendLength);
	}

	/* Check, if a response is desired. */
	if (cbRecvLength && !recvBufferIsNULL)
		recvBuf = (BYTE*)malloc(cbRecvLength);
	else
		cbRecvLength = 0;

	if (ptrIoRecvPciBuffer)
	{
		if (Stream_GetRemainingLength(irp->input) < 8)
		{
			DEBUG_ERROR("length violation %d [%d]\n%s", 8, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
			status = SCARD_F_INTERNAL_ERROR;
			goto finish;
		}
		/* recvPci */
		Stream_Read_UINT32(irp->input, linkedLen);
		Stream_Read_UINT16(irp->input, ioRecvPci.rq->dwProtocol);
		Stream_Read_UINT16(irp->input, ioRecvPci.rq->cbPciLength);
	
		/* Just check for too few bytes, there may be more actual
		 * data than is used due to padding. */
		if (linkedLen < ioSendPci.rq->cbPciLength)
		{
			DEBUG_ERROR("SCARD_IO_REQUEST with invalid extra byte length %d [%d]\n%s",
					ioSendPci.rq->cbPciLength - sizeof(SCARD_IO_REQUEST), linkedLen, Stream_HexDump(irp->input));
			status = SCARD_F_INTERNAL_ERROR;
			goto finish;
		}

		if (Stream_GetRemainingLength(irp->input) < ioRecvPci.rq->cbPciLength)
		{
			DEBUG_ERROR("length violation %d [%d]\n%s", ioRecvPci.rq->cbPciLength, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
			status = SCARD_F_INTERNAL_ERROR;
			goto finish;
		}

		/* Read data, see
		 * http://msdn.microsoft.com/en-us/library/windows/desktop/aa379807%28v=vs.85%29.aspx
		 */
		tmp = realloc(ioRecvPci.v, ioRecvPci.rq->cbPciLength);
		if (!tmp)
			goto finish;
		ioRecvPci.v = tmp;

		Stream_Read(irp->input, &ioRecvPci.rq[1], ioRecvPci.rq->cbPciLength);

		pPioRecvPci = ioRecvPci.rq;
	}
	else
		pPioRecvPci = NULL;

	DEBUG_SCARD("SCardTransmit(hcard: 0x%08lx, send: %d bytes, recv: %d bytes)",
		(long unsigned) hCard, (int) cbSendLength, (int) cbRecvLength);

	if (!check_handle_is_forwarded(scard, hCard, hContext))
	{
		DEBUG_ERROR("invalid handle %p [%p]", hCard, hContext);
		status = SCARD_E_INVALID_TARGET;
		goto finish;
	}

	status = SCardTransmit(hCard, ioSendPci.rq, sendBuf, cbSendLength, pPioRecvPci, recvBuf, &cbRecvLength);

	{
		char buf[4096] = {0};
		int x = 0;

		x += sprintf(&buf[x], "\nSent: %d\n", cbSendLength);
		x += winpr_HexDumpToBuffer(&buf[x], sendBuf, cbSendLength);
		x += sprintf(&buf[x], "\nReceived: %d\n", cbRecvLength);
		x += winpr_HexDumpToBuffer(&buf[x], recvBuf, cbRecvLength);
		DEBUG_SCARD("%s", buf);
	}

	if (status != SCARD_S_SUCCESS)
	{
		DEBUG_ERROR("Failure: %s (0x%08x)", pcsc_stringify_error(status), (unsigned) status);
	}
	else
	{
		DEBUG_SCARD("SCardTransmit Success. (recieved %d bytes) Context: %p Card: %p", (int) cbRecvLength, hContext, hCard);

		Stream_Write_UINT32(irp->output, 0); 	/* pioRecvPci 0x00; */

		if (recvBuf)
		{
			smartcard_output_buffer_start(irp, cbRecvLength);	/* start of recvBuf output */
			smartcard_output_buffer(irp, (char*) recvBuf, cbRecvLength);
		}
	}

	smartcard_output_alignment(irp, 8);

finish:
	if (sendBuf)
		free(sendBuf);
	if (recvBuf)
		free(recvBuf);
	if (ioSendPci.v)
		free(ioSendPci.v);
	if (ioRecvPci.v)
		free(ioRecvPci.v);

	return status;
}

static UINT32 handle_Control(SMARTCARD_DEVICE* scard, IRP* irp, size_t inlen)
{
	LONG status;
	SCARDCONTEXT hContext;
	SCARDHANDLE hCard;
	UINT32 pvInBuffer, fpvOutBufferIsNULL;
	UINT32 controlCode;
	UINT32 controlFunction;
	BYTE* recvBuffer = NULL;
	BYTE* sendBuffer = NULL;
	UINT32 recvLength;
	DWORD nBytesReturned;
	DWORD outBufferSize;

	status = handle_CommonTypeHeader(scard, irp, &inlen);
	if (status)
		goto finish;

	status = handle_PrivateTypeHeader(scard, irp, &inlen);
	if (status)
		goto finish;

	status = handle_CardHandle(scard, irp, &inlen);
	if (status)
		goto finish;

	if (Stream_GetRemainingLength(irp->input) < 20)
	{
		DEBUG_ERROR("length violation %d [%d]\n%s", 20, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		status = SCARD_F_INTERNAL_ERROR;
		goto finish;
	}

	Stream_Read_UINT32(irp->input, controlCode);
	Stream_Read_UINT32(irp->input, recvLength);
	Stream_Read_UINT32(irp->input, pvInBuffer);
	Stream_Read_UINT32(irp->input, fpvOutBufferIsNULL);
	Stream_Read_UINT32(irp->input, outBufferSize);

	status = handle_RedirHandleRef(scard, irp, &inlen, &hContext, &hCard);
	if (status)
		goto finish;

	/* Translate Windows SCARD_CTL_CODE's to corresponding local code */
	if (WIN_CTL_DEVICE_TYPE(controlCode) == WIN_FILE_DEVICE_SMARTCARD)
	{
		controlFunction = WIN_CTL_FUNCTION(controlCode);
		controlCode = SCARD_CTL_CODE(controlFunction);
	}
	DEBUG_SCARD("controlCode: 0x%08x", (unsigned) controlCode);

	if (pvInBuffer)
	{
		/* Get the size of the linked data. */
		if (Stream_GetRemainingLength(irp->input) < 4)
		{
			DEBUG_ERROR("length violation %d [%d]\n%s", 4, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
			status = SCARD_F_INTERNAL_ERROR;
			goto finish;
		}
		Stream_Read_UINT32(irp->input, recvLength);

		/* Check, if there is actually enough data... */
		if (Stream_GetRemainingLength(irp->input) < recvLength)
		{
			DEBUG_ERROR("length violation %d [%d]\n%s", recvLength, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
			status = SCARD_F_INTERNAL_ERROR;
			goto finish;
		}
		recvBuffer = (BYTE*)malloc(recvLength);

		Stream_Read(irp->input, recvBuffer, recvLength);
	}

	nBytesReturned = outBufferSize;
	sendBuffer = (BYTE*)malloc(outBufferSize);

	if (!check_handle_is_forwarded(scard, hCard, hContext))
	{
		DEBUG_ERROR("invalid handle %p [%p]", hCard, hContext);
		status = SCARD_E_INVALID_TARGET;
		goto finish;
	}

	status = SCardControl(hCard, (DWORD) controlCode, recvBuffer, (DWORD) recvLength,
		sendBuffer, (DWORD) outBufferSize, &nBytesReturned);

	if (status != SCARD_S_SUCCESS) {
		DEBUG_ERROR("Failure: %s (0x%08x)", pcsc_stringify_error(status), (unsigned) status);
	} else {
		DEBUG_SCARD("SCardControl Success (out: %u bytes)", (unsigned) nBytesReturned);
	}

	Stream_Write_UINT32(irp->output, (UINT32) nBytesReturned);
	//TODO (nik) Is this hardcoded value representing a value size? if so, is it x64 compatible?
	Stream_Write_UINT32(irp->output, 0x00000004);
	Stream_Write_UINT32(irp->output, nBytesReturned);

	if (nBytesReturned > 0)
	{
		Stream_Write(irp->output, sendBuffer, nBytesReturned);
		smartcard_output_repos(irp, nBytesReturned);
	}

	smartcard_output_alignment(irp, 8);

finish:
	if (recvBuffer)
		free(recvBuffer);
	if (sendBuffer)
		free(sendBuffer);

	return status;
}

static UINT32 handle_GetAttrib(SMARTCARD_DEVICE* scard, IRP* irp, size_t inlen)
{
	LONG status;
	SCARDHANDLE hCard;
	SCARDCONTEXT hContext;
	DWORD dwAttrId = 0;
	DWORD dwAttrLen = 0;
	DWORD attrLen = 0;
	BYTE* pbAttr = NULL;

	status = handle_CommonTypeHeader(scard, irp, &inlen);
	if (status)
		return status;

	status = handle_PrivateTypeHeader(scard, irp, &inlen);
	if (status)
		return status;

	status = handle_CardHandle(scard, irp, &inlen);
	if (status)
		return status;

	if (Stream_GetRemainingLength(irp->input) < 12)
	{
		DEBUG_ERROR("length violation %d [%d]\n%s", 12, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Read_UINT32(irp->input, dwAttrId);
	Stream_Seek(irp->input, 0x4);
	Stream_Read_UINT32(irp->input, dwAttrLen);
	
	status = handle_RedirHandleRef(scard, irp, &inlen, &hContext, &hCard);
	if (status)
		return status;

	DEBUG_SCARD("hcard: 0x%08x, attrib: 0x%08x (%d bytes)",
		(unsigned) hCard, (unsigned) dwAttrId, (int) dwAttrLen);

	if (!check_handle_is_forwarded(scard, hCard, hContext))
	{
		DEBUG_ERROR("invalid handle %p [%p]", hCard, hContext);
		return SCARD_E_INVALID_TARGET;
	}

#ifdef SCARD_AUTOALLOCATE
	if (dwAttrLen == 0)
	{
		attrLen = 0;
	}
	else
	{
		attrLen = SCARD_AUTOALLOCATE;
	}
#endif

	status = SCardGetAttrib(hCard, dwAttrId, attrLen == 0 ? NULL : (BYTE*) &pbAttr, &attrLen);

	if (status != SCARD_S_SUCCESS)
	{
#ifdef SCARD_AUTOALLOCATE
		if (dwAttrLen == 0)
			attrLen = 0;
		else
			attrLen = SCARD_AUTOALLOCATE;
#endif
	}

	if (dwAttrId == SCARD_ATTR_DEVICE_FRIENDLY_NAME_A && status == SCARD_E_UNSUPPORTED_FEATURE)
	{
		status = SCardGetAttrib(hCard, SCARD_ATTR_DEVICE_FRIENDLY_NAME_W,
			attrLen == 0 ? NULL : (BYTE*) &pbAttr, &attrLen);

		if (status != SCARD_S_SUCCESS)
		{
#ifdef SCARD_AUTOALLOCATE
			if (dwAttrLen == 0)
				attrLen = 0;
			else
				attrLen = SCARD_AUTOALLOCATE;
#endif
		}
	}
	if (dwAttrId == SCARD_ATTR_DEVICE_FRIENDLY_NAME_W && status == SCARD_E_UNSUPPORTED_FEATURE)
	{
		status = SCardGetAttrib(hCard, SCARD_ATTR_DEVICE_FRIENDLY_NAME_A,
			attrLen == 0 ? NULL : (BYTE*) &pbAttr, &attrLen);

		if (status != SCARD_S_SUCCESS)
		{
#ifdef SCARD_AUTOALLOCATE
			if (dwAttrLen == 0)
				attrLen = 0;
			else
				attrLen = SCARD_AUTOALLOCATE;
#endif
		}
	}
	if (attrLen > dwAttrLen && pbAttr != NULL)
	{
		status = SCARD_E_INSUFFICIENT_BUFFER;
	}
	dwAttrLen = attrLen;

	if (status != SCARD_S_SUCCESS)
	{
		DEBUG_ERROR("Failure: %s (0x%08x)", pcsc_stringify_error(status), (unsigned int) status);
		free(pbAttr);
		return smartcard_output_return(irp, status);
	}
	else
	{
		DEBUG_SCARD("Success (%d bytes)", (int) dwAttrLen);

		Stream_Write_UINT32(irp->output, dwAttrLen);
		//TODO(nik) what is this hardcoded value for?
		Stream_Write_UINT32(irp->output, 0x00000200);
		Stream_Write_UINT32(irp->output, dwAttrLen);

		if (!pbAttr)
		{
			Stream_Zero(irp->output, dwAttrLen);
		}
		else
		{
			Stream_Write(irp->output, pbAttr, dwAttrLen);
		}
		smartcard_output_repos(irp, dwAttrLen);
		/* align to multiple of 4 */
		Stream_Write_UINT32(irp->output, 0);
	}
	smartcard_output_alignment(irp, 8);

#ifdef SCARD_AUTOALLOCATE
	SCardFreeMemory(hContext, pbAttr);
#else
	free(pbAttr);
#endif

	return status;
}

static UINT32 handle_AccessStartedEvent(SMARTCARD_DEVICE* scard, IRP* irp, size_t inlen)

{
	if (Stream_GetRemainingLength(irp->input) < 4)
	{
		DEBUG_ERROR("length violation %d [%d]\n%s", 4, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}
	Stream_Seek(irp->input, 4);

	smartcard_output_alignment(irp, 8);
	
	return SCARD_S_SUCCESS;
}

void scard_error(SMARTCARD_DEVICE* scard, IRP* irp, UINT32 ntstatus)
{
	/* [MS-RDPESC] 3.1.4.4 */
	DEBUG_ERROR("scard processing error %x", ntstatus);

	Stream_SetPosition(irp->output, 0);	/* CHECKME */
	irp->IoStatus = ntstatus;
	irp->Complete(irp);
}

/* http://msdn.microsoft.com/en-gb/library/ms938473.aspx */
typedef struct _SERVER_SCARD_ATRMASK
{
	UINT32 cbAtr;
	BYTE rgbAtr[36];
	BYTE rgbMask[36];
}
SERVER_SCARD_ATRMASK;

static UINT32 handle_LocateCardsByATR(SMARTCARD_DEVICE* scard, IRP* irp, size_t inlen, BOOL wide)
{
	LONG status;
	int i, j, k;
	SCARDCONTEXT hContext;
	UINT32 atrMaskCount = 0;
	UINT32 readerCount = 0;
	SCARD_READERSTATEA* cur = NULL;
	SCARD_READERSTATEA* rsCur = NULL;
	SCARD_READERSTATEA* readerStates = NULL;
	SERVER_SCARD_ATRMASK* curAtr = NULL;
	SERVER_SCARD_ATRMASK* pAtrMasks = NULL;

	status = handle_CommonTypeHeader(scard, irp, &inlen);
	if (status)
		return status;

	status = handle_PrivateTypeHeader(scard, irp, &inlen);
	if (status)
		return status;

	status = handle_Context(scard, irp, &inlen);
	if (status)
		return status;

	if (Stream_GetRemainingLength(irp->input) < 4)
	{
		DEBUG_ERROR("length violation %d [%d]\n%s", 4, Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Seek(irp->input, 4);
	status = handle_RedirContextRef(scard, irp, &inlen, &hContext);
	if (status)
		return status;

	Stream_Seek(irp->input, 0x2C);
	Stream_Read_UINT32(irp->input, hContext);
	Stream_Read_UINT32(irp->input, atrMaskCount);

	pAtrMasks = malloc(atrMaskCount * sizeof(SERVER_SCARD_ATRMASK));

	if (!pAtrMasks)
		return smartcard_output_return(irp, SCARD_E_NO_MEMORY);

	for (i = 0; i < atrMaskCount; i++)
	{
		Stream_Read_UINT32(irp->input, pAtrMasks[i].cbAtr);
		Stream_Read(irp->input, pAtrMasks[i].rgbAtr, 36);
		Stream_Read(irp->input, pAtrMasks[i].rgbMask, 36);
	}

	Stream_Read_UINT32(irp->input, readerCount);

	readerStates = malloc(readerCount * sizeof(SCARD_READERSTATEA));
	ZeroMemory(readerStates, readerCount * sizeof(SCARD_READERSTATEA));

	if (!readerStates)
	{
		free(pAtrMasks);
		return smartcard_output_return(irp, SCARD_E_NO_MEMORY);
	}

	for (i = 0; i < readerCount; i++)
	{
		cur = &readerStates[i];

		Stream_Seek(irp->input, 4);

		/*
		 * TODO: on-wire is little endian; need to either
		 * convert to host endian or fix the headers to
		 * request the order we want
		 */
		Stream_Read_UINT32(irp->input, cur->dwCurrentState);
		Stream_Read_UINT32(irp->input, cur->dwEventState);
		Stream_Read_UINT32(irp->input, cur->cbAtr);
		Stream_Read(irp->input, cur->rgbAtr, 32);

		Stream_Seek(irp->input, 4);

		/* reset high bytes? */
		cur->dwCurrentState &= 0x0000FFFF;
		cur->dwEventState &= 0x0000FFFF;
		cur->dwEventState = 0;
	}

	for (i = 0; i < readerCount; i++)
	{
		UINT32 dataLength;
		cur = &readerStates[i];

		Stream_Seek(irp->input, 8);
		Stream_Read_UINT32(irp->input, dataLength);
		smartcard_input_repos(irp, smartcard_input_string(irp, (char **) &cur->szReader, dataLength, wide));

		DEBUG_SCARD("Reader: \"%s\" user: 0x%08x, state: 0x%08x, event: 0x%08x", cur->szReader ? cur->szReader : "NULL", (unsigned) cur->pvUserData, (unsigned) cur->dwCurrentState, (unsigned) cur->dwEventState);

		if (!cur->szReader)
		{
			DEBUG_WARN("cur->szReader=%p", cur->szReader);
			continue;
		}
		if (strcmp(cur->szReader, "\\\\?PnP?\\Notification") == 0)
			cur->dwCurrentState |= SCARD_STATE_IGNORE;
	}

	status = SCardGetStatusChangeA(hContext, 0x00000001, readerStates, readerCount);
	if (status != SCARD_S_SUCCESS)
	{
		DEBUG_ERROR("Failure: %s (0x%08x)", pcsc_stringify_error(status), (unsigned) status);

		free(readerStates);
		free(pAtrMasks);
		return smartcard_output_return(irp, status);
	}

	DEBUG_SCARD("SCardGetStatusChangeA Success");
	for (i = 0, curAtr = pAtrMasks; i < atrMaskCount; i++, curAtr++)
	{
		for (j = 0, rsCur = readerStates; j < readerCount; j++, rsCur++)
		{
			BOOL equal = 1;
			for (k = 0; k < cur->cbAtr; k++)
			{
				if ((curAtr->rgbAtr[k] & curAtr->rgbMask[k]) !=
				    (rsCur->rgbAtr[k] & curAtr->rgbMask[k]))
				{
					equal = 0;
					break;
				}
			}
			if (equal)
			{
				rsCur->dwEventState |= 0x00000040;	/* SCARD_STATE_ATRMATCH 0x00000040 */
			}
		}
	}

	Stream_Write_UINT32(irp->output, readerCount);
	//TODO(nik) what is this hardcoded value for?
	Stream_Write_UINT32(irp->output, 0x00084dd8);
	Stream_Write_UINT32(irp->output, readerCount);

	for (i = 0, cur = readerStates; i < readerCount; i++, cur++)
	{
		Stream_Write_UINT32(irp->output, cur->dwCurrentState);
		Stream_Write_UINT32(irp->output, cur->dwEventState);
		Stream_Write_UINT32(irp->output, cur->cbAtr);
		Stream_Write(irp->output, cur->rgbAtr, 32);

		Stream_Zero(irp->output, 4);

		free((void*) cur->szReader);
	}

	smartcard_output_alignment(irp, 8);

	free(readerStates);
	free(pAtrMasks);

	return status;
}

BOOL smartcard_async_op(IRP* irp)
{
	UINT32 ioctl_code;

	/* peek ahead */
	Stream_Seek(irp->input, 8);
	Stream_Read_UINT32(irp->input, ioctl_code);
	Stream_Rewind(irp->input, 12);

	switch (ioctl_code)
	{
		/* non-blocking events */
		case SCARD_IOCTL_ACCESS_STARTED_EVENT:

		case SCARD_IOCTL_ESTABLISH_CONTEXT:
		case SCARD_IOCTL_RELEASE_CONTEXT:
		case SCARD_IOCTL_IS_VALID_CONTEXT:

			return FALSE;
			break;

		/* async events */
		case SCARD_IOCTL_GET_STATUS_CHANGE_A:
		case SCARD_IOCTL_GET_STATUS_CHANGE_W:

		case SCARD_IOCTL_TRANSMIT:

		case SCARD_IOCTL_STATUS_A:
		case SCARD_IOCTL_STATUS_W:
			return TRUE;
			break;

		default:
			break;
	}	

	/* default to async */
	return TRUE;
}

void smartcard_device_control(SMARTCARD_DEVICE* scard, IRP* irp)
{
	UINT32 pos;
	UINT32 result;
	UINT32 result_pos;
	UINT32 output_len;
	UINT32 input_len;
	UINT32 ioctl_code;
	UINT32 stream_len;
	UINT32 irp_result_pos;
	UINT32 output_len_pos;
	const UINT32 header_lengths = 16;

	/* MS-RPCE, Sections 2.2.6.1 and 2.2.6.2. */
	if (Stream_GetRemainingLength(irp->input) < 32)
	{
		DEBUG_WARN("Invalid IRP of length %d received, ignoring.\n%s", Stream_GetRemainingLength(irp->input), Stream_HexDump(irp->input));
		return;
	}

	Stream_Read_UINT32(irp->input, output_len);
	Stream_Read_UINT32(irp->input, input_len);
	Stream_Read_UINT32(irp->input, ioctl_code);

	Stream_Seek(irp->input, 20);	/* padding */

	// Stream_Seek(irp->input, 4);	/* TODO: parse len, le, v1 */
	// Stream_Seek(irp->input, 4);	/* 0xcccccccc */
	// Stream_Seek(irp->input, 4);	/* rpce len */

	/* [MS-RDPESC] 3.2.5.1 Sending Outgoing Messages */
	Stream_EnsureRemainingCapacity(irp->output, 2048);

	irp_result_pos = Stream_GetPosition(irp->output);

	Stream_Write_UINT32(irp->output, 0x00000000); 	/* MS-RDPEFS 
							 * OutputBufferLength
							 * will be updated 
							 * later in this 
							 * function.
							 */
	/* [MS-RPCE] 2.2.6.1 */
	Stream_Write_UINT32(irp->output, 0x00081001); /* len 8, LE, v1 */
	Stream_Write_UINT32(irp->output, 0xcccccccc); /* filler */

	output_len_pos = Stream_GetPosition(irp->output);
	Stream_Seek(irp->output, sizeof(UINT));		/* size */

	Stream_Write_UINT32(irp->output, 0x0);	/* filler */

	result_pos = Stream_GetPosition(irp->output);
	Stream_Seek(irp->output, 4);		/* result */

	/* Ensure, that this package is fully available. */
	if (Stream_GetRemainingLength(irp->input) < input_len)
	{
		DEBUG_WARN("Invalid IRP of length %d received, expected %d, ignoring.\n%s",
				Stream_GetRemainingLength(irp->input), input_len, Stream_HexDump(irp->input));
		return;
	}

	/* body. input_len contains the length of the remaining data
	 * that can be read from the current position of irp->input,
	 * so pass it on ;) */
	DEBUG_SCARD("ioctl (%08X) %s", ioctl_code, ioctlToName(ioctl_code));
	switch (ioctl_code)
	{
		case SCARD_IOCTL_ESTABLISH_CONTEXT:
			result = handle_EstablishContext(scard, irp, input_len);
			break;

		case SCARD_IOCTL_IS_VALID_CONTEXT:
			result = handle_IsValidContext(scard, irp, input_len);
			break;

		case SCARD_IOCTL_RELEASE_CONTEXT:
			result = handle_ReleaseContext(scard, irp, input_len);
			break;

		case SCARD_IOCTL_LIST_READERS_A:
			result = handle_ListReaders(scard, irp, input_len, 0);
			break;
		case SCARD_IOCTL_LIST_READERS_W:
#ifdef NO_UNICODE_SUPPORT
			result = handle_ListReaders(scard, irp, input_len, 1);
#else
			result = handle_ListReadersW(scard, irp, input_len);
#endif
			break;

		case SCARD_IOCTL_LIST_READER_GROUPS_A:
		case SCARD_IOCTL_LIST_READER_GROUPS_W:
			/* typically not used unless list_readers fail */
			result = SCARD_F_INTERNAL_ERROR;
			break;

		case SCARD_IOCTL_GET_STATUS_CHANGE_A:
			result = handle_GetStatusChange(scard, irp, input_len, 0);
			break;
		case SCARD_IOCTL_GET_STATUS_CHANGE_W:
#ifdef NO_UNICODE_SUPPORT
			result = handle_GetStatusChange(scard, irp, input_len, 1);
#else
			result = handle_GetStatusChangeW(scard, irp, input_len);
#endif
			break;

		case SCARD_IOCTL_CANCEL:
			result = handle_Cancel(scard, irp, input_len);
			break;

		case SCARD_IOCTL_CONNECT_A:
			result = handle_Connect(scard, irp, input_len, 0);
			break;
		case SCARD_IOCTL_CONNECT_W:
			result = handle_Connect(scard, irp, input_len, 1);
			break;

		case SCARD_IOCTL_RECONNECT:
			result = handle_Reconnect(scard, irp, input_len);
			break;

		case SCARD_IOCTL_DISCONNECT:
			result = handle_Disconnect(scard, irp, input_len);
			break;

		case SCARD_IOCTL_BEGIN_TRANSACTION:
			result = handle_BeginTransaction(scard, irp, input_len);
			break;

		case SCARD_IOCTL_END_TRANSACTION:
			result = handle_EndTransaction(scard, irp, input_len);
			break;

		case SCARD_IOCTL_STATE:
			result = handle_State(scard, irp, input_len);
			break;

		case SCARD_IOCTL_STATUS_A:
			result = handle_Status(scard, irp, input_len, 0);
			break;
		case SCARD_IOCTL_STATUS_W:
			result = handle_Status(scard, irp, input_len, 1);
			break;

		case SCARD_IOCTL_TRANSMIT:
			result = handle_Transmit(scard, irp, input_len);
			break;

		case SCARD_IOCTL_CONTROL:
			result = handle_Control(scard, irp, input_len);
			break;

		case SCARD_IOCTL_GETATTRIB:
			result = handle_GetAttrib(scard, irp, input_len);
			break;

		case SCARD_IOCTL_ACCESS_STARTED_EVENT:
			result = handle_AccessStartedEvent(scard, irp, input_len);
			break;

		case SCARD_IOCTL_LOCATE_CARDS_BY_ATR:
			result = handle_LocateCardsByATR(scard, irp, input_len, 0);
			break;
		case SCARD_IOCTL_LOCATE_CARDS_BY_ATR + 4:
			result = handle_LocateCardsByATR(scard, irp, input_len, 1);
			break;

		default:
			result = 0xc0000001;
			DEBUG_WARN("scard unknown ioctl 0x%x [%d]\n",
					ioctl_code, input_len);
			break;
	}

	/* look for NTSTATUS errors */
	if ((result & 0xc0000000) == 0xc0000000) {
#ifndef _WIN32
		return scard_error(scard, irp, result);
#else
		scard_error(scard, irp, result);
		return;
#endif
	}

	/* per Ludovic Rousseau, map different usage of this particular
  	 * error code between pcsc-lite & windows */
	if (result == 0x8010001F)
		result = 0x80100022;

	/* handle response packet */
	pos = Stream_GetPosition(irp->output);
	stream_len = pos - irp_result_pos - 4;	/* Value of OutputBufferLength */
	Stream_SetPosition(irp->output, irp_result_pos);
	Stream_Write_UINT32(irp->output, stream_len);

	Stream_SetPosition(irp->output, output_len_pos);
	/* Remove the effect of the MS-RPCE Common Type Header and Private
	 * Header (Sections 2.2.6.1 and 2.2.6.2).
	 */
	Stream_Write_UINT32(irp->output, stream_len - header_lengths);

	Stream_SetPosition(irp->output, result_pos);
	Stream_Write_UINT32(irp->output, result);

	Stream_SetPosition(irp->output, pos);

#ifdef WITH_DEBUG_SCARD_DISABLED
	{
		char buffer[4096] = {0x20};
		int x = 0;
		x += sprintf(&buffer[x], "\nInput: (%#x) %s\n", ioctl_code, ioctlToName(ioctl_code));
		x += winpr_HexDumpToBuffer(&buffer[x], Stream_Buffer(irp->input), Stream_Length(irp->input));
		x += sprintf(&buffer[x], "Output: (%#x) %s\n", ioctl_code, ioctlToName(ioctl_code));
		x += winpr_HexDumpToBuffer(&buffer[x], Stream_Buffer(irp->output), Stream_GetPosition(irp->output));
		DEBUG_SCARD("%s\n", buffer);
	}
	//winpr_HexDump(Stream_Buffer(irp->output), Stream_GetPosition(irp->output));
#endif
	irp->IoStatus = 0;

	irp->Complete(irp);

}

#ifndef USE_PCSC
char* pcsc_stringify_error(const long pcscError)
{
      static char strError[75];

      switch (pcscError)
      {
      case SCARD_S_SUCCESS:
            (void)strcpy_s(strError, sizeof(strError), "Command successful.");
            break;
      case SCARD_E_CANCELLED:
            (void)strcpy_s(strError, sizeof(strError), "Command cancelled.");
            break;
      case SCARD_E_CANT_DISPOSE:
            (void)strcpy_s(strError, sizeof(strError), "Cannot dispose handle.");
            break;
      case SCARD_E_INSUFFICIENT_BUFFER:
            (void)strcpy_s(strError, sizeof(strError), "Insufficient buffer.");
            break;
      case SCARD_E_INVALID_ATR:
            (void)strcpy_s(strError, sizeof(strError), "Invalid ATR.");
            break;
      case SCARD_E_INVALID_HANDLE:
            (void)strcpy_s(strError, sizeof(strError), "Invalid handle.");
            break;
      case SCARD_E_INVALID_PARAMETER:
            (void)strcpy_s(strError, sizeof(strError), "Invalid parameter given.");
            break;
      case SCARD_E_INVALID_TARGET:
            (void)strcpy_s(strError, sizeof(strError), "Invalid target given.");
            break;
      case SCARD_E_INVALID_VALUE:
            (void)strcpy_s(strError, sizeof(strError), "Invalid value given.");
            break;
      case SCARD_E_NO_MEMORY:
            (void)strcpy_s(strError, sizeof(strError), "Not enough memory.");
            break;
      case SCARD_F_COMM_ERROR:
            (void)strcpy_s(strError, sizeof(strError), "RPC transport error.");
            break;
      case SCARD_F_INTERNAL_ERROR:
            (void)strcpy_s(strError, sizeof(strError), "Internal error.");
            break;
      case SCARD_F_UNKNOWN_ERROR:
            (void)strcpy_s(strError, sizeof(strError), "Unknown error.");
            break;
      case SCARD_F_WAITED_TOO_LONG:
            (void)strcpy_s(strError, sizeof(strError), "Waited too long.");
            break;
      case SCARD_E_UNKNOWN_READER:
            (void)strcpy_s(strError, sizeof(strError), "Unknown reader specified.");
            break;
      case SCARD_E_TIMEOUT:
            (void)strcpy_s(strError, sizeof(strError), "Command timeout.");
            break;
      case SCARD_E_SHARING_VIOLATION:
            (void)strcpy_s(strError, sizeof(strError), "Sharing violation.");
            break;
      case SCARD_E_NO_SMARTCARD:
            (void)strcpy_s(strError, sizeof(strError), "No smart card inserted.");
            break;
      case SCARD_E_UNKNOWN_CARD:
            (void)strcpy_s(strError, sizeof(strError), "Unknown card.");
            break;
      case SCARD_E_PROTO_MISMATCH:
            (void)strcpy_s(strError, sizeof(strError), "Card protocol mismatch.");
            break;
      case SCARD_E_NOT_READY:
            (void)strcpy_s(strError, sizeof(strError), "Subsystem not ready.");
            break;
      case SCARD_E_SYSTEM_CANCELLED:
            (void)strcpy_s(strError, sizeof(strError), "System cancelled.");
            break;
      case SCARD_E_NOT_TRANSACTED:
            (void)strcpy_s(strError, sizeof(strError), "Transaction failed.");
            break;
      case SCARD_E_READER_UNAVAILABLE:
            (void)strcpy_s(strError, sizeof(strError), "Reader is unavailable.");
            break;
      case SCARD_W_UNSUPPORTED_CARD:
            (void)strcpy_s(strError, sizeof(strError), "Card is not supported.");
            break;
      case SCARD_W_UNRESPONSIVE_CARD:
            (void)strcpy_s(strError, sizeof(strError), "Card is unresponsive.");
            break;
      case SCARD_W_UNPOWERED_CARD:
            (void)strcpy_s(strError, sizeof(strError), "Card is unpowered.");
            break;
      case SCARD_W_RESET_CARD:
            (void)strcpy_s(strError, sizeof(strError), "Card was reset.");
            break;
      case SCARD_W_REMOVED_CARD:
            (void)strcpy_s(strError, sizeof(strError), "Card was removed.");
            break;
      //case SCARD_W_INSERTED_CARD:
            //(void)strcpy_s(strError, sizeof(strError), "Card was inserted.");
            //break;
      case SCARD_E_UNSUPPORTED_FEATURE:
            (void)strcpy_s(strError, sizeof(strError), "Feature not supported.");
            break;
      case SCARD_E_PCI_TOO_SMALL:
            (void)strcpy_s(strError, sizeof(strError), "PCI struct too small.");
            break;
      case SCARD_E_READER_UNSUPPORTED:
            (void)strcpy_s(strError, sizeof(strError), "Reader is unsupported.");
            break;
      case SCARD_E_DUPLICATE_READER:
            (void)strcpy_s(strError, sizeof(strError), "Reader already exists.");
            break;
      case SCARD_E_CARD_UNSUPPORTED:
            (void)strcpy_s(strError, sizeof(strError), "Card is unsupported.");
            break;
      case SCARD_E_NO_SERVICE:
            (void)strcpy_s(strError, sizeof(strError), "Service not available.");
            break;
      case SCARD_E_SERVICE_STOPPED:
            (void)strcpy_s(strError, sizeof(strError), "Service was stopped.");
            break;
      case SCARD_E_NO_READERS_AVAILABLE:
            (void)strcpy_s(strError, sizeof(strError), "Cannot find a smart card reader.");
            break;
      default:
            (void)sprintf_s(strError, sizeof(strError), "Unkown error: 0x%08lX", pcscError);
      };

      /* add a null byte */
      strError[sizeof(strError)-1] = '\0';

      return strError;
}
#endif

const char* ioctlToName(UINT ioctl_code)
{
	switch (ioctl_code)
	{
		case SCARD_IOCTL_ESTABLISH_CONTEXT:
			return "SCARD_IOCTL_ESTABLISH_CONTEXT";

		case SCARD_IOCTL_IS_VALID_CONTEXT:
			return "SCARD_IOCTL_IS_VALID_CONTEXT";

		case SCARD_IOCTL_RELEASE_CONTEXT:
			return "SCARD_IOCTL_RELEASE_CONTEXT";

		case SCARD_IOCTL_LIST_READERS_A:
			return "SCARD_IOCTL_LIST_READERS_A";
		case SCARD_IOCTL_LIST_READERS_W:
			return "SCARD_IOCTL_LIST_READERS_W";

		case SCARD_IOCTL_LIST_READER_GROUPS_A:
		case SCARD_IOCTL_LIST_READER_GROUPS_W:
			return "SCARD_IOCTL_LIST_READER_GROUPS_";
			/* typically not used unless list_readers fail */

		case SCARD_IOCTL_GET_STATUS_CHANGE_A:
			return "SCARD_IOCTL_GET_STATUS_CHANGE_A";
		case SCARD_IOCTL_GET_STATUS_CHANGE_W:
			return "SCARD_IOCTL_GET_STATUS_CHANGE_W";

		case SCARD_IOCTL_CANCEL:
			return "SCARD_IOCTL_CANCEL";

		case SCARD_IOCTL_CONNECT_A:
			return "SCARD_IOCTL_CONNECT_A";
		case SCARD_IOCTL_CONNECT_W:
			return "SCARD_IOCTL_CONNECT_W";

		case SCARD_IOCTL_RECONNECT:
			return "SCARD_IOCTL_RECONNECT";

		case SCARD_IOCTL_DISCONNECT:
			return "SCARD_IOCTL_DISCONNECT";

		case SCARD_IOCTL_BEGIN_TRANSACTION:
			return "SCARD_IOCTL_BEGIN_TRANSACTION";

		case SCARD_IOCTL_END_TRANSACTION:
			return "SCARD_IOCTL_END_TRANSACTION";

		case SCARD_IOCTL_STATE:
			return "SCARD_IOCTL_STATE";

		case SCARD_IOCTL_STATUS_A:
			return "SCARD_IOCTL_STATUS_A";
		case SCARD_IOCTL_STATUS_W:
			return "SCARD_IOCTL_STATUS_W";

		case SCARD_IOCTL_TRANSMIT:
			return "SCARD_IOCTL_TRANSMIT";

		case SCARD_IOCTL_CONTROL:
			return "SCARD_IOCTL_CONTROL";

		case SCARD_IOCTL_GETATTRIB:
			return "SCARD_IOCTL_GETATTRIB";

		case SCARD_IOCTL_ACCESS_STARTED_EVENT:
			return "SCARD_IOCTL_ACCESS_STARTED_EVENT";

		case SCARD_IOCTL_LOCATE_CARDS_BY_ATR:
			return "SCARD_IOCTL_LOCATE_CARDS_BY_ATR";
		case SCARD_IOCTL_LOCATE_CARDS_BY_ATR + 4:
			return "SCARD_IOCTL_LOCATE_CARDS_BY_ATR_W";

		default:
			DEBUG_WARN("scard unknown ioctl 0x%x\n", ioctl_code);
			break;
	}

	return "Unknown";
}
