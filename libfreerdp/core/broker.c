/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Custom Connection Broker
 *
 * Copyright 2013 Marc-Andre Moreau <marcandre.moreau@gmail.com>
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

#include <winpr/crt.h>

#include "broker.h"

int broker_verde_send_connection_prefix(rdpNego* nego, char* username, char* desktop, char* ticket)
{
	wStream* s;
	verdempc_t mpc;

	ZeroMemory(&mpc, sizeof(verdempc_t));
	strcpy(mpc.sig, VERDE_MPC_SIGNATURE);

	mpc.ptype = 1;
	mpc.version = 1;

	strcpy(mpc.username, username);
	strcpy(mpc.desktop, desktop);
	strcpy(mpc.ticket, ticket);

	if (!nego_tcp_connect(nego))
		return -1;

	s = Stream_New(NULL, 640);

	Stream_Write(s, mpc.sig, 8); /* sig (8 bytes) */
	Stream_Write_UINT32(s, mpc.ptype); /* ptype (4 bytes) */
	Stream_Write(s, mpc.username, 240); /* username (240 bytes) */
	Stream_Write(s, mpc.desktop, 250); /* username (250 bytes) */
	Stream_Write_UINT32(s, mpc.reserved0); /* reserved0 (4 bytes) */
	Stream_Write_UINT16(s, mpc.width); /* width (2 bytes) */
	Stream_Write_UINT16(s, mpc.height); /* height (2 bytes) */
	Stream_Write_UINT8(s, mpc.version); /* version (1 byte) */
	Stream_Write_UINT8(s, mpc.reserved1[1]); /* reserved1 (1 byte) */
	Stream_Write(s, mpc.ticket, 64); /* ticket (64 bytes) */
	Stream_Write(s, mpc.reserved2, 64); /* ticket (64 bytes) */

	Stream_SealLength(s);

	if (transport_write(nego->transport, s) < 0)
		return FALSE;

	Stream_Free(s, TRUE);

	return 0;
}

#define TEST_VERDE_BROKER_HOSTNAME	"corp.contoso.com"
#define TEST_VERDE_USERNAME		"johndoe@corp.contoso.com"
#define TEST_VERDE_DESKTOP_NAME		"CONTOSO"
#define TEST_VERDE_SECURITY_TICKET	"3mc6yjKrLjBx/HRP2e612il+Oo6MM+aiywA5fD3IqWRH4zX1sM"

int broker_verde_connect(rdpNego* nego)
{
	rdpSettings* settings = nego->settings;

	printf("VerdeBrokerConnect\n");

	settings->VerdeBrokerHostname = _strdup(TEST_VERDE_BROKER_HOSTNAME);

	if (!settings->VerdeBrokerPort)
		settings->VerdeBrokerPort = VERDE_BROKER_DEFAULT_PORT;

	settings->VerdeUsername = _strdup(TEST_VERDE_USERNAME);

	settings->VerdeDesktopName = _strdup(TEST_VERDE_DESKTOP_NAME);

	settings->VerdeSecurityTicket = _strdup(TEST_VERDE_SECURITY_TICKET);

	nego_set_target(nego, settings->VerdeBrokerHostname, settings->VerdeBrokerPort);

	broker_verde_send_connection_prefix(nego, settings->VerdeUsername,
			settings->VerdeDesktopName, settings->VerdeSecurityTicket);

	return 0;
}

int nego_custom_broker_connect(rdpNego* nego)
{
	int status;

	status = broker_verde_connect(nego);

	return status;
}
