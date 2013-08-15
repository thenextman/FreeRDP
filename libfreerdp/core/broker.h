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

#ifndef FREERDP_CORE_BROKER_H
#define FREERDP_CORE_BROKER_H

#include <winpr/crt.h>

#include <freerdp/freerdp.h>
#include <freerdp/settings.h>

#include "nego.h"

#define VERDE_MPC_SIGNATURE "VERDEmpc"

typedef struct
{
	char sig[8];
	UINT32 ptype;
	char username[240];
	char desktop[250];
	UINT32 reserved0;
	UINT16 width;
	UINT16 height;
	char version;
	char reserved1[1];
	char ticket[64];
	char reserved2[64];
} verdempc_t;

int broker_verde_send_connection_prefix(rdpNego* nego, char* username, char* desktop, char* ticket);

#endif /* FREERDP_CORE_BROKER_H */

