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

#ifdef WIN32
#include <conio.h>
#endif

#ifdef WITH_WINSCARD
#pragma comment(lib,"winscard")
#endif

#ifdef HAVE__GETCH
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif

int _getch(unsigned char echo)
{
	struct termios savedState, newState;
	int c;

	if (-1 == tcgetattr(STDIN_FILENO, &savedState))
	{
		return EOF;     /* error on tcgetattr */
	}

	newState = savedState;

	if ((echo = !echo)) /* yes i'm doing an assignment in an if clause */
	{
		echo = ECHO;    /* echo bit to disable echo */
	}

	/* disable canonical input and disable echo.  set minimal input to 1. */
	newState.c_lflag &= ~(echo | ICANON);
	newState.c_cc[VMIN] = 1;

	if (-1 == tcsetattr(STDIN_FILENO, TCSANOW, &newState))
	{
		return EOF;     /* error on tcsetattr */
	}

	c = getchar();      /* block (withot spinning) until we get a keypress */

	/* restore the saved state */
	if (-1 == tcsetattr(STDIN_FILENO, TCSANOW, &savedState))
	{
		return EOF;     /* error on tcsetattr */
	}

	return c;
}
#endif

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

#if defined(WIN32) && defined(WITH_DEBUG)
	gLogMutex = CreateMutex(NULL, FALSE, NULL);
#endif

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

	status = freerdp_client_settings_parse_command_line(settings, context->argc, context->argv);

	status = freerdp_client_settings_command_line_status_print(settings, status, context->argc, context->argv);

	if (status)
	{
		freerdp_client_context_free(context);
		_getch();
		return 0;
	}

	freerdp_client_start(context);

	thread = freerdp_client_get_thread(context);

	WaitForSingleObject(thread, INFINITE);

	GetExitCodeThread(thread, &dwExitCode);

	freerdp_client_stop(context);

	freerdp_client_context_free(context);

	return 0;
}
