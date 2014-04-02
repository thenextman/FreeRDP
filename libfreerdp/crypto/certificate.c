/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Certificate Handling
 *
 * Copyright 2011 Jiten Pathy
 * Copyright 2011-2012 Marc-Andre Moreau <marcandre.moreau@gmail.com>
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

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <winpr/crt.h>
#include <winpr/file.h>
#include <winpr/path.h>

#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <freerdp/utils/debug.h>

static const char certificate_store_dir[] = "certs";
static const char certificate_server_dir[] = "server";
static const char certificate_known_hosts_file[] = "known_hosts";

#include <freerdp/crypto/certificate.h>

DWORD MakeDirectory(char* path)
{
#ifndef WIN32
	/* Non win32 winpr handles recursize directory creation */
	return CreateDirectoryA(path, 0);
#else
	DWORD status;
	char dir[MAX_PATH] = {0};

	
	char* token = strstr(path, "\\");
	if (token) {
		do {
			strncpy(dir, path, token-path);
			if (dir[1] != ':' && dir[2] != 0x00 && ! PathFileExistsA(dir)) {
				status = CreateDirectoryA(dir, 0);
				if (! status) {
					return status;
				}
			}
		} while ((token=strstr(token+1, "\\")));
	}

	if (! PathFileExistsA(path)) {
		status = CreateDirectoryA(path, 0);
		if (! status) {
			return status;
		}
	}

	return ERROR_SUCCESS;
#endif
}

void certificate_store_init(rdpCertificateStore* certificate_store)
{
	DWORD status;
	char* server_path;
	rdpSettings* settings;

	settings = certificate_store->settings;

	if (!PathFileExistsA(settings->ConfigPath))
	{
		status = MakeDirectory(settings->ConfigPath);
		if (! status) {
			DEBUG_ERROR("Failed to create configuration directory %s. Error: %#lx", settings->ConfigPath, status);
			return;
		}

		fprintf(stderr, "creating directory %s\n", settings->ConfigPath);
	}

	certificate_store->path = GetCombinedPath(settings->ConfigPath, (char*) certificate_store_dir);

	if (!PathFileExistsA(certificate_store->path))
	{
		status = MakeDirectory(certificate_store->path);
		if (! status) {
			DEBUG_ERROR("Failed to create certificate store path %s. Error: %#lx", certificate_store->path, status);
			return;
		}
		fprintf(stderr, "creating directory %s\n", certificate_store->path);
	}

	server_path = GetCombinedPath(settings->ConfigPath, (char*) certificate_server_dir);

	if (!PathFileExistsA(server_path))
	{
		status = MakeDirectory(server_path);
		if (! status) {
			DEBUG_ERROR("Failed to create server path %s. Error: %#lx", server_path, status);
			return;
		}
		fprintf(stderr, "creating directory %s\n", server_path);
	}

	free(server_path);

	certificate_store->file = GetCombinedPath(settings->ConfigPath, (char*) certificate_known_hosts_file);

	if (PathFileExistsA(certificate_store->file) == FALSE)
	{
		certificate_store->fp = fopen((char*) certificate_store->file, "w+");

		if (certificate_store->fp == NULL)
		{
			fprintf(stderr, "certificate_store_open: error opening [%s] for writing\n", certificate_store->file);
			return;
		}

		fflush(certificate_store->fp);
	}
	else
	{
		certificate_store->fp = fopen((char*) certificate_store->file, "r+");
	}
}

int certificate_data_match(rdpCertificateStore* certificate_store, rdpCertificateData* certificate_data)
{
	FILE* fp;
	int length;
	char* data;
	char* pline;
	int match = 1;
	long int size;

	fp = certificate_store->fp;

	if (!fp)
		return match;

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	if (size < 1)
		return match;

	data = (char*) malloc(size + 2);

	if (fread(data, size, 1, fp) != 1)
	{
		free(data);
		return match;
	}

	data[size] = '\n';
	data[size + 1] = '\0';
	pline = strtok(data, "\n");

	while (pline != NULL)
	{
		length = strlen(pline);

		if (length > 0)
		{
			length = strcspn(pline, " \t");
			pline[length] = '\0';

			if (strcmp(pline, certificate_data->hostname) == 0)
			{
				pline = &pline[length + 1];

				if (strcmp(pline, certificate_data->fingerprint) == 0)
					match = 0;
				else
					match = -1;
				break;
			}
		}

		pline = strtok(NULL, "\n");
	}
	free(data);

	return match;
}

void certificate_data_replace(rdpCertificateStore* certificate_store, rdpCertificateData* certificate_data)
{
	FILE* fp;
	int length;
	char* data;
	char* pline;
	long int size;

	fp = certificate_store->fp;

	if (!fp)
		return;
	
	/* Read the current contents of the file. */
	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	if (size < 1)
		return;

	data = (char*) malloc(size + 2);

	if (fread(data, size, 1, fp) != 1)
	{
		free(data);
		return;
	}
	
	/* Write the file back out, with appropriate fingerprint substitutions */
	fp = fopen(certificate_store->file, "w+");
	data[size] = '\n';
	data[size + 1] = '\0';
	pline = strtok(data, "\n"); // xxx: use strsep

	while (pline != NULL)
	{
		length = strlen(pline);

		if (length > 0)
		{
			char* hostname = pline, *fingerprint;
			
			length = strcspn(pline, " \t");
			hostname[length] = '\0';

			/* If this is the replaced hostname, use the updated fingerprint. */
			if (strcmp(hostname, certificate_data->hostname) == 0)
				fingerprint = certificate_data->fingerprint;
			else
				fingerprint = &hostname[length + 1];
			
			fprintf(fp, "%s %s\n", hostname, fingerprint);
		}

		pline = strtok(NULL, "\n");
	}
	
	fclose(fp);
	free(data);	
}

void certificate_data_print(rdpCertificateStore* certificate_store, rdpCertificateData* certificate_data)
{
	FILE* fp;

	/* reopen in append mode */
	fp = fopen(certificate_store->file, "a");

	if (!fp)
		return;

	fprintf(fp, "%s %s\n", certificate_data->hostname, certificate_data->fingerprint);
	fclose(fp);
}

rdpCertificateData* certificate_data_new(char* hostname, char* fingerprint)
{
	rdpCertificateData* certdata;

	certdata = (rdpCertificateData *)calloc(1, sizeof(rdpCertificateData));
	if (!certdata)
		return NULL;

	certdata->hostname = _strdup(hostname);
	if (!certdata->hostname)
		goto out_free;
	certdata->fingerprint = _strdup(fingerprint);
	if (!certdata->fingerprint)
		goto out_free_hostname;
	return certdata;

out_free_hostname:
	free(certdata->hostname);
out_free:
	free(certdata);
	return NULL;
}

void certificate_data_free(rdpCertificateData* certificate_data)
{
	if (certificate_data != NULL)
	{
		free(certificate_data->hostname);
		free(certificate_data->fingerprint);
		free(certificate_data);
	}
}

rdpCertificateStore* certificate_store_new(rdpSettings* settings)
{
	rdpCertificateStore* certificate_store;

	certificate_store = (rdpCertificateStore*) malloc(sizeof(rdpCertificateStore));

	if (certificate_store != NULL)
	{
		ZeroMemory(certificate_store, sizeof(rdpCertificateStore));

		certificate_store->settings = settings;
		certificate_store_init(certificate_store);
	}

	return certificate_store;
}

void certificate_store_free(rdpCertificateStore* certstore)
{
	if (certstore != NULL)
	{
		if (certstore->fp != NULL)
			fclose(certstore->fp);

		free(certstore->path);
		free(certstore->file);
		free(certstore);
	}
}
