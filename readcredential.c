/* Proxytunnel - (C) 2024    Jos Visser / Mark Janssen / Hartmut Birr          */
/* Contact:                  josv@osp.nl / maniac@maniac.nl / e9hack@gmail.com */

/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <stdio.h>
#include <windef.h>
#include <wincred.h>
#include <winerror.h>
#include <wchar.h>

#include "config.h"

#ifndef _countof
#define _countof(x)	sizeof((x)) / sizeof((x)[0])
#endif

#ifndef CRED_PACK_PROTECTED_CREDENTIALS
// missing in wincred.h
#define CRED_PACK_PROTECTED_CREDENTIALS		0x1
#endif

char* getcred_x(const char *server, const char* user) {
	static char buf[_PASSWORD_LEN + 1];
	char *tmp = (char*)strchr(server, ':');
	const char* proto = "http";
	char *target;
	BOOL res;
	BOOL found = FALSE;
	PCREDENTIAL pcred;
	unsigned tmp_len;
	
	memset(buf, 0, sizeof(buf));

	if (tmp) {
		tmp_len = tmp - server;
		if ((unsigned)atoi(tmp + 1) == 443)
			proto = "https";
		tmp = (char*)alloca(tmp_len + 1);
		strncpy(tmp, server, tmp_len);
		tmp[tmp_len] = 0;
		server = tmp;
	}

	tmp_len = strlen(server) + sizeof("proxytunnel:://@") + strlen(proto) + strlen(user);
	target = (char*)alloca(tmp_len);
	sprintf(target, "proxytunnel:%s://%s", proto, server);

	pcred = NULL;
	res = CredRead(target, CRED_TYPE_GENERIC, 0, &pcred);
	if (res) { 
		if (pcred && pcred->UserName && !strcmp(user, pcred->UserName)) {
			tmp_len = pcred->CredentialBlobSize / sizeof(wchar_t);
			if (tmp_len < _countof(buf)) {
				snprintf(buf, tmp_len, "%S", (wchar_t*)pcred->CredentialBlob);
				buf[tmp_len] = 0;
			}
			CredFree(pcred);
			return buf;
		}
		CredFree(pcred);
		res = FALSE;
		found = TRUE;
	}

	if (!res) {
		sprintf(target, "proxytunnel:%s://%s@%s", proto, user, server);
		pcred = NULL;
		res = CredRead(target, CRED_TYPE_GENERIC, 0, &pcred);
		if (res) {
			tmp_len = pcred->CredentialBlobSize / sizeof(wchar_t);
			if (tmp_len < _countof(buf)) {
				snprintf(buf, tmp_len, "%S", (wchar_t*)pcred->CredentialBlob);
				buf[tmp_len] = 0;
			}
			CredFree(pcred);
			return buf;
		}
	}

	if (!res)
	{
		wchar_t *w_user;
		wchar_t *w_message;
		CREDUI_INFOW cui;
		PBYTE authInBuffer;
		ULONG authInBufferSize = 0;
		DWORD size;
		DWORD authPackage = 0;
		PVOID authOutBuffer;
		ULONG authOutBufferSize = 0;

		tmp_len = sizeof("Enter credentials for '://@'") +
					strlen(user) + strlen(proto) + strlen(server);
		w_message = (wchar_t*)alloca(tmp_len * sizeof(wchar_t));
		if (found) {

#ifdef __GNUC__
			swprintf(w_message, tmp_len, L"Enter credentials for '%s://%s@%s'", proto, user, server);
#else
			swprintf(w_message, tmp_len, L"Enter credentials for '%S://%S@%S'", proto, user, server);
#endif
		} else {
#ifdef __GNUC__
			swprintf(w_message, tmp_len, L"Enter credentials for '%s://%s'", proto, server);
#else
			swprintf(w_message, tmp_len, L"Enter credentials for '%S://%S'", proto, server);
#endif
		}

		tmp_len = strlen(user) + 1;
		w_user = (wchar_t*)alloca(tmp_len * sizeof(wchar_t));
#ifdef __GNUC__
		swprintf(w_user, tmp_len, L"%s", user);
#else
		swprintf(w_user, tmp_len, L"%S", user);
#endif

		memset(&cui, 0, sizeof(cui));
		cui.cbSize = sizeof(cui);
		cui.hwndParent = NULL;
		cui.pszMessageText = w_message;
		cui.pszCaptionText = L"Proxytunnel Credential Manager";
		cui.hbmBanner = NULL;

		authInBuffer = NULL;
		authInBufferSize = 0;

		res = CredPackAuthenticationBufferW(CRED_PACK_PROTECTED_CREDENTIALS,
											w_user,
											L"",
											authInBuffer,
											&authInBufferSize);

		authInBuffer = (PBYTE)alloca(authInBufferSize);

		res = CredPackAuthenticationBufferW(CRED_PACK_PROTECTED_CREDENTIALS,
											w_user,
											L"",
											authInBuffer,
											&authInBufferSize);

		// only the unicode variant of this function does work on windows 10
		size = CredUIPromptForWindowsCredentialsW(&cui,
												  0,
												  &(authPackage),
												  authInBuffer,
												  authInBufferSize,
												  &authOutBuffer,
												  &authOutBufferSize, 
												  NULL,
												  CREDUIWIN_GENERIC);

		if (size == ERROR_SUCCESS) {
			wchar_t *pwsUserName;
			DWORD cbSizeUserName = 0;
			wchar_t *pwsDomainName;
			ULONG cbSizeDomainName = 0;
			wchar_t *pwsPassword;
			DWORD cbSizePassword = 0;

			res = CredUnPackAuthenticationBufferW(CRED_PACK_PROTECTED_CREDENTIALS,
												  authOutBuffer,
												  authOutBufferSize,
												  NULL,
												  &cbSizeUserName,
												  NULL,
												  &cbSizeDomainName,
												  NULL,
												  &cbSizePassword);

			pwsUserName = cbSizeUserName ? (wchar_t*)alloca(cbSizeUserName * sizeof(wchar_t)) : NULL;
			pwsDomainName = cbSizeDomainName ? (wchar_t*)alloca(cbSizeDomainName * sizeof(wchar_t)) : NULL;
			pwsPassword = cbSizePassword ? (wchar_t*)alloca(cbSizePassword * sizeof(wchar_t)) : NULL;

			res = CredUnPackAuthenticationBufferW(CRED_PACK_PROTECTED_CREDENTIALS,
												  authOutBuffer,
												  authOutBufferSize,
												  pwsUserName,
												  &cbSizeUserName,
												  pwsDomainName,
												  &cbSizeDomainName,
												  pwsPassword,
												  &cbSizePassword);

			memset(authOutBuffer, 0, authOutBufferSize);

			if (res) {
				CREDENTIALA cred;
				if (cbSizeUserName <= _countof(buf)) {
					sprintf(buf, "%S", pwsPassword);
				}

				if (!found)
					sprintf(target, "proxytunnel:%s://%s", proto, server);

				memset(&cred, 0, sizeof(cred));
				cred.Type = CRED_TYPE_GENERIC;
				cred.TargetName = target;
				cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
				cred.CredentialBlobSize = cbSizePassword * sizeof(wchar_t);
				cred.CredentialBlob = (LPBYTE)pwsPassword;
				cred.UserName = (char*)user;

				res = CredWrite(&cred, 0);

				memset(pwsUserName, 0, cbSizeUserName * sizeof(wchar_t));
				memset(pwsDomainName, 0, cbSizeDomainName * sizeof(wchar_t));
				memset(pwsPassword, 0, cbSizePassword * sizeof(wchar_t));
			}
		}
	}

	return buf;
}
