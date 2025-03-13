/**
 * Copyright 2022-2025 NETCAT (www.netcat.pl)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author NETCAT <firma@netcat.pl>
 * @copyright 2022-2025 NETCAT (www.netcat.pl)
 * @license https://www.apache.org/licenses/LICENSE-2.0
 */

#include "internal.h"
#include "viesapi.h"


BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, void* lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH || dwReason == DLL_THREAD_ATTACH) {
		CoInitialize(NULL);
	}

	return TRUE;
}

BOOL utf8_to_bstr(const char* str, BSTR* bstr)
{
	int len;

	if ((len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0)) == 0) {
		return FALSE;
	}

	*bstr = SysAllocStringLen(0, len);

	if (MultiByteToWideChar(CP_ACP, 0, str, -1, *bstr, len) == 0) {
		return FALSE;
	}

	return TRUE;
}

BOOL bstr_to_utf8(const BSTR bstr, char** str)
{
	int len;

	if ((len = WideCharToMultiByte(CP_ACP, 0, bstr, -1, NULL, 0, NULL, NULL)) == 0) {
		return FALSE;
	}

	*str = malloc(len);

	if (WideCharToMultiByte(CP_ACP, 0, bstr, -1, *str, len, NULL, NULL) == 0) {
		return FALSE;
	}

	return TRUE;
}

int bstr_replace(BSTR* bstr, BSTR rep, BSTR with)
{
	BSTR orig = (bstr ? *bstr : NULL);

	BSTR result = NULL;
	BSTR ins = NULL;
	BSTR o = NULL;
	BSTR p = NULL;

	size_t len_rep;
	size_t len_with;
	size_t len_front;
	
	int count;

	if (!orig) {
		return -1;
	}

	if (!rep) {
		return -1;
	}

	len_rep = wcslen(rep);
	
	if (len_rep == 0) {
		return -1;
	}

	if (!with) {
		with = L"";
	}

	len_with = wcslen(with);

	// count the number of replacements needed
	o = orig;
	
	for (count = 0; p = wcsstr(o, rep); ++count) {
		o = p + len_rep;
	}

	if (count == 0) {
		return 0;
	}

	result = SysAllocStringLen(NULL, (UINT)(wcslen(orig) + (len_with - len_rep) * count + 1));

	if (!result) {
		return -1;
	}

	// replace
	o = orig;
	p = result;

	while (count--) {
		ins = wcsstr(o, rep);
		len_front = (int)(ins - o);
		p = wcsncpy(p, o, len_front) + len_front;
		p = wcscpy(p, with) + len_with;
		o += len_front + len_rep;
	}

	wcscpy(p, o);
	
	SysFreeString(orig);
	*bstr = result;
	
	return count;
}
