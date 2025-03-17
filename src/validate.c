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


#define CHAR2NUM(c)		((c) - 48)

static BOOL _viesapi_isdigit(char* str, int start, int count)
{
	int i;

	for (i = start; i < (start + count); i++) {
		if (!isdigit(str[i])) {
			return FALSE;
		}
	}

	return TRUE;
}

static BOOL _viesapi_isalpha(char* str, int start, int count)
{
	int i;

	for (i = start; i < (start + count); i++) {
		if (!isalpha(str[i])) {
			return FALSE;
		}
	}

	return TRUE;
}

static BOOL _viesapi_isalnum(char* str, int start, int count)
{
	int i;

	for (i = start; i < (start + count); i++) {
		if (!isalnum(str[i])) {
			return FALSE;
		}
	}

	return TRUE;
}

static BOOL _viesapi_isalnum_ext(char* str, int start, int count)
{
	int i;

	for (i = start; i < (start + count); i++) {
		if (!isalnum(str[i]) && str[i] != '+' && str[i] != '*') {
			return FALSE;
		}
	}

	return TRUE;
}

/////////////////////////////////////////////////////////////////

VIESAPI_API char* viesapi_nip_normalize(const char* nip)
{
	char num[MAX_NUMBER];

	int len;
	int p;
	int i;

	if (!nip || (len = (int)strlen(nip)) < 10 || len > 13) {
		return NULL;
	}

	// [0-9]{10}
	memset(num, 0, sizeof(num));

	for (i = 0, p = 0; i < len; i++) {
		if (isdigit(nip[i])) {
			num[p++] = nip[i];
		}
	}

	if (strlen(num) != 10) {
		return NULL;
	}

	return strdup(num);
}

VIESAPI_API BOOL viesapi_nip_is_valid(const char* nip)
{
	char* num = viesapi_nip_normalize(nip);

	int w[] = {
		6, 5, 7, 2, 3, 4, 5, 6, 7
	};

	int wlen = 9;
	int sum = 0;
	int i;

	if (!num) {
		return FALSE;
	}

	for (i = 0; i < wlen; i++) {
		sum += CHAR2NUM(num[i]) * w[i];
	}

	sum %= 11;

	if (sum != CHAR2NUM(num[9])) {
		free(num);
		return FALSE;
	}

	free(num);

	return TRUE;
}

VIESAPI_API char* viesapi_euvat_normalize(const char* euvat)
{
	char num[MAX_NUMBER];

	int len;
	int p;
	int i;

	if (!euvat || (len = (int)strlen(euvat)) == 0) {
		return NULL;
	}

	memset(num, 0, sizeof(num));

	for (i = 0, p = 0; i < len; i++) {
		if ((isalnum(euvat[i]) || euvat[i] == '+' || euvat[i] == '*') && p < (sizeof(num) - 1)) {
			num[p++] = toupper(euvat[i]);
		}
	}

	if ((len = (int)strlen(num)) < 4 || len > 14) {
		return NULL;
	}

	return strdup(num);
}

VIESAPI_API BOOL viesapi_euvat_is_valid(const char* euvat)
{
	BOOL ret = FALSE;

	char* num = viesapi_euvat_normalize(euvat);

	int len;

	if (!num) {
		goto err;
	}

	len = (int)strlen(num);

	if (strncmp(num, "AT", 2) == 0) {
		// ATU\\d{8}
		if (len != (3 + 8) || num[2] != 'U') {
			goto err;
		}

		if (!_viesapi_isdigit(num, 3, 8)) {
			goto err;
		}
	}
	else if (strncmp(num, "BE", 2) == 0) {
		// BE[0-1]{1}\d{9}
		if (len != (3 + 9) || (num[2] != '0' && num[2] != '1')) {
			goto err;
		}

		if (!_viesapi_isdigit(num, 3, 9)) {
			goto err;
		}
	}
	else if (strncmp(num, "BG", 2) == 0) {
		// BG\\d{9,10}
		if (len < (2 + 9) || len > (2 + 10)) {
			goto err;
		}

		if (!_viesapi_isdigit(num, 2, len - 2)) {
			goto err;
		}
	}
	else if (strncmp(num, "CY", 2) == 0) {
		// CY\d{8}[A-Z]{1}
		if (len != (2 + 8 + 1) || !isalpha(num[len - 1])) {
			goto err;
		}

		if (!_viesapi_isdigit(num, 2, 8)) {
			goto err;
		}
	}
	else if (strncmp(num, "CZ", 2) == 0) {
		// CZ\\d{8,10}
		if (len < (2 + 8) || len > (2 + 10)) {
			goto err;
		}

		if (!_viesapi_isdigit(num, 2, len - 2)) {
			goto err;
		}
	}
	else if (strncmp(num, "DE", 2) == 0) {
		// DE\\d{9}
		if (len != (2 + 9)) {
			goto err;
		}

		if (!_viesapi_isdigit(num, 2, 9)) {
			goto err;
		}
	}
	else if (strncmp(num, "DK", 2) == 0) {
		// DK\\d{8}
		if (len != (2 + 8)) {
			goto err;
		}

		if (!_viesapi_isdigit(num, 2, 8)) {
			goto err;
		}
	}
	else if (strncmp(num, "EE", 2) == 0) {
		// EE\\d{9}
		if (len != (2 + 9)) {
			goto err;
		}

		if (!_viesapi_isdigit(num, 2, 9)) {
			goto err;
		}
	}
	else if (strncmp(num, "EL", 2) == 0) {
		// EL\\d{9}
		if (len != (2 + 9)) {
			goto err;
		}

		if (!_viesapi_isdigit(num, 2, 9)) {
			goto err;
		}
	}
	else if (strncmp(num, "ES", 2) == 0) {
		// ES[A-Z0-9]{1}\d{7}[A-Z0-9]{1}
		if (len != (2 + 1 + 7 + 1)) {
			goto err;
		}

		if (!_viesapi_isalnum(num, 2, 1)) {
			goto err;
		}

		if (!_viesapi_isdigit(num, 3, 7)) {
			goto err;
		}

		if (!_viesapi_isalnum(num, 10, 1)) {
			goto err;
		}
	}
	else if (strncmp(num, "FI", 2) == 0) {
		// FI\\d{8}
		if (len != (2 + 8)) {
			goto err;
		}

		if (!_viesapi_isdigit(num, 2, 8)) {
			goto err;
		}
	}
	else if (strncmp(num, "FR", 2) == 0) {
		// FR[A-Z0-9]{2}\\d{9}
		if (len != (2 + 2 + 9)) {
			goto err;
		}

		if (!_viesapi_isalnum(num, 2, 2)) {
			goto err;
		}

		if (!_viesapi_isdigit(num, 4, 9)) {
			goto err;
		}
	}
	else if (strncmp(num, "HR", 2) == 0) {
		// HR\\d{11}
		if (len != (2 + 11)) {
			goto err;
		}

		if (!_viesapi_isdigit(num, 2, 11)) {
			goto err;
		}
	}
	else if (strncmp(num, "HU", 2) == 0) {
		// HU\\d{8}
		if (len != (2 + 8)) {
			goto err;
		}

		if (!_viesapi_isdigit(num, 2, 8)) {
			goto err;
		}
	}
	else if (strncmp(num, "IE", 2) == 0) {
		// IE[A-Z0-9+*]{8,9}
		if (len < (2 + 8) || len > (2 + 9)) {
			goto err;
		}

		if (!_viesapi_isalnum_ext(num, 2, len - 2)) {
			goto err;
		}
	}
	else if (strncmp(num, "IT", 2) == 0) {
		// IT\\d{11}
		if (len != (2 + 11)) {
			goto err;
		}

		if (!_viesapi_isdigit(num, 2, 11)) {
			goto err;
		}
	}
	else if (strncmp(num, "LT", 2) == 0) {
		// LT\\d{9,12}
		if (len < (2 + 9) || len > (2 + 12)) {
			goto err;
		}

		if (!_viesapi_isdigit(num, 2, len - 2)) {
			goto err;
		}
	}
	else if (strncmp(num, "LU", 2) == 0) {
		// LU\\d{8}
		if (len != (2 + 8)) {
			goto err;
		}

		if (!_viesapi_isdigit(num, 2, 8)) {
			goto err;
		}
	}
	else if (strncmp(num, "LV", 2) == 0) {
		// LV\\d{11}
		if (len != (2 + 11)) {
			goto err;
		}

		if (!_viesapi_isdigit(num, 2, 11)) {
			goto err;
		}
	}
	else if (strncmp(num, "MT", 2) == 0) {
		// MT\\d{8}
		if (len != (2 + 8)) {
			goto err;
		}

		if (!_viesapi_isdigit(num, 2, 8)) {
			goto err;
		}
	}
	else if (strncmp(num, "NL", 2) == 0) {
		// NL[A-Z0-9+*]{12}
		if (len != (2 + 12)) {
			goto err;
		}

		if (!_viesapi_isalnum_ext(num, 2, 12)) {
			goto err;
		}
	}
	else if (strncmp(num, "PL", 2) == 0) {
		// PL\\d{10}
		if (len != (2 + 10)) {
			goto err;
		}

		if (!_viesapi_isdigit(num, 2, 10)) {
			goto err;
		}
	}
	else if (strncmp(num, "PT", 2) == 0) {
		// PT\\d{9}
		if (len != (2 + 9)) {
			goto err;
		}

		if (!_viesapi_isdigit(num, 2, 9)) {
			goto err;
		}
	}
	else if (strncmp(num, "RO", 2) == 0) {
		// RO\\d{2,10}
		if (len < (2 + 2) || len > (2 + 10)) {
			goto err;
		}

		if (!_viesapi_isdigit(num, 2, len - 2)) {
			goto err;
		}
	}
	else if (strncmp(num, "SE", 2) == 0) {
		// SE\\d{12}
		if (len != (2 + 12)) {
			goto err;
		}

		if (!_viesapi_isdigit(num, 2, 12)) {
			goto err;
		}
	}
	else if (strncmp(num, "SI", 2) == 0) {
		// SI\\d{8}
		if (len != (2 + 8)) {
			goto err;
		}

		if (!_viesapi_isdigit(num, 2, 8)) {
			goto err;
		}
	}
	else if (strncmp(num, "SK", 2) == 0) {
		// SK\\d{10}
		if (len != (2 + 10)) {
			goto err;
		}

		if (!_viesapi_isdigit(num, 2, 10)) {
			goto err;
		}
	}
	else if (strncmp(num, "XI", 2) == 0) {
		// XI[A-Z0-9]{5,12}
		if (len < (2 + 5) || len > (2 + 12)) {
			goto err;
		}

		if (!_viesapi_isalnum(num, 2, len - 2)) {
			goto err;
		}
	}
	else {
		goto err;
	}

	if (strncmp(num, "PL", 2) == 0 && !viesapi_nip_is_valid(num + 2)) {
		goto err;
	}

	ret = TRUE;

err:
	free(num);

	return ret;
}

VIESAPI_API BOOL viesapi_is_uuid(const char* uuid)
{
	const char* s = uuid;
	
	int tmp;

	if (!uuid || strlen(uuid) != 36) {
		return FALSE;
	}

	while (*s) {
		if (isspace(*s++)) {
			return FALSE;
		}
	}

	return (s - uuid == 36 && sscanf(uuid, "%4x%4x-%4x-%4x-%4x-%4x%4x%4x%c",
		&tmp, &tmp, &tmp, &tmp, &tmp, &tmp, &tmp, &tmp, &tmp) == 8);
}
