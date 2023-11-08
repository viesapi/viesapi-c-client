/**
 * Copyright 2022-2023 NETCAT (www.netcat.pl)
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
 * @copyright 2022-2023 NETCAT (www.netcat.pl)
 * @license https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef __VIESAPI_API_CLIENT_H__
#define __VIESAPI_API_CLIENT_H__

/////////////////////////////////////////////////////////////////

#define VIESAPI_VERSION			"1.2.6"

#define VIESAPI_PRODUCTION_URL	"https://viesapi.eu/api"

#define VIESAPI_TEST_URL		"https://viesapi.eu/api-test"
#define VIESAPI_TEST_ID			"test_id"
#define VIESAPI_TEST_KEY		"test_key"

/////////////////////////////////////////////////////////////////

/// <summary>
/// Number types
/// </summary>
typedef enum Number {
	EUVAT = 1,
	NIP,
} Number;

/////////////////////////////////////////////////////////////////

/// <summary>
/// VIES API service client
/// </summary>
typedef struct VIESAPIClient {
	char* url;
	char* id;
	char* key;

	char* app;

    int err_code;
	char* err;
} VIESAPIClient;

/////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/// <summary>
/// Create new client object
/// </summary>
/// <param name="viesapi">pointer for a new client object</param>
/// <param name="url">VIES API service URL address</param>
/// <param name="id">API key identifier</param>
/// <param name="key">API key</param>
/// <returns>TRUE if succeeded</returns>
VIESAPI_API BOOL viesapi_new(VIESAPIClient** viesapi, const char* url, const char* id, const char* key);

/// <summary>
/// Create client object and establish connection to the production system
/// </summary>
/// <param name="viesapi">pointer for a new client object</param>
/// <param name="id">API key identifier</param>
/// <param name="key">API key (keep it secret)</param>
/// <returns>TRUE if succeeded</returns>
VIESAPI_API BOOL viesapi_new_prod(VIESAPIClient** viesapi, const char* id, const char* key);

/// <summary>
/// Create client object and establish connection to the test system
/// </summary>
/// <param name="viesapi">pointer for a new client object</param>
/// <returns>TRUE if succeeded</returns>
VIESAPI_API BOOL viesapi_new_test(VIESAPIClient** viesapi);

/// <summary>
/// Free client object
/// </summary>
/// <param name="viesapi">pointer to an object to free</param>
/// <returns></returns>
VIESAPI_API void viesapi_free(VIESAPIClient** viesapi);

/// <summary>
/// Get last error code
/// </summary>
/// <param name="viesapi">client object</param>
/// <returns>error code as VIESAPI_ERR_xxx value</returns>
VIESAPI_API int viesapi_get_last_err_code(VIESAPIClient* viesapi);

/// <summary>
/// Get last error message
/// </summary>
/// <param name="viesapi">client object</param>
/// <returns>error code as text</returns>
VIESAPI_API char* viesapi_get_last_err(VIESAPIClient* viesapi);

/// <summary>
/// Get VIES data for specified number from EU VIES system
/// </summary>
/// <param name="viesapi">client object</param>
/// <param name="euvat">EU VAT number with 2-letter country prefix</param>
/// <returns>VIES data or NULL in case of error</returns>
VIESAPI_API VIESData* viesapi_get_vies_data(VIESAPIClient* viesapi, const char* euvat);

/// <summary>
/// Get current account status
/// </summary>
/// <param name="viesapi">client object</param>
/// <returns>account status or NULL in case of error</returns>
VIESAPI_API AccountStatus* viesapi_get_account_status(VIESAPIClient* viesapi);

#ifdef __cplusplus
}
#endif

/////////////////////////////////////////////////////////////////

#endif
