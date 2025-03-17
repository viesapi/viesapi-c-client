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

#ifndef __VIESAPI_API_ERROR_H__
#define __VIESAPI_API_ERROR_H__

/////////////////////////////////////////////////////////////////

#define VIESAPI_ERR_NIP_BAD					7
#define VIESAPI_ERR_CONTENT_SYNTAX			8
#define VIESAPI_ERR_INVALID_PATH			10
#define VIESAPI_ERR_EXCEPTION				11
#define VIESAPI_ERR_NO_PERMISSION			12
#define VIESAPI_ERR_GEN_INVOICES			13
#define VIESAPI_ERR_GEN_SPEC_INV			14
#define VIESAPI_ERR_SEND_INVOICE			15
#define VIESAPI_ERR_SEND_ANNOUNCEMENT		17
#define VIESAPI_ERR_INVOICE_PAYMENT			18
#define VIESAPI_ERR_SEARCH_KEY_EMPTY		20
#define VIESAPI_ERR_EUVAT_BAD				22
#define VIESAPI_ERR_VIES_SYNC				23
#define VIESAPI_ERR_PLAN_FEATURE			26
#define VIESAPI_ERR_SEARCH_TYPE				27
#define VIESAPI_ERR_NIP_FEATURE				30
#define VIESAPI_ERR_TEST_MODE				33
#define VIESAPI_ERR_ACCESS_DENIED			35
#define VIESAPI_ERR_MAINTENANCE				36
#define VIESAPI_ERR_BILLING_PLANS			37
#define VIESAPI_ERR_DOCUMENT_PDF			38
#define VIESAPI_ERR_EXPORT_PDF				39
#define VIESAPI_ERR_GROUP_CHECKS			42
#define VIESAPI_ERR_CLIENT_COUNTERS			43
#define VIESAPI_ERR_SEND_REMAINDER			47
#define VIESAPI_ERR_EXPORT_JPK				48
#define VIESAPI_ERR_GEN_ORDER_INV			49
#define VIESAPI_ERR_SEND_EXPIRATION			50
#define VIESAPI_ERR_ORDER_CANCEL			52
#define VIESAPI_ERR_AUTH_TIMESTAMP			54
#define VIESAPI_ERR_AUTH_MAC				55
#define VIESAPI_ERR_SEND_MAIL				56
#define VIESAPI_ERR_AUTH_KEY				57
#define VIESAPI_ERR_VIES_TOO_MANY_REQ		58
#define VIESAPI_ERR_VIES_UNAVAILABLE		59
#define VIESAPI_ERR_GEOCODE					60
#define VIESAPI_ERR_BATCH_SIZE				61
#define VIESAPI_ERR_BATCH_PROCESSING		62
#define VIESAPI_ERR_BATCH_REJECTED			63

#define VIESAPI_ERR_DB_AUTH_IP              101
#define VIESAPI_ERR_DB_AUTH_KEY_STATUS      102
#define VIESAPI_ERR_DB_AUTH_KEY_VALUE       103
#define VIESAPI_ERR_DB_AUTH_OVER_PLAN       104
#define VIESAPI_ERR_DB_CLIENT_LOCKED        105
#define VIESAPI_ERR_DB_CLIENT_TYPE          106
#define VIESAPI_ERR_DB_CLIENT_NOT_PAID      107
#define VIESAPI_ERR_DB_AUTH_KEYID_VALUE     108

#define VIESAPI_ERR_CLI_CONNECT             201
#define VIESAPI_ERR_CLI_RESPONSE            202
#define VIESAPI_ERR_CLI_NUMBER              203
#define VIESAPI_ERR_CLI_NIP                 204
#define VIESAPI_ERR_CLI_EUVAT               205
#define VIESAPI_ERR_CLI_EXCEPTION           206
#define VIESAPI_ERR_CLI_DATEFORMAT          207
#define VIESAPI_ERR_CLI_INPUT               208
#define VIESAPI_ERR_CLI_BATCH_SIZE			209

/////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/// <summary>
/// Get error message
/// </summary>
/// <param name="code">error code as VIESAPI_ERR_CLI_xxx value</param>
/// <returns>error message</returns>
VIESAPI_API const char* viesapi_errstr(int code);

#ifdef __cplusplus
}
#endif

/////////////////////////////////////////////////////////////////

#endif
