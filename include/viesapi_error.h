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

#ifndef __VIESAPI_API_ERROR_H__
#define __VIESAPI_API_ERROR_H__

/////////////////////////////////////////////////////////////////

#define VIESAPI_ERR_NIP_EMPTY               1
#define VIESAPI_ERR_NIP_UNKNOWN             2
#define VIESAPI_ERR_GUS_LOGIN               3
#define VIESAPI_ERR_GUS_CAPTCHA             4
#define VIESAPI_ERR_GUS_SYNC                5
#define VIESAPI_ERR_NIP_UPDATE              6
#define VIESAPI_ERR_NIP_BAD                 7
#define VIESAPI_ERR_CONTENT_SYNTAX          8
#define VIESAPI_ERR_NIP_NOT_ACTIVE          9
#define VIESAPI_ERR_INVALID_PATH            10
#define VIESAPI_ERR_EXCEPTION               11
#define VIESAPI_ERR_NO_PERMISSION           12
#define VIESAPI_ERR_GEN_INVOICES            13
#define VIESAPI_ERR_GEN_SPEC_INV            14
#define VIESAPI_ERR_SEND_INVOICE            15
#define VIESAPI_ERR_PREMIUM_FEATURE         16
#define VIESAPI_ERR_SEND_ANNOUNCEMENT       17
#define VIESAPI_ERR_INVOICE_PAYMENT         18
#define VIESAPI_ERR_REGON_BAD               19
#define VIESAPI_ERR_SEARCH_KEY_EMPTY        20
#define VIESAPI_ERR_KRS_BAD                 21
#define VIESAPI_ERR_EUVAT_BAD               22
#define VIESAPI_ERR_VIES_SYNC               23
#define VIESAPI_ERR_CEIDG_SYNC              24
#define VIESAPI_ERR_RANDOM_NUMBER           25
#define VIESAPI_ERR_PLAN_FEATURE            26
#define VIESAPI_ERR_SEARCH_TYPE             27
#define VIESAPI_ERR_PPUMF_SYNC              28
#define VIESAPI_ERR_PPUMF_DIRECT            29
#define VIESAPI_ERR_NIP_FEATURE             30
#define VIESAPI_ERR_REGON_FEATURE           31
#define VIESAPI_ERR_KRS_FEATURE             32
#define VIESAPI_ERR_TEST_MODE               33
#define VIESAPI_ERR_ACTIVITY_CHECK          34
#define VIESAPI_ERR_ACCESS_DENIED           35
#define VIESAPI_ERR_MAINTENANCE             36
#define VIESAPI_ERR_BILLING_PLANS           37
#define VIESAPI_ERR_DOCUMENT_PDF            38
#define VIESAPI_ERR_EXPORT_PDF              39
#define VIESAPI_ERR_RANDOM_TYPE             40
#define VIESAPI_ERR_LEGAL_FORM              41
#define VIESAPI_ERR_GROUP_CHECKS            42
#define VIESAPI_ERR_CLIENT_COUNTERS         43
#define VIESAPI_ERR_URE_SYNC                44
#define VIESAPI_ERR_URE_DATA                45
#define VIESAPI_ERR_DKN_BAD                 46
#define VIESAPI_ERR_SEND_REMAINDER          47
#define VIESAPI_ERR_EXPORT_JPK              48
#define VIESAPI_ERR_GEN_ORDER_INV           49
#define VIESAPI_ERR_SEND_EXPIRATION         50
#define VIESAPI_ERR_IBAN_SYNC               51
#define VIESAPI_ERR_ORDER_CANCEL            52
#define VIESAPI_ERR_WHITELIST_CHECK         53
#define VIESAPI_ERR_AUTH_TIMESTAMP          54
#define VIESAPI_ERR_AUTH_MAC                55
#define VIESAPI_ERR_IBAN_BAD                56

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
