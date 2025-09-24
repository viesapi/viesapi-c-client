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


static const char* _viesapi_codes[] = {
    /* VIESAPI_ERR_CLI_CONNECT */     "Failed to connect to the VIES API service",
    /* VIESAPI_ERR_CLI_RESPONSE */    "VIES API service response has invalid format",
    /* VIESAPI_ERR_CLI_NUMBER */      "Invalid number type",
    /* VIESAPI_ERR_CLI_NIP */         "NIP is invalid",
    /* VIESAPI_ERR_CLI_EUVAT */       "EU VAT ID is invalid",
    /* VIESAPI_ERR_CLI_EXCEPTION */   "Function generated an exception",
    /* VIESAPI_ERR_CLI_DATEFORMAT */  "Date has an invalid format",
    /* VIESAPI_ERR_CLI_INPUT */       "Invalid input parameter",
    /* VIESAPI_ERR_CLI_BATCH_SIZE */  "Batch size limit exceeded [3-99]"
};

VIESAPI_API const char* viesapi_errstr(int code)
{
    if (code < VIESAPI_ERR_CLI_CONNECT || code > VIESAPI_ERR_CLI_BATCH_SIZE) {
        return NULL;
    }

    return _viesapi_codes[code - VIESAPI_ERR_CLI_CONNECT];
}
