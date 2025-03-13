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


VIESAPI_API BOOL accountstatus_new(AccountStatus** account)
{
	AccountStatus* as = NULL;

	BOOL ret = FALSE;

	if ((as = (AccountStatus*)malloc(sizeof(AccountStatus))) == NULL) {
		goto err;
	}

	memset(as, 0, sizeof(AccountStatus));

	// ok
	*account = as;
	as = NULL;

	ret = TRUE;

err:
	accountstatus_free(&as);

	return ret;
}

VIESAPI_API void accountstatus_free(AccountStatus** account)
{
	AccountStatus* as = (account ? *account : NULL);

	if (as) {
		free(as->UID);
		free(as->Type);
		free(as->BillingPlanName);

		free(*account);
		*account = NULL;
	}
}
