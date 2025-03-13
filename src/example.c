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

#pragma warning(disable: 4333 4996)

#define _CRT_SECURE_NO_DEPRECATE
#define _WIN32_WINNT	0x0400

#include <windows.h>
#include <stdio.h>

#include "viesapi.h"

int main()
{
	VIESAPIClient* viesapi = NULL;
	
	AccountStatus* account = NULL;
	VIESData* vies = NULL;
	VIESData* vies_parsed = NULL;

	const char* vat_eu = "PL7171642051";

	// Create client object and establish connection to the production system
	// id – API identifier
	// key – API key (keep it secret)
	// viesapi_new_prod(&viesapi, "id", "key");

	// Create client object and establish connection to the test system
	if (!viesapi_new_test(&viesapi)) {
		goto err;
	}

	// Get current account status
	account = viesapi_get_account_status(viesapi);

	if (account != NULL) {
		printf("Plan name:         %s\n", account->BillingPlanName);
		printf("Price:             %.2f\n", account->SubscriptionPrice);
		printf("Number of queries: %d\n", account->TotalCount);
	}
	else {
		printf("Error: %s (code: %d)\n", viesapi_get_last_err(viesapi), viesapi_get_last_err_code(viesapi));
	}

	// Get VIES data from VIES system
	vies = viesapi_get_vies_data(viesapi, vat_eu);

	if (vies != NULL) {
		printf("Country:  %s\n", vies->CountryCode);
		printf("VAT ID:   %s\n", vies->VATNumber);
		printf("Is valid: %d\n", vies->Valid);
	}
	else {
		printf("Error: %s (code: %d)\n", viesapi_get_last_err(viesapi), viesapi_get_last_err_code(viesapi));
	}

	// Get VIES data from VIES system with parsed trader address components
	vies_parsed = viesapi_get_vies_data_parsed(viesapi, vat_eu);

	if (vies_parsed != NULL) {
		printf("Country:  %s\n", vies_parsed->CountryCode);
		printf("VAT ID:   %s\n", vies_parsed->VATNumber);
		printf("Is valid: %d\n", vies_parsed->Valid);

		if (vies_parsed->TraderAddressComponents) {
			printf("Country:      %s\n", vies_parsed->TraderAddressComponents->Country);
			printf("PostalCode:   %s\n", vies_parsed->TraderAddressComponents->PostalCode);
			printf("City:         %s\n", vies_parsed->TraderAddressComponents->City);
			printf("Street:       %s\n", vies_parsed->TraderAddressComponents->Street);
			printf("StreetNumber: %s\n", vies_parsed->TraderAddressComponents->StreetNumber);
			printf("HouseNumber:  %s\n", vies_parsed->TraderAddressComponents->HouseNumber);
		}
	}
	else {
		printf("Error: %s (code: %d)\n", viesapi_get_last_err(viesapi), viesapi_get_last_err_code(viesapi));
	}

err:
	viesapi_free(&viesapi);

	accountstatus_free(&account);
	viesdata_free(&vies);
	viesdata_free(&vies_parsed);

	return 0;
}

