/**
 * Copyright 2022 NETCAT (www.netcat.pl)
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
 * @copyright 2022 NETCAT (www.netcat.pl)
 * @license https://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef __VIESAPI_API_ACCOUNT_H__
#define __VIESAPI_API_ACCOUNT_H__

/////////////////////////////////////////////////////////////////

/// <summary>
/// Account status information
/// </summary>
typedef struct AccountStatus {

	/// <summary>
	/// Create new object
	/// </summary>
	char* UID;

	/// <summary>
	/// Account type
	/// </summary>
	char* Type;

	/// <summary>
	/// Account validity date (only for pre-paid accounts)
	/// </summary>
	time_t ValidTo;

	/// <summary>
	/// Billing plan name
	/// </summary>
	char* BillingPlanName;

	/// <summary>
	/// Monthly subscription net price
	/// </summary>
	double SubscriptionPrice;

	/// <summary>
	/// Single query cost off-plan (only for standard plans)
	/// </summary>
	double ItemPrice;

	/// <summary>
	/// Net price of a single query for an individual plan
	/// </summary>
	double ItemPriceStatus;

	/// <summary>
	/// Maximum number of queries in the plan
	/// </summary>
	int Limit;

	/// <summary>
	/// The minimum time interval between queries
	/// </summary>
	int RequestDelay;

	/// <summary>
	/// Maximum number of domains (API keys)
	/// </summary>
	int DomainLimit;

	/// <summary>
	/// Ability to exceed the maximum number of queries in the plan
	/// </summary>
	BOOL OverPlanAllowed;

	/// <summary>
	/// Access to MS Excel add-in
	/// </summary>
	BOOL ExcelAddIn;

	/// <summary>
	/// Access to VIES Checker App application
	/// </summary>
	BOOL App;

	/// <summary>
	/// Access to VIES Checker CLI/CMD command line application
	/// </summary>
	BOOL CLI;

	/// <summary>
	/// Access to the statistics of the queries made
	/// </summary>
	BOOL Stats;

	/// <summary>
	/// Access to monitoring the status of entities
	/// </summary>
	BOOL Monitor;

	/// <summary>
	/// Access to entity status checking functions in the VIES system
	/// </summary>
	BOOL FuncGetVIESData;

	/// <summary>
	/// Number of queries to the VIES system performed in the current month
	/// </summary>
	int VIESDataCount;

	/// <summary>
	/// Total number of queries performed in the current month
	/// </summary>
	int TotalCount;
} AccountStatus;

/////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/// <summary>
/// Create new object 
/// </summary>
/// <param name="account">pointer to new object</param>
/// <returns></returns>
VIESAPI_API BOOL accountstatus_new(AccountStatus** account);

/// <summary>
/// Free object
/// </summary>
/// <param name="account">pointer to object to free</param>
/// <returns></returns>
VIESAPI_API void accountstatus_free(AccountStatus** account);

#ifdef __cplusplus
}
#endif

/////////////////////////////////////////////////////////////////

#endif
