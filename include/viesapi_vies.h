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

#ifndef __VIESAPI_API_VIES_H__
#define __VIESAPI_API_VIES_H__

/////////////////////////////////////////////////////////////////

/// <summary>
/// VIES data
/// </summary>
typedef struct VIESData {

	/// <summary>
	/// Unique response ID
	/// </summary>
	char* UID;

	/// <summary>
	/// Country code (2-letters)
	/// </summary>
	char* CountryCode;

	/// <summary>
	/// VAT number
	/// </summary>
	char* VATNumber;
	
	/// <summary>
	/// Validity flag
	/// </summary>
	BOOL Valid;
	
	/// <summary>
	/// Trader name
	/// </summary>
	char* TraderName;

	/// <summary>
	/// Trader company type
	/// </summary>
	char* TraderCompanyType;

	/// <summary>
	/// Trader address
	/// </summary>
	char* TraderAddress;

	/// <summary>
	/// Request ID from EU VIES system
	/// </summary>
	char* ID;

	/// <summary>
	/// Check date time
	/// </summary>
	time_t Date;

	/// <summary>
	/// The source of returned information
	/// </summary>
	char* Source;
} VIESData;

/////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/// <summary>
/// Create new object
/// </summary>
/// <param name="vies">pointer to a new object</param>
/// <returns>TRUE if succeeded</returns>
VIESAPI_API BOOL viesdata_new(VIESData** vies);

/// <summary>
/// Free data object
/// </summary>
/// <param name="vies">pointer to an object to free</param>
VIESAPI_API void viesdata_free(VIESData** vies);

#ifdef __cplusplus
}
#endif

/////////////////////////////////////////////////////////////////

#endif
