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

#ifndef __VIESAPI_API_VIES_H__
#define __VIESAPI_API_VIES_H__

/////////////////////////////////////////////////////////////////

/// <summary>
/// Legal forms
/// </summary>
typedef enum LegalForm {
	UNKNOWN = 0,
	SOLE_PROPRIETORSHIP = 1,
	LIMITED_LIABILITY_COMPANY = 2,
	GENERAL_PARTNERSHIP = 3,
	JOINT_STOCK_COMPANY = 4,
	LIMITED_PARTNERSHIP = 5,
	PRIVATE_LIMITED_LIABILITY_COMPANY = 6,
	SINGLE_MEMBER_JOINT_STOCK_COMPANY = 7,
	SIMPLE_LIMITED_LIABILITY_COMPANY = 8,
	SINGLE_MEMBER_LIMITED_LIABILITY_COMPANY = 9,
	SIMPLIFIED_JOINT_STOCK_COMPANY = 10,
	SMALL_COMPANY = 11,
	LIMITED_JOINT_STOCK_PARTNERSHIP = 12,
	PROFESSIONAL_PARTNERSHIP = 13,
	LIMITED_LIABILITY_PARTNERSHIP = 14,
	PRIVATE_PARTNERSHIP = 15,
	LIMITED_LIABILITY_COMPANY_LIMITED_PARTNERSHIP = 16,
	LIMITED_LIABILITY_COMPANY_LIMITED_JOINT_STOCK_PARTNERSHIP = 17,
	PUBLIC_INSTITUTION = 18
} LegalForm;

/////////////////////////////////////////////////////////////////

 /// <summary>
 /// Name components
 /// </summary>
typedef struct NameComponents {
	/// <summary>
	/// Trader name
	/// </summary>
	char* Name;

	/// <summary>
	/// Legal form name
	/// </summary>
	char* LegalForm;

	/// <summary>
	/// Legal form canonical id
	/// </summary>
	LegalForm LegalFormCanonicalId;

	/// <summary>
	/// Legal form canonical name
	/// </summary>
	char* LegalFormCanonicalName;
} NameComponents;

/////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/// <summary>
/// Create new object
/// </summary>
/// <param name="addr">pointer to a new object</param>
/// <returns>TRUE if succeeded</returns>
VIESAPI_API BOOL name_components_new(NameComponents** name);

/// <summary>
/// Free data object
/// </summary>
/// <param name="addr">pointer to an object to free</param>
VIESAPI_API void name_components_free(NameComponents** name);

#ifdef __cplusplus
}
#endif

/////////////////////////////////////////////////////////////////

/// <summary>
/// Address components
/// </summary>
typedef struct AddressComponents {
	/// <summary>
	/// Country name
	/// </summary>
	char* Country;

	/// <summary>
	/// Postal code
	/// </summary>
	char* PostalCode;

	/// <summary>
	/// City or locality
	/// </summary>
	char* City;

	/// <summary>
	/// Street name
	/// </summary>
	char* Street;

	/// <summary>
	/// Street number
	/// </summary>
	char* StreetNumber;

	/// <summary>
	/// House number
	/// </summary>
	char* HouseNumber;
} AddressComponents;
 
/////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/// <summary>
/// Create new object
/// </summary>
/// <param name="addr">pointer to a new object</param>
/// <returns>TRUE if succeeded</returns>
VIESAPI_API BOOL address_components_new(AddressComponents** addr);

/// <summary>
/// Free data object
/// </summary>
/// <param name="addr">pointer to an object to free</param>
VIESAPI_API void address_components_free(AddressComponents** addr);

#ifdef __cplusplus
}
#endif

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
	/// Trader name parsed into components
	/// </summary>
	NameComponents* TraderNameComponents;

	/// <summary>
	/// Trader company type
	/// </summary>
	char* TraderCompanyType;

	/// <summary>
	/// Trader address
	/// </summary>
	char* TraderAddress;

	/// <summary>
	/// Trader address parsed into components
	/// </summary>
	AddressComponents* TraderAddressComponents;

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

/// <summary>
/// VIES error
/// </summary>
typedef struct VIESError {

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
	/// Error description
	/// </summary>
	char* Error;

	/// <summary>
	/// Check date time
	/// </summary>
	time_t Date;

	/// <summary>
	/// The source of returned information
	/// </summary>
	char* Source;
} VIESError;

/////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/// <summary>
/// Create new object
/// </summary>
/// <param name="error">pointer to a new object</param>
/// <returns>TRUE if succeeded</returns>
VIESAPI_API BOOL vieserror_new(VIESError** error);

/// <summary>
/// Free data object
/// </summary>
/// <param name="error">pointer to an object to free</param>
VIESAPI_API void vieserror_free(VIESError** error);

#ifdef __cplusplus
}
#endif

/////////////////////////////////////////////////////////////////

/// <summary>
/// Batch result
/// </summary>
typedef struct BatchResult {

	/// <summary>
	/// Valid VIES results
	/// </summary>
	VIESData** Numbers;
	int NumbersCount;

	/// <summary>
	/// Failed VIES results
	/// </summary>
	VIESError** Errors;
	int ErrorsCount;
} BatchResult;

/////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/// <summary>
/// Create new object
/// </summary>
/// <param name="result">pointer to a new object</param>
/// <returns>TRUE if succeeded</returns>
VIESAPI_API BOOL batchresult_new(BatchResult** result);

/// <summary>
/// Free data object
/// </summary>
/// <param name="result">pointer to an object to free</param>
VIESAPI_API void batchresult_free(BatchResult** result);

#ifdef __cplusplus
}
#endif

/////////////////////////////////////////////////////////////////

#endif
