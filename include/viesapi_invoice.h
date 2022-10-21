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

#ifndef __VIESAPI_API_INVOICE_H__
#define __VIESAPI_API_INVOICE_H__

/////////////////////////////////////////////////////////////////

/**
 * Dane firmy wymagane do wystawienia faktury
 */
typedef struct InvoiceData {
	char* UID;

	char* NIP;
	char* Name;
	char* FirstName;
	char* LastName;

	char* Street;
	char* StreetNumber;
	char* HouseNumber;
	char* City;
	char* PostCode;
	char* PostCity;

	char* Phone;
	char* Email;
	char* WWW;
} InvoiceData;

/////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Utworzenie nowego obiektu z danymi
 * @param invoice adres na utworzony obiekt
 */
VIESAPI_API BOOL invoicedata_new(InvoiceData** invoice);

/**
 * Dealokacja obiektu z danymi
 * @param invoice adres na utworzony obiekt
 */
VIESAPI_API void invoicedata_free(InvoiceData** invoice);

#ifdef __cplusplus
}
#endif

/////////////////////////////////////////////////////////////////

#endif
