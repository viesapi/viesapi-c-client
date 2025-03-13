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

#ifndef __VIESAPI_API_VALIDATE_H__
#define __VIESAPI_API_VALIDATE_H__

/////////////////////////////////////////////////////////////////

#ifdef __cplusplus
extern "C" {
#endif

/// <summary>
/// Normalizes form of the NIP number
/// </summary>
/// <param name="nip">NIP number in any valid format</param>
/// <returns>normalized NIP number (free() is required)</returns>
VIESAPI_API char* viesapi_nip_normalize(const char* nip);

/// <summary>
/// Checks if specified NIP is valid
/// </summary>
/// <param name="nip">input number</param>
/// <returns>TRUE if number is valid</returns>
VIESAPI_API BOOL viesapi_nip_is_valid(const char* nip);

/// <summary>
/// Normalizes form of the VAT number
/// </summary>
/// <param name="number">EU VAT number in any valid format</param>
/// <returns>normalized VAT number (free() is required)</returns>
VIESAPI_API char* viesapi_euvat_normalize(const char* euvat);

/// <summary>
/// Checks if specified VAT number is valid
/// </summary>
/// <param name="number">input number</param>
/// <returns>TRUE if number is valid</returns>
VIESAPI_API BOOL viesapi_euvat_is_valid(const char* euvat);

#ifdef __cplusplus
}
#endif

/////////////////////////////////////////////////////////////////

#endif
