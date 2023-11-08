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

#ifndef __VIESAPI_API_H__
#define __VIESAPI_API_H__

/////////////////////////////////////////////////////////////////

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <time.h>

/////////////////////////////////////////////////////////////////

#ifdef VIESAPI_STATIC
	#define VIESAPI_API
#else
	#ifdef VIESAPI_EXPORTS
		#define VIESAPI_API __declspec(dllexport)
	#else
		#define VIESAPI_API __declspec(dllimport)
	#endif
#endif

/////////////////////////////////////////////////////////////////

#include "viesapi_error.h"
#include "viesapi_validate.h"
#include "viesapi_invoice.h"
#include "viesapi_vies.h"
#include "viesapi_account.h"
#include "viesapi_client.h"

/////////////////////////////////////////////////////////////////

#endif
