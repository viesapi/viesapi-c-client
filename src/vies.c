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

#include "internal.h"
#include "viesapi.h"


VIESAPI_API BOOL viesdata_new(VIESData** vies)
{
	VIESData* vd = NULL;

	BOOL ret = FALSE;

	if ((vd = (VIESData*)malloc(sizeof(VIESData))) == NULL) {
		goto err;
	}

	memset(vd, 0, sizeof(VIESData));

	// ok
	*vies = vd;
	vd = NULL;

	ret = TRUE;

err:
	viesdata_free(&vd);

	return ret;
}

VIESAPI_API void viesdata_free(VIESData** vies)
{
	VIESData* vd = (vies ? *vies : NULL);

	if (vd) {
		free(vd->UID);

		free(vd->CountryCode);
		free(vd->VATNumber);

		free(vd->TraderName);
		free(vd->TraderCompanyType);
		free(vd->TraderAddress);

		free(vd->ID);
		free(vd->Source);

		free(*vies);
		*vies = NULL;
	}
}
