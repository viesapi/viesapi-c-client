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


/// <summary>
/// Get random hex string
/// </summary>
/// <param name="length">lenght of string</param>
/// <param name="bstr">new hex string</param>
/// <returns>TRUE if succeeded</returns>
static BOOL _viesapi_get_random(int length, BSTR* bstr)
{
	HCRYPTPROV hcp = 0;

	BOOL ret = FALSE;

	DWORD len;

	char hex[MAX_STRING];
	char buf[MAX_NUMBER];

	memset(hex, 0, sizeof(hex));

	if (!CryptAcquireContext(&hcp, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		goto err;
	}

	if (!CryptGenRandom(hcp, length / 2, buf)) {
		goto err;
	}

	len = sizeof(hex);

	if (!CryptBinaryToString(buf, length / 2, CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF, hex, &len)) {
		goto err;
	}

	if (!utf8_to_bstr(hex, bstr)) {
		goto err;
	}

	// ok
	ret = TRUE;

err:
	CryptReleaseContext(hcp, 0);

	return ret;
}

/// <summary>
/// Calculates HMAC256 from input string
/// </summary>
/// <param name="viesapi">client object</param>
/// <param name="str">input string</param>
/// <param name="bstr">HMAC256 as Base64 string</param>
/// <returns>TRUE if succeeded</returns>
static BOOL _viesapi_get_hmac(VIESAPIClient* viesapi, const char* str, BSTR* bstr)
{
	HMAC_INFO hi;
	KEYDATA kd;

	HCRYPTPROV hcp = 0;
	HCRYPTKEY hck = 0;
	HCRYPTHASH hch = 0;

	BOOL ret = FALSE;

	DWORD blen;
	DWORD len;

	char hmac[MAX_STRING];
	char b64[MAX_STRING];

	if (!CryptAcquireContext(&hcp, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		goto err;
	}

	kd.hdr.bType = PLAINTEXTKEYBLOB;
	kd.hdr.bVersion = CUR_BLOB_VERSION;
	kd.hdr.reserved = 0;
	kd.hdr.aiKeyAlg = CALG_RC2;
	kd.keyLength = (unsigned long)strlen(viesapi->key);
	
	memcpy(kd.key, viesapi->key, kd.keyLength);

	if (!CryptImportKey(hcp, (BYTE*)&kd, sizeof(kd), 0, CRYPT_IPSEC_HMAC_KEY, &hck)) {
		goto err;
	}

	if (!CryptCreateHash(hcp, CALG_HMAC, hck, 0, &hch)) {
		goto err;
	}

	memset(&hi, 0, sizeof(hi));
	hi.HashAlgid = CALG_SHA_256;

	if (!CryptSetHashParam(hch, HP_HMAC_INFO, (BYTE*)&hi, 0)) {
		goto err;
	}

	if (!CryptHashData(hch, (BYTE*)str, (DWORD)strlen(str), 0)) {
		goto err;
	}

	len = sizeof(hmac);

	if (!CryptGetHashParam(hch, HP_HASHVAL, hmac, &len, 0)) {
		goto err;
	}

	blen = sizeof(b64);

	if (!CryptBinaryToString(hmac, len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64, &blen)) {
		goto err;
	}

	if (!utf8_to_bstr(b64, bstr)) {
		goto err;
	}

	// ok
	ret = TRUE;

err:
	CryptDestroyHash(hch);
	CryptDestroyKey(hck);
	CryptReleaseContext(hcp, 0);

	return ret;
}

/// <summary>
/// Create authorization header
/// </summary>
/// <param name="viesapi">client object</param>
/// <param name="method">HTTP method name</param>
/// <param name="url">target URL address</param>
/// <param name="bstr">authorization information</param>
/// <returns>TRUE if succeeded</returns>
static BOOL _viesapi_get_auth_header(VIESAPIClient* viesapi, BSTR method, BSTR url, BSTR* bstr)
{
	URL_COMPONENTS uc;

	BSTR host = NULL;
	BSTR path = NULL;
	BSTR nonce = NULL;
	BSTR hmac = NULL;

	BOOL ret = FALSE;

	char str[MAX_STRING];

	long ts;

	memset(&uc, 0, sizeof(uc));
	uc.dwStructSize = sizeof(uc);
	uc.dwSchemeLength = -1;
	uc.dwHostNameLength = -1;
	uc.dwUrlPathLength = -1;
	uc.dwExtraInfoLength = -1;

	if (!WinHttpCrackUrl(url, 0, 0, &uc)) {
		goto err;
	}

	host = SysAllocStringLen(uc.lpszHostName, uc.dwHostNameLength);
	path = SysAllocStringLen(uc.lpszUrlPath, uc.dwUrlPathLength);

	if (!_viesapi_get_random(8, &nonce)) {
		goto err;
	}

	ts = (long)time(NULL);

	snprintf(str, sizeof(str), "%ld\n%ls\n%ls\n%ls\n%ls\n%d\n\n", ts, nonce, method, path, host, uc.nPort);

	if (!_viesapi_get_hmac(viesapi, str, &hmac)) {
		goto err;
	}

	snprintf(str, sizeof(str), "MAC id=\"%s\", ts=\"%ld\", nonce=\"%ls\", mac=\"%ls\"", viesapi->id, ts, nonce, hmac);

	if (!utf8_to_bstr(str, bstr)) {
		goto err;
	}

	// ok
	ret = TRUE;

err:
	SysFreeString(host);
	SysFreeString(path);
	SysFreeString(nonce);
	SysFreeString(hmac);

	return ret;
}

/// <summary>
/// Create user agent header
/// </summary>
/// <param name="viesapi">client object</param>
/// <param name="bstr">user agent information</param>
/// <returns>TRUE if succeeded</returns>
static BOOL _viesapi_get_agent_header(VIESAPIClient* viesapi, BSTR* bstr)
{
	char str[MAX_STRING];

	if (viesapi->app && strlen(viesapi->app) > 0) {
		snprintf(str, sizeof(str), "%s VIESAPIClient/%s C/%s", viesapi->app, VIESAPI_VERSION, "Windows");
	}
	else {
		snprintf(str, sizeof(str), "VIESAPIClient/%s C/%s", VIESAPI_VERSION, "Windows");
	}

	return utf8_to_bstr(str, bstr);
}

/// <summary>
/// Parse server response as XML doc 
/// </summary>
/// <param name="str">server response</param>
/// <param name="doc">output XML doc</param>
/// <returns>TRUE if succeeded</returns>
static BOOL _viesapi_load_doc(BSTR str, IXMLDOMDocument2** doc)
{
	IXMLDOMDocument2* pDoc = NULL;

	VARIANT_BOOL loaded;
	VARIANT xpath;
	HRESULT hr;

	BOOL ret = FALSE;

	if ((hr = CoCreateInstance(&CLSID_DOMDocument, 0, CLSCTX_INPROC_SERVER, &IID_IXMLDOMDocument2, &pDoc)) != S_OK) {
		goto err;
	}

	if ((hr = pDoc->lpVtbl->put_async(pDoc, VARIANT_FALSE)) != S_OK) {
		goto err;
	}

	if ((hr = pDoc->lpVtbl->put_validateOnParse(pDoc, VARIANT_FALSE)) != S_OK) {
		goto err;
	}

	xpath.vt = VT_BSTR;
	xpath.bstrVal = L"XPath";

	if ((hr = pDoc->lpVtbl->setProperty(pDoc, L"SelectionLanguage", xpath)) != S_OK) {
		goto err;
	}

	if ((hr = pDoc->lpVtbl->loadXML(pDoc, str, &loaded)) != S_OK || loaded != VARIANT_TRUE) {
		goto err;
	}

	// ok
	*doc = pDoc;
	pDoc = NULL;

	ret = TRUE;

err:
	if (pDoc) {
		pDoc->lpVtbl->Release(pDoc);
	}

	return ret;
}

/// <summary>
/// Perform HTTP GET
/// </summary>
/// <param name="viesapi">client object</param>
/// <param name="url">request URL</param>
/// <param name="doc">response as XML doc</param>
/// <returns>TRUE if succeeded</returns>
static BOOL _viesapi_http_get(VIESAPIClient* viesapi, const char* url, IXMLDOMDocument2** doc)
{
	IXMLHTTPRequest* pXhr = NULL;

	VARIANT async;
	VARIANT var;
	HRESULT hr;
	
	BSTR burl = NULL;
	BSTR auth = NULL;
	BSTR agent = NULL;
	BSTR resp = NULL;

	BOOL ret = FALSE;

	long state;
	long status;

	// clear

	// xml http object
	if ((hr = CoCreateInstance(&CLSID_XMLHTTPRequest, 0, CLSCTX_INPROC_SERVER, &IID_IXMLHTTPRequest, &pXhr)) != S_OK) {
		goto err;
	}

	// send
	async.vt = VT_BOOL;
	async.boolVal = VARIANT_FALSE;

	var.vt = VT_BSTR;
	var.bstrVal = NULL;

	if (!utf8_to_bstr(url, &burl)) {
		goto err;
	}

	if ((hr = pXhr->lpVtbl->open(pXhr, L"GET", burl, async, var, var)) != S_OK) {
		goto err;
	}

	if (!_viesapi_get_auth_header(viesapi, L"GET", burl, &auth)) {
		goto err;
	}

	if ((hr = pXhr->lpVtbl->setRequestHeader(pXhr, L"Authorization", auth)) != S_OK) {
		goto err;
	}

	if (!_viesapi_get_agent_header(viesapi, &agent)) {
		goto err;
	}

	if ((hr = pXhr->lpVtbl->setRequestHeader(pXhr, L"User-Agent", agent)) != S_OK) {
		goto err;
	}

	if ((hr = pXhr->lpVtbl->send(pXhr, var)) != S_OK) {
		goto err;
	}

	// check response
	if ((hr = pXhr->lpVtbl->get_readyState(pXhr, &state)) != S_OK) {
		goto err;
	}

	if ((hr = pXhr->lpVtbl->get_status(pXhr, &status)) != S_OK) {
		goto err;
	}

	if (state != 4 || status != 200) {
		goto err;
	}

	if ((hr = pXhr->lpVtbl->get_responseText(pXhr, &resp)) != S_OK) {
		goto err;
	}

	if (!_viesapi_load_doc(resp, doc)) {
		goto err;
	}

	// ok
	ret = TRUE;

err:
	if (pXhr) {
		pXhr->lpVtbl->Release(pXhr);
	}

	SysFreeString(burl);
	SysFreeString(auth);
	SysFreeString(agent);
	SysFreeString(resp);

	return ret;
}

/// <summary>
/// Clear last error
/// </summary>
/// <param name="viesapi">client object</param>
static void _viesapi_clear_err(VIESAPIClient* viesapi)
{
	viesapi->err_code = 0;

	free(viesapi->err);
	viesapi->err = NULL;
}

/// <summary>
/// Set last error information
/// </summary>
/// <param name="viesapi">client object</param>
/// <param name="code">error code</param>
/// <param name="err">error message</param>
static void _viesapi_set_err(VIESAPIClient* viesapi, int code, const char* err)
{
	_viesapi_clear_err(viesapi);

	viesapi->err_code = code;
	viesapi->err = strdup(err ? err : viesapi_errstr(code));
}

/// <summary>
/// Get path suffix
/// </summary>
/// <param name="viesapi">client object</param>
/// <param name="type">number type</param>
/// <param name="number">number value</param>
/// <param name="path">path fragment</param>
/// <returns>TRUE if succeeded</returns>
static BOOL _viesapi_get_path_suffix(VIESAPIClient* viesapi, Number type, const char* number, char* path)
{
	char* n = NULL;

	if (type == EUVAT) {
		if (!viesapi_euvat_is_valid(number)) {
			_viesapi_set_err(viesapi, VIESAPI_ERR_CLI_EUVAT, NULL);
			return FALSE;
		}

		n = viesapi_euvat_normalize(number);

		strcat(path, "euvat/");
		strcat(path, n);

		free(n);
	}
	else if (type == NIP) {
		if (!viesapi_nip_is_valid(number)) {
			_viesapi_set_err(viesapi, VIESAPI_ERR_CLI_NIP, NULL);
			return FALSE;
		}

		n = viesapi_nip_normalize(number);

		strcat(path, "nip/");
		strcat(path, n);

		free(n);
	}
	else {
		_viesapi_set_err(viesapi, VIESAPI_ERR_CLI_NUMBER, NULL);
		return FALSE;
	}

	return TRUE;
}

/// <summary>
/// Get XML node value as string
/// </summary>
/// <param name="doc">XML document</param>
/// <param name="xpath">XPath expression selecting the value</param>
/// <param name="def">default value used when node does not exist</param>
/// <returns>node value as string</returns>
static char* _viesapi_parse_str(IXMLDOMDocument2* doc, BSTR xpath, const char* def)
{
	IXMLDOMElement* root = NULL;
	IXMLDOMNode* node = NULL;

	BSTR txt = NULL;

	HRESULT hr;

	char* str = NULL;

	if ((hr = doc->lpVtbl->get_documentElement(doc, &root)) != S_OK) {
		goto err;
	}

	if ((hr = root->lpVtbl->selectSingleNode(root, xpath, &node)) != S_OK) {
		goto err;
	}

	if ((hr = node->lpVtbl->get_text(node, &txt)) != S_OK) {
		goto err;
	}

	if (txt && wcslen(txt) > 0) {
		bstr_replace(&txt, L"&quot;", L"\"");
		bstr_replace(&txt, L"&quot;", L"\"");
		bstr_replace(&txt, L"&apos;", L"'");
		bstr_replace(&txt, L"&lt;", L"<");
		bstr_replace(&txt, L"&gt;", L">");
		bstr_replace(&txt, L"&amp;", L"&");
	}

	if (!bstr_to_utf8(txt, &str)) {
		goto err;
	}
	
err:
	if (!str) {
		str = strdup(def ? def : "");
	}

	if (node) {
		node->lpVtbl->Release(node);
	}

	if (root) {
		root->lpVtbl->Release(root);
	}

	SysFreeString(txt);

	return str;
}

/// <summary>
/// Get XML node value as unix timestamp
/// </summary>
/// <param name="doc">XML document</param>
/// <param name="path">XPath expression selecting the value</param>
/// <returns>timestamp value</returns>
static time_t _viesapi_parse_datetime(IXMLDOMDocument2* doc, BSTR xpath)
{
	struct tm stm;

	char* str = _viesapi_parse_str(doc, xpath, NULL);

	time_t t = 0;

	// 2010-04-11T23:02:46.453+02:00
	if (str && strlen(str) > 0) {
		memset(&stm, 0, sizeof(stm));
		
		if (sscanf(str, "%04d-%02d-%02dT%02d:%02d:%02d", &stm.tm_year, &stm.tm_mon, &stm.tm_mday,
			&stm.tm_hour, &stm.tm_min, &stm.tm_sec) != 6) {

			goto err;
		}

		stm.tm_year -= 1900;
		stm.tm_mon -= 1;

		t = _mkgmtime(&stm);
	}

err:
	free(str);

	return t;
}

/// <summary>
/// Get XML node value as unix timestamp
/// </summary>
/// <param name="doc">XML document</param>
/// <param name="path">XPath expression selecting the value</param>
/// <returns>timestamp value</returns>
static time_t _viesapi_parse_date(IXMLDOMDocument2* doc, BSTR xpath)
{
	struct tm stm;

	char* str = _viesapi_parse_str(doc, xpath, NULL);

	time_t t = 0;

	// 2019-02-13+01:00
	if (str && strlen(str) > 0) {
		memset(&stm, 0, sizeof(stm));
		
		if (sscanf(str, "%04d-%02d-%02d", &stm.tm_year, &stm.tm_mon, &stm.tm_mday) != 3) {
			goto err;
		}

		stm.tm_year -= 1900;
		stm.tm_mon -= 1;

		t = _mkgmtime(&stm);
	}

err:
	free(str);

	return t;
}

/// <summary>
/// Get XML node value as int value
/// </summary>
/// <param name="doc">XML document</param>
/// <param name="path">XPath expression selecting the value</param>
/// <param name="def">default value used when node does not exist</param>
/// <returns>int value</returns>
static int _viesapi_parse_int(IXMLDOMDocument2* doc, BSTR xpath, int def)
{
	int val = def;

	char* str = _viesapi_parse_str(doc, xpath, NULL);

	if (str && strlen(str) > 0) {
		val = atoi(str);
	}

	free(str);

	return val;
}

/// <summary>
/// Get XML node value as double value
/// </summary>
/// <param name="doc">XML document</param>
/// <param name="path">XPath expression selecting the value</param>
/// <param name="def">default value used when node does not exist</param>
/// <returns>double value</returns>
static double _viesapi_parse_double(IXMLDOMDocument2* doc, BSTR xpath, double def)
{
	double val = def;

	char* str = _viesapi_parse_str(doc, xpath, NULL);

	if (str && strlen(str) > 0) {
		val = atof(str);
	}

	free(str);

	return val;
}

/// <summary>
/// Get XML node value as boolean value
/// </summary>
/// <param name="doc">XML document</param>
/// <param name="path">XPath expression selecting the value</param>
/// <param name="def">default value used when node does not exist</param>
/// <returns>boolean value</returns>
static BOOL _viesapi_parse_bool(IXMLDOMDocument2* doc, BSTR xpath, BOOL def)
{
	BOOL val = def;

	char* str = _viesapi_parse_str(doc, xpath, NULL);

	if (str && strlen(str) > 0) {
		val = (strcmp(str, "true") == 0 ? TRUE : FALSE);
	}

	free(str);

	return val;
}

/////////////////////////////////////////////////////////////////

VIESAPI_API BOOL viesapi_new(VIESAPIClient** viesapi, const char* url, const char* id, const char* key)
{
	VIESAPIClient* n = NULL;

	BOOL ret = FALSE;

	if (!viesapi || !url || strlen(url) == 0 || !id || strlen(id) == 0 || !key || strlen(key) == 0) {
		goto err;
	}

	if ((n = (VIESAPIClient*)malloc(sizeof(VIESAPIClient))) == NULL) {
		goto err;
	}

	memset(n, 0, sizeof(VIESAPIClient));

	n->url = strdup(url);
	n->id = strdup(id);
	n->key = strdup(key);

	// ok
	*viesapi = n;
	n = NULL;

	ret = TRUE;

err:
	viesapi_free(&n);

	return ret;
}

VIESAPI_API BOOL viesapi_new_prod(VIESAPIClient** viesapi, const char* id, const char* key)
{
	return viesapi_new(viesapi, VIESAPI_PRODUCTION_URL, id, key);
}

VIESAPI_API BOOL viesapi_new_test(VIESAPIClient** viesapi)
{
	return viesapi_new(viesapi, VIESAPI_TEST_URL, VIESAPI_TEST_ID, VIESAPI_TEST_KEY);
}

VIESAPI_API void viesapi_free(VIESAPIClient** viesapi)
{
	VIESAPIClient* n = (viesapi ? *viesapi : NULL);

	if (n) {
		free(n->url);
		free(n->id);
		free(n->key);

		free(n->app);
		free(n->err);

		free(*viesapi);
		*viesapi = NULL;
	}
}

VIESAPI_API int viesapi_get_last_err_code(VIESAPIClient* viesapi)
{
	return (viesapi ? viesapi->err_code : -1);
}

VIESAPI_API char* viesapi_get_last_err(VIESAPIClient* viesapi)
{
	return (viesapi ? viesapi->err : NULL);
}

VIESAPI_API VIESData* viesapi_get_vies_data(VIESAPIClient* viesapi, const char* euvat)
{
	IXMLDOMDocument2* doc = NULL;
	VIESData* vies = NULL;

	char url[MAX_STRING];

	char* code = NULL;

	if (!viesapi || !euvat || strlen(euvat) == 0) {
		_viesapi_set_err(viesapi, VIESAPI_ERR_CLI_INPUT, NULL);
		goto err;
	}

	// clear error
	_viesapi_clear_err(viesapi);

	// validate number and construct path
	snprintf(url, sizeof(url), "%s/get/vies/", viesapi->url);

	if (!_viesapi_get_path_suffix(viesapi, EUVAT, euvat, url)) {
		goto err;
	}

	// prepare request
	if (!_viesapi_http_get(viesapi, url, &doc)) {
		_viesapi_set_err(viesapi, VIESAPI_ERR_CLI_CONNECT, NULL);
		goto err;
	}

	// parse response
	code = _viesapi_parse_str(doc, L"/result/error/code", NULL);

	if (code && strlen(code) > 0) {
		// error
		_viesapi_set_err(viesapi, atoi(code), _viesapi_parse_str(doc, L"/result/error/description", NULL));
		goto err;
	}

	if (!viesdata_new(&vies)) {
		goto err;
	}

	vies->UID = _viesapi_parse_str(doc, L"/result/vies/uid", NULL);

	vies->CountryCode = _viesapi_parse_str(doc, L"/result/vies/countryCode", NULL);
	vies->VATNumber = _viesapi_parse_str(doc, L"/result/vies/vatNumber", NULL);

	vies->Valid = _viesapi_parse_bool(doc, L"/result/vies/valid", FALSE);

	vies->TraderName = _viesapi_parse_str(doc, L"/result/vies/traderName", NULL);
	vies->TraderCompanyType = _viesapi_parse_str(doc, L"/result/vies/traderCompanyType", NULL);
	vies->TraderAddress = _viesapi_parse_str(doc, L"/result/vies/traderAddress", NULL);

	vies->ID = _viesapi_parse_str(doc, L"/result/vies/id", NULL);
	vies->Date = _viesapi_parse_date(doc, L"/result/vies/date");
	vies->Source = _viesapi_parse_str(doc, L"/result/vies/source", NULL);

err:
	if (doc) {
		doc->lpVtbl->Release(doc);
	}

	free(code);

	return vies;
}

VIESAPI_API AccountStatus* viesapi_get_account_status(VIESAPIClient* viesapi)
{
	IXMLDOMDocument2* doc = NULL;
	AccountStatus* status = NULL;

	char url[MAX_STRING];

	char* code = NULL;

	if (!viesapi) {
		_viesapi_set_err(viesapi, VIESAPI_ERR_CLI_INPUT, NULL);
		goto err;
	}

	// clear error
	_viesapi_clear_err(viesapi);

	// validate number and construct path
	snprintf(url, sizeof(url), "%s/check/account/status", viesapi->url);

	// prepare request
	if (!_viesapi_http_get(viesapi, url, &doc)) {
		_viesapi_set_err(viesapi, VIESAPI_ERR_CLI_CONNECT, NULL);
		goto err;
	}

	// parse response
	code = _viesapi_parse_str(doc, L"/result/error/code", NULL);

	if (code && strlen(code) > 0) {
		// error
		_viesapi_set_err(viesapi, atoi(code), _viesapi_parse_str(doc, L"/result/error/description", NULL));
		goto err;
	}

	if (!accountstatus_new(&status)) {
		goto err;
	}

	status->UID = _viesapi_parse_str(doc, L"/result/account/uid", NULL);
	status->Type = _viesapi_parse_str(doc, L"/result/account/type", NULL);
	status->ValidTo = _viesapi_parse_datetime(doc, L"/result/account/validTo");
	status->BillingPlanName = _viesapi_parse_str(doc, L"/result/account/billingPlan/name", NULL);

	status->SubscriptionPrice = _viesapi_parse_double(doc, L"/result/account/billingPlan/subscriptionPrice", 0);
	status->ItemPrice = _viesapi_parse_double(doc, L"/result/account/billingPlan/itemPrice", 0);
	status->ItemPriceStatus = _viesapi_parse_double(doc, L"/result/account/billingPlan/itemPriceCheckStatus", 0);

	status->Limit = _viesapi_parse_int(doc, L"/result/account/billingPlan/limit", 0);
	status->RequestDelay = _viesapi_parse_int(doc, L"/result/account/billingPlan/requestDelay", 0);
	status->DomainLimit = _viesapi_parse_int(doc, L"/result/account/billingPlan/domainLimit", 0);
	status->OverPlanAllowed = _viesapi_parse_bool(doc, L"/result/account/billingPlan/overplanAllowed", FALSE);
	status->ExcelAddIn = _viesapi_parse_bool(doc, L"/result/account/billingPlan/excelAddin", FALSE);

	status->App = _viesapi_parse_bool(doc, L"/result/account/billingPlan/app", FALSE);
	status->CLI = _viesapi_parse_bool(doc, L"/result/account/billingPlan/cli", FALSE);
	status->Stats = _viesapi_parse_bool(doc, L"/result/account/billingPlan/stats", FALSE);
	status->Monitor = _viesapi_parse_bool(doc, L"/result/account/billingPlan/monitor", FALSE);

	status->FuncGetVIESData = _viesapi_parse_bool(doc, L"/result/account/billingPlan/funcGetVIESData", FALSE);

	status->VIESDataCount = _viesapi_parse_int(doc, L"/result/account/requests/viesData", 0);
	status->TotalCount = _viesapi_parse_int(doc, L"/result/account/requests/total", 0);

err:
	if (doc) {
		doc->lpVtbl->Release(doc);
	}

	free(code);

	return status;
}
