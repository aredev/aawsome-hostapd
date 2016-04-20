/*
 * hostapd / EAP-MD5 server
 * Copyright (c) 2004-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "crypto/random.h"
#include "eap_i.h"
#include "eap_common/chap.h"
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#define CHALLENGE_LEN 350

struct eap_md5_data {
	u8 challenge[CHALLENGE_LEN];
	enum { CONTINUE, SUCCESS, FAILURE } state;
};


static void * eap_md5_init(struct eap_sm *sm)
{
	struct eap_md5_data *data;

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	data->state = CONTINUE;

	return data;
}


static void eap_md5_reset(struct eap_sm *sm, void *priv)
{
	struct eap_md5_data *data = priv;
	os_free(data);
}


static struct wpabuf * eap_md5_buildReq(struct eap_sm *sm, void *priv, u8 id)
{
	struct eap_md5_data *data = priv;
	struct wpabuf *req;

	if (random_get_bytes(data->challenge, CHALLENGE_LEN)) {
		wpa_printf(MSG_ERROR, "EAP-MD5: Failed to get random data");
		data->state = FAILURE;
		return NULL;
	}

	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_MD5, 1 + CHALLENGE_LEN,
			    EAP_CODE_REQUEST, id);
	if (req == NULL) {
		wpa_printf(MSG_ERROR, "EAP-MD5: Failed to allocate memory for "
			   "request");
		data->state = FAILURE;
		return NULL;
	}

	//Call for context and nonce

	wpa_printf(MSG_INFO, "Generating freshness for this session...");

	system("java -jar crypto-all-1.0-SNAPSHOT.jar c");

	wpa_printf(MSG_INFO, "Freshness generated. Saving freshness...");

	FILE *fp;

	fp = fopen("c.txt", "rb");

	char context[257];
	char nonce[81];

	fgets(context, sizeof(context)-1, fp);
	fgets(nonce, sizeof(context)-1, fp);

//	wpa_printf(MSG_INFO, "This is the challenge %s", context);
//	wpa_hexdump(MSG_MSGDUMP, "EAP-MD5: Challenge", data->challenge,
//		    CHALLENGE_LEN);

	char total[350] = " ";
	strcat(total, context);
	strcat(total, "\n");
	strcat(total, nonce);

	wpabuf_put_u8(req, CHALLENGE_LEN);
	wpa_printf(MSG_INFO, "This is the challenge message: %s", total);

	wpabuf_put_data(req, total, CHALLENGE_LEN);

	data->state = CONTINUE;

	return req;
}


static Boolean eap_md5_check(struct eap_sm *sm, void *priv,
			     struct wpabuf *respData)
{
	//Harde goedkeuring
	return FALSE;


	const u8 *pos;
	size_t len;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_MD5, respData, &len);
	if (pos == NULL || len < 1) {
		wpa_printf(MSG_INFO, "EAP-MD5: Invalid frame");
		return TRUE;
	}
	if (*pos != CHAP_MD5_LEN || 1 + CHAP_MD5_LEN > len) {
		wpa_printf(MSG_INFO, "EAP-MD5: Invalid response "
			   "(response_len=%d payload_len=%lu",
			   *pos, (unsigned long) len);
		return TRUE;
	}

	return FALSE;
}


static void eap_md5_process(struct eap_sm *sm, void *priv,
			    struct wpabuf *respData)
{
	struct eap_md5_data *data = priv;
	const u8 *pos;
	size_t plen;
	u8 hash[CHAP_MD5_LEN], id;

	if (sm->user == NULL || sm->user->password == NULL ||
	    sm->user->password_hash) {
		wpa_printf(MSG_INFO, "EAP-MD5: Plaintext password not "
			   "configured");
		data->state = FAILURE;
		return;
	}

	wpa_printf(MSG_INFO, "Received disclosed attribute and proof of user");

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_MD5, respData, &plen);
	if (pos == NULL || *pos != CHAP_MD5_LEN || plen < 1 + CHAP_MD5_LEN)
		return; /* Should not happen - frame already validated */

	pos++; /* Skip response len */
	wpa_hexdump(MSG_MSGDUMP, "EAP-MD5: Response", pos, CHAP_MD5_LEN);

	id = eap_get_id(respData);
	if (chap_md5(id, sm->user->password, sm->user->password_len,
		     data->challenge, CHALLENGE_LEN, hash)) {
		wpa_printf(MSG_INFO, "EAP-MD5: CHAP MD5 operation failed");
		data->state = FAILURE;
		return;
	}


	//I would like to retrieve my custom send data
	
	char *symbol = pos++;
	char credential[1500];
	FILE *fp;

	int i = 16;

	wpa_printf(MSG_INFO, "Serializing proof...");
	
	fp = fopen("output.txt", "w+");

	if(fp == NULL){
		wpa_printf(MSG_INFO, "Error opening file");
	}else{
		wpa_printf(MSG_INFO, "File opened succesfully!");
	}

	//Write received message to a file	
	int c = 0;
	while(symbol[i] != '<'){
		//Eigen terminatie teken
		credential[c] = symbol[i];
		c++;
		i++;
	}

	fputs(credential,fp);
	fclose(fp);

	//Call verifier
	wpa_printf(MSG_INFO, "Checking wheter everything if fine");

	system("java -jar crypto-all-1.0-SNAPSHOT.jar v");	

	data->state = SUCCESS;
}

static Boolean eap_md5_isDone(struct eap_sm *sm, void *priv)
{
	struct eap_md5_data *data = priv;
	return data->state != CONTINUE;
}


static Boolean eap_md5_isSuccess(struct eap_sm *sm, void *priv)
{
	struct eap_md5_data *data = priv;
	return data->state == SUCCESS;
}


int eap_server_md5_register(void)
{
	struct eap_method *eap;
	int ret;

	eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION,
				      EAP_VENDOR_IETF, EAP_TYPE_MD5, "MD5");
	if (eap == NULL)
		return -1;

	eap->init = eap_md5_init;
	eap->reset = eap_md5_reset;
	eap->buildReq = eap_md5_buildReq;
	eap->check = eap_md5_check;
	eap->process = eap_md5_process;
	eap->isDone = eap_md5_isDone;
	eap->isSuccess = eap_md5_isSuccess;

	ret = eap_server_method_register(eap);
	if (ret)
		eap_server_method_free(eap);
	return ret;
}
