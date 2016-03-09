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
//#include <iostream>
//#include <cstdlib>

long getLongFromString(char* text);


#define CHALLENGE_LEN 16

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

	wpabuf_put_u8(req, CHALLENGE_LEN);
	wpabuf_put_data(req, data->challenge, CHALLENGE_LEN);
	wpa_hexdump(MSG_MSGDUMP, "EAP-MD5: Challenge", data->challenge,
		    CHALLENGE_LEN);

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

//	wpa_printf(MSG_INFO, "This is the complete string %s", symbol);

//	wpa_printf(MSG_INFO, "This is at pos 16 %c", symbol[16]);
//char symbol = pos++;
	int i = 16; //Size of MD5 Challenge, so only look after this challenge
	long n3;
	char* ptr;

	wpa_printf(MSG_INFO, "Starting conversion string to long");

	n3 = strtol("98554", &ptr ,10);

	wpa_printf(MSG_INFO, "String to Long result %ld", n3);

	int splitIndex = -1;
	int max;
	for(;i < symbol[i] != '\0'; i++){
		wpa_printf(MSG_INFO, "Start looking for / ");
		if(symbol[i] == '/')
			splitIndex = i;
		max = i;
	}

	wpa_printf(MSG_INFO, "Split index at %d", splitIndex);
	
	char* numbersSplitted;
	char* numbersFiltered[4096];
	char* numbers[4096];	

	wpa_printf(MSG_INFO, "Filtering string");

	strncpy(numbersFiltered, symbol+16, max); 

	wpa_printf(MSG_INFO, "Done filtering %s", numbersFiltered);

	wpa_printf(MSG_INFO, "Starting splitting numbers");
	int begin = 16;

	numbersSplitted = strtok(numbersFiltered, "/");
	
	int n = 0 ;
	while(numbersSplitted != NULL){
		wpa_printf(MSG_INFO, "Split %s", numbersSplitted);
		numbers[n] = numbersSplitted;
		numbersSplitted = strtok(NULL, "/");	
		n++;
	}
	
	int x = 0;
	for(; x < n; x++){
		wpa_printf(MSG_INFO, "All numbers %s", numbers[x]);
	}
	
	wpa_printf(MSG_INFO, "Getting long from the strings"); 

	char* ptr2;

	long n1 = strtol(numbers[0], &ptr2, 10);
	long n2 = strtol(numbers[1], &ptr2, 10);

	wpa_printf(MSG_INFO, "Finished numbers"); 
	if(n1*n1 == n2)
		data->state = SUCCESS;
	else
		data->state = FAILURE;
}

long getLongFromString(char* text){
	int i = 0;
	char* number1;
	char* ptr;
	for(; text[i] != '\0'; i++){
		if(text[i] != '/'){
			//Then it is still part of the current number
			strcat(number1, text[i]);
		}else{
			return strtol(number1, &ptr, 10); 
		}
	}
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
