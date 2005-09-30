#include "ntlm.h"
#include "global.h"
#include <openssl/md4.h>
#include <openssl/md5.h>
#include "base64.h"
#include <stdlib.h>
#include <string.h>
#include "proxytunnel.h"
#include <ctype.h>
#include <sys/time.h>

#define TYPE1_DATA_SEG 9
#define TYPE2_BUF_SIZE 2048
#define DOMAIN_BUFLEN 256

int ntlm_challenge = 0;
void message( char *s, ... );
int unicode = 0;

unsigned char challenge[8];
char domain[DOMAIN_BUFLEN];
char workstation[] = "WORKSTATION";

unsigned char unipasswd[DOMAIN_BUFLEN * 2];

unsigned char t2_buf[TYPE2_BUF_SIZE];

unsigned char *pblob = NULL;
int bloblen;

unsigned char *t_info;
int t_info_len;

unsigned long flags;

unsigned char lm2digest[16];

void build_type1() {
	ntlm_type1 *type1;
	int len = sizeof(ntlm_type1) + sizeof(unsigned char) * TYPE1_DATA_SEG;

	type1 = (ntlm_type1 *)malloc(len);
	if (!type1) {
		message("Fatal Error in build type1, Malloc failed\n");
		exit(-1);
	}

	memset(type1, 0, len);
	type1->signature[0] = 'N';
	type1->signature[1] = 'T';
	type1->signature[2] = 'L';
	type1->signature[3] = 'M';
	type1->signature[4] = 'S';
	type1->signature[5] = 'S';
	type1->signature[6] = 'P';
	type1->signature[7] = '\0';

	type1->message_type = NTLM_TYPE_1;
	type1->flags = NEG_UNICODE | NEG_OEM | REQ_TARGET | NEG_NTLM | NEG_ASIGN | NEG_NTLM2 | NEG_128 | NEG_56 | IE_SETSTHIS;

	base64(ntlm_type1_buf, (unsigned char *)type1, len);

	free(type1);
	return;
}


int parse_type2(unsigned char *buf) {


	int len = unbase64(t2_buf, buf, TYPE2_BUF_SIZE);
	int i;

	if (len <= 0) {
		message("parse_type2: failed to decode the message\n");
		return -1;
	}

	ntlm_type2 *t2 = (ntlm_type2 *)t2_buf;

	if (strcmp(t2->signature, "NTLMSSP") != 0) {
		message("parse_type2: Signature did not match\n");
		return -1;
	}

	message("parse_type2: Signature matched\n");

	if (t2->message_type != NTLM_TYPE_2) {
		message("parse_type2: Incorrect message type sent\n");
		return -1;
	}

	if (t2->target_name.length > 0 && t2->target_name.length < DOMAIN_BUFLEN && (t2->target_name.length + t2->target_name.offset < len)) {
		int sp = 1;
		if (t2->flags & NEG_UNICODE)
			sp = 2;
		for (i = 0; i < t2->target_name.length / sp; i++)
			domain[i] = t2_buf[t2->target_name.offset + i * sp];
		domain[i] = 0;
	} else
		domain[0] = 0;

	for (i = 0; i < 8; i++)
		challenge[i] = t2->challenge[i];

	message("NTLM Got Domain: %s\n", domain);

	if( args_info.domain_given )
	{
		message( "NTLM Overriding domain: %s\n", args_info.domain_arg );
		for( i = 0; i < strlen(args_info.domain_arg); i++ )
		{
			domain[i] = args_info.domain_arg[i];
		}
		domain[i] = 0;
	}
	message("NTLM Domain: %s\n", domain);
	message("NTLM Got Challenge: ");
	for (i = 0; i < 8; i++)
		message("%02X", challenge[i]);
	message("\n");

	if (!(t2->flags & NEG_NTLM && t2->flags & NEG_NTLM2)) {
		message("parse_type2: Sorry, NTLMv2 is only supported at this time, I will do NTLMv1 should I ever get stuck behind a NTLMv1 FW\n");
		return -1;
	}

	if (t2->flags & NEG_UNICODE)
		unicode = 1;
	else
		unicode = 0;

	t_info = &t2_buf[t2->target_info.offset];
	t_info_len = t2->target_info.length;

	flags = t2->flags;

	ntlm_challenge = 1;

	build_ntlm2_response();

	return 0;
}


void build_type3_response() {
	unsigned char *t3;
	ntlm_type3 *type3;
	int len;
	int sp = 1;
	int i;

	if (unicode)
		sp = 2;

	len = sizeof(ntlm_type3) + sizeof(unsigned char) * (16 + bloblen + (strlen(domain) + strlen(args_info.user_arg) + strlen(workstation)) * sp);

	type3 = (ntlm_type3 *)malloc(len);
	if (!type3) {
		message("Fatal Error in build type3, Malloc failed\n");
		exit(-1);
	}
	t3 = (unsigned char *) type3;

	memset(type3, 0, len);
	type3->signature[0] = 'N';
	type3->signature[1] = 'T';
	type3->signature[2] = 'L';
	type3->signature[3] = 'M';
	type3->signature[4] = 'S';
	type3->signature[5] = 'S';
	type3->signature[6] = 'P';
	type3->signature[7] = '\0';

	type3->message_type = NTLM_TYPE_3;
	type3->flags = flags & ~TAR_DOMAIN;

	type3->LM_response.length = 16;
	type3->LM_response.space = 16;
	type3->LM_response.offset = sizeof(ntlm_type3);
	memcpy(&t3[type3->LM_response.offset], lm2digest, 16);

	type3->NTLM_response.length = bloblen;
	type3->NTLM_response.space = bloblen;
	type3->NTLM_response.offset = type3->LM_response.offset + type3->LM_response.space;
	memcpy(&t3[type3->NTLM_response.offset], pblob, bloblen);

	type3->domain.length = strlen(domain) * sp;
	type3->domain.space = strlen(domain) * sp;
	type3->domain.offset = type3->NTLM_response.offset + type3->NTLM_response.space;
	for (i = 0; i < strlen(domain); i++)
		t3[type3->domain.offset + i * sp] = domain[i];

	type3->user.length = strlen(args_info.user_arg) * sp;
	type3->user.space = strlen(args_info.user_arg) * sp;
	type3->user.offset = type3->domain.offset + type3->domain.space;
	for (i = 0; i < strlen(args_info.user_arg); i++)
		t3[type3->user.offset + i * sp] = args_info.user_arg[i];

	type3->workstation.length = strlen(workstation) * sp;
	type3->workstation.space = strlen(workstation) * sp;
	type3->workstation.offset = type3->user.offset + type3->user.space;
	for (i = 0; i < strlen(workstation); i++)
		t3[type3->workstation.offset + i * sp] = workstation[i];

	base64(ntlm_type3_buf, (unsigned char *)type3, len);

	free(type3);
	return;
}




/*
** Function: hmac_md5
*/

void
hmac_md5(text, text_len, key, key_len, digest)
unsigned char* text; /* pointer to data stream */
int text_len; /* length of data stream */
unsigned char* key; /* pointer to authentication key */
int key_len; /* length of authentication key */
unsigned char digest[16]; /* caller digest to be filled in */
{
        MD5_CTX context;
        unsigned char k_ipad[65];    /* inner padding -
                                      * key XORd with ipad
                                      */
        unsigned char k_opad[65];    /* outer padding -
                                      * key XORd with opad
                                      */
        unsigned char tk[16];
        int i;

		/* if key is longer than 64 bytes reset it to key=MD5(key) */
        if (key_len > 64) {

			MD5_CTX      tctx;
			MD5_Init(&tctx);
			MD5_Update(&tctx, key, key_len);
			MD5_Final(tk, &tctx);

			key = tk;
			key_len = 16;
        }

        /*
         * the HMAC_MD5 transform looks like:
         *
         * MD5(K XOR opad, MD5(K XOR ipad, text))
         *
         * where K is an n byte key
         * ipad is the byte 0x36 repeated 64 times
         * opad is the byte 0x5c repeated 64 times
         * and text is the data being protected
         */

        /* start out by storing key in pads */
        bzero( k_ipad, sizeof k_ipad);
        bzero( k_opad, sizeof k_opad);
        bcopy( key, k_ipad, key_len);
        bcopy( key, k_opad, key_len);

        /* XOR key with ipad and opad values */
        for (i=0; i<64; i++) {
                k_ipad[i] ^= 0x36;
                k_opad[i] ^= 0x5c;
        }
        /*
         * perform inner MD5
         */
        MD5_Init(&context);                   /* init context for 1st
                                              * pass */
        MD5_Update(&context, k_ipad, 64);     /* start with inner pad */
        MD5_Update(&context, text, text_len); /* then text of datagram */
        MD5_Final(digest, &context);          /* finish up 1st pass */
        /*
         * perform outer MD5
         */
        MD5_Init(&context);                   /* init context for 2nd
                                              * pass */
        MD5_Update(&context, k_opad, 64);     /* start with outer pad */
        MD5_Update(&context, digest, 16);     /* then results of 1st
                                              * hash */
        MD5_Final(digest, &context);          /* finish up 2nd pass */
}

void build_ntlm2_response() {
	int i, j;
	int passlen = 0;
	MD4_CTX passcontext;
	unsigned char passdigest[16];
	unsigned char *userdom;
	int userdomlen;
	unsigned char userdomdigest[16];
	blob *b;
	struct timeval t;
	unsigned char responsedigest[16];
	unsigned char lm2data[16];

	if (pblob != NULL)
		free(pblob);

	memset(unipasswd, 0, sizeof(unsigned char) * DOMAIN_BUFLEN * 2);
	for (i = 0; i < strlen(args_info.pass_arg); i++) {
		if (unicode) {
			unipasswd[i * 2] = args_info.pass_arg[i];
			passlen++;
			passlen++;
		} else {
			unipasswd[i] = args_info.pass_arg[i];
			passlen++;
		}
	}

	MD4_Init (&passcontext);
	MD4_Update (&passcontext, unipasswd, passlen);
	MD4_Final (passdigest, &passcontext);

	message("MD4 of password is: ");
	for( i = 0; i < 16; i++)
		message("%02X", passdigest[i]);
	message("\n");

	message("DOMAIN: %s\nUSER: %s\n", domain, args_info.user_arg);


	userdomlen = sizeof(unsigned char) * (strlen(args_info.user_arg) + strlen(domain)) * 2;
	userdom = (unsigned char *)malloc(userdomlen);
	if (!userdom) {
		message("Fatal Error in build_ntlm2_response, Malloc failed\n");
		exit(-1);
	}

	userdomlen = 0;
	for (i = 0; i < strlen(args_info.user_arg); i++) {
		if (unicode) {
			userdom[i * 2] = toupper(args_info.user_arg[i]);
			userdomlen++;
			userdomlen++;
		} else {
			userdom[i] = toupper(args_info.user_arg[i]);
			userdomlen++;
		}
	}

	for (j = 0; j < strlen(domain); j++) {
		if (unicode) {
			userdom[i * 2 + j * 2] = toupper(domain[j]);
			userdomlen++;
			userdomlen++;
		} else {
			userdom[i + j] = toupper(domain[j]);
			userdomlen++;
		}
	}

	message("userdom is: ");
	for( i = 0; i < userdomlen; i++)
		message("%02X", userdom[i]);
	message("\n");


	hmac_md5(userdom, userdomlen, passdigest, 16, userdomdigest);

	free(userdom);

	message("HMAC_MD5 of userdom keyed with MD4 pass is: ");
	for( i = 0; i < 16; i++)
		message("%02X", userdomdigest[i]);
	message("\n");

	if ((sizeof(long long) != 8)) {
		message("We are in trouble here.. long long support is not here!!\n");
		exit(-1);
	}


	bloblen = sizeof(blob) + sizeof(unsigned char) * t_info_len;


	pblob = (unsigned char *)malloc(bloblen);
	if (!pblob) {
		message("Fatal Error in build_ntlm2_response, Malloc failed\n");
		exit(-1);
	}

	memset(pblob, 0, bloblen);

	b = (blob *)pblob;

	for (i = 0; i < 8; i++)
		b->challenge[i] = challenge[i];

	b->signature = 0x00000101;


	// This is nasty, also not sure all this 64bit arithmetic will work all the time.. basically the spec says you
	// need the number of 10ths of microseconds since jan 1, 1601.

	gettimeofday(&t, NULL);
	b->timestamp = (long long)t.tv_sec;
	b->timestamp += 11644473600LL;
	b->timestamp *= 1000000LL;
	b->timestamp += (long long)t.tv_usec;
	b->timestamp *= 10LL;

	// need a ramdom client challenge
	for (i = 0; i < 8; i++)
		b->client_challenge[i] = (unsigned char) ((256.0 * rand()) / (RAND_MAX + 1.0)) ;

	message("client_challenge is: ");
	for( i = 0; i < 8; i++)
		message("%02X", b->client_challenge[i]);
	message("\n");



	memcpy(&b->data_start, t_info, t_info_len);

	hmac_md5(&pblob[8], bloblen - 8, userdomdigest, 16, responsedigest);

	for(i = 0; i < 16; i++)
		b->digest[i] = responsedigest[i];

	message("HMAC is: ");
	for( i = 0; i < 16; i++)
		message("%02X", responsedigest[i]);
	message("\n");


	// LM2 response generation

	for (i = 0; i < 8; i++)
		lm2data[i] = b->challenge[i];

	for (i = 0; i < 8; i++)
		lm2data[8 + i] = b->client_challenge[i];

	hmac_md5(lm2data, 16, userdomdigest, 16, lm2digest);

}


