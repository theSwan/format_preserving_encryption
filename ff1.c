

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include "fpe.h"

struct ciphersql_fpe_t {
	int type;
	AES_KEY key;
};

static uint32_t modulo[] = {
		1,
		10,
		100,
		1000,
		10000,
		100000,
		1000000,
		10000000,
		100000000,
		1000000000,
		1000000000};

int ciphersql_fpe_init(ciphersql_fpe_t *fpe, int type, const unsigned char *key, int keybits)
{
	if (AES_set_encrypt_key(key, keybits, &fpe->key) < 0) {
		fprintf(stderr, "error: %s: %s: %d\n", __FUNCTION__, __FILE__, __LINE__);
		return -1;
	}

	return 0;
}

void ciphersql_fpe_cleanup(ciphersql_fpe_t *fpe)
{
	memset(fpe, 0, sizeof(ciphersql_fpe_t));
}

int ciphersql_fpe_encrypt(ciphersql_fpe_t *fpe,
		const char *in, const unsigned char *tweak, size_t tweaklen,
		char *out)
{
	size_t inlen;
	int llen, rlen;
	uint32_t lval, rval;
	unsigned char pblock[16] = {
		0x01, 0x02, 0x01, 0x0a, 0x00, 0x00, 0x0a, 0xff,
		0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00};
	unsigned char qblock[16];
	char lbuf[CIPHERSQL_FPE_MAX_DIGITS/2 + 2];
	uint64_t yval;
	int i;

	assert(out);
	assert(in);
	assert(tweak);

	inlen = strlen(in);
	if (inlen < CIPHERSQL_FPE_MIN_DIGITS || inlen > CIPHERSQL_FPE_MAX_DIGITS) {
		fprintf(stderr, "%s: invalid digits length\n", __FUNCTION__);
		return -1;
	}
	for (i = 0; i < inlen; i++) {
		if (!isdigit(in[i])) {
			fprintf(stderr, "%s: invalid digits format\n", __FUNCTION__);
			return -1;
		}
	}
	llen = inlen / 2;
	rlen = inlen - llen;


	if (tweaklen < CIPHERSQL_FPE_MIN_TWEAKLEN || tweaklen > CIPHERSQL_FPE_MAX_TWEAKLEN) {
		fprintf(stderr, "%s: invalid tweak length\n", __FUNCTION__);
		return -1;
	}

	memcpy(lbuf, in, llen);
	lbuf[llen] = 0;
	lval = atoi(lbuf);
	rval = atoi(in + llen);

	pblock[7] = llen & 0xff;
	pblock[8] = inlen & 0xff;
	pblock[12] = tweaklen & 0xff;

	AES_encrypt(pblock, pblock, &fpe->key);

	memset(qblock, 0, sizeof(qblock));
	memcpy(qblock, tweak, tweaklen);
	
	for (i = 0; i < CIPHERSQL_FPE_NUM_ROUNDS; i += 2) {
	
		unsigned char rblock[16];
		int j;

		qblock[11] = i & 0xff;
		memcpy(qblock + 12, &rval, sizeof(rval));
		for (j = 0; j < sizeof(rblock); j++) {
			rblock[j] = pblock[j] ^ qblock[j];
		}
		AES_encrypt(rblock, rblock, &fpe->key);
		yval = *((uint64_t *)rblock) % modulo[llen];
		lval = (lval + yval) % modulo[llen];
		
		qblock[11] = (i + 1) & 0xff;
		memcpy(qblock + 12, &lval, sizeof(lval));
		for (j = 0; j < sizeof(rblock); j++) {
			rblock[j] = pblock[j] ^ qblock[j];
		}
		AES_encrypt(rblock, rblock, &fpe->key);
		yval = *((uint64_t *)rblock) % modulo[rlen];
		rval = (rval + yval) % modulo[rlen];
	}

	memset(out, '0', inlen);
	sprintf(lbuf, "%d", rval);
	memcpy(out + rlen - strlen(lbuf), lbuf, strlen(lbuf));
	sprintf(lbuf, "%d", lval);
	strcpy(out + inlen - strlen(lbuf), lbuf);

	return 0;
}

int ciphersql_fpe_decrypt(ciphersql_fpe_t *fpe,
		const char *in, const unsigned char *tweak, size_t tweaklen,		
		char *out)
{
	size_t inlen;
	int llen, rlen;
	uint32_t lval, rval;
	unsigned char pblock[16] = {
		0x01, 0x02, 0x01, 0x0a, 0x00, 0x00, 0x0a, 0xff,
		0xff, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00};
	unsigned char qblock[16];
	char lbuf[CIPHERSQL_FPE_MAX_DIGITS/2 + 2];
	uint64_t yval;
	int i;

	assert(out);
	assert(in);
	assert(tweak);

	inlen = strlen(in);
	if (inlen < CIPHERSQL_FPE_MIN_DIGITS || inlen > CIPHERSQL_FPE_MAX_DIGITS) {
		fprintf(stderr, "%s: invalid digits length\n", __FUNCTION__);
		return -1;
	}
	for (i = 0; i < inlen; i++) {
		if (!isdigit(in[i])) {
			fprintf(stderr, "%s: invalid digits format\n", __FUNCTION__);
			return -1;
		}
	}
	rlen = inlen / 2;
	llen = inlen - rlen;

	if (tweaklen < CIPHERSQL_FPE_MIN_TWEAKLEN || tweaklen > CIPHERSQL_FPE_MAX_TWEAKLEN) {
		fprintf(stderr, "%s: invalid tweak length\n", __FUNCTION__);
		return -1;
	}

	memcpy(lbuf, in, llen);
	lbuf[llen] = 0;
	lval = atoi(lbuf);
	rval = atoi(in + llen);

	pblock[7] = rlen & 0xff;
	pblock[8] = inlen & 0xff;
	pblock[12] = tweaklen & 0xff;

	AES_encrypt(pblock, pblock, &fpe->key);

	memset(qblock, 0, sizeof(qblock));
	memcpy(qblock, tweak, tweaklen);
	
	for (i = CIPHERSQL_FPE_NUM_ROUNDS - 1; i > 0; i -= 2) {
	
		unsigned char rblock[16];
		int j;

		qblock[11] = i & 0xff;
		memcpy(qblock + 12, &rval, sizeof(rval));
		for (j = 0; j < sizeof(rblock); j++) {
			rblock[j] = pblock[j] ^ qblock[j];
		}
		AES_encrypt(rblock, rblock, &fpe->key);
		yval = *((uint64_t *)rblock) % modulo[llen];
		lval = (lval >= yval) ? (lval - yval) : lval + modulo[llen] - yval;
		
		qblock[11] = (i - 1) & 0xff;
		memcpy(qblock + 12, &lval, sizeof(lval));
		for (j = 0; j < sizeof(rblock); j++) {
			rblock[j] = pblock[j] ^ qblock[j];
		}
		AES_encrypt(rblock, rblock, &fpe->key);
		yval = *((uint64_t *)rblock) % modulo[rlen];
		rval = (rval >= yval) ? (rval - yval) : rval + modulo[rlen] - yval;
	}

	memset(out, '0', inlen);
	sprintf(lbuf, "%d", rval);
	memcpy(out + rlen - strlen(lbuf), lbuf, strlen(lbuf));
	sprintf(lbuf, "%d", lval);
	strcpy(out + inlen - strlen(lbuf), lbuf);

	return 0;
}

int ciphersql_fpe_test()
{
	char buf[100];
	char buf2[100];
	unsigned char key[32] = {0};
	unsigned char tweak[8] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
	ciphersql_fpe_t fpe;
	int r;

	ERR_load_crypto_strings();

	if (ciphersql_fpe_init(&fpe, 0, key, sizeof(key) * 8) < 0) {
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "%s: %d\n", __FILE__, __LINE__);
		return -1;
	}

	r = ciphersql_fpe_encrypt(&fpe, "99999999999999999", tweak, sizeof(tweak), buf);

	if (r < 0) {
		printf("failed\n");
		return -1;
	}

	printf("%s\n", buf);
	printf("\n");

	r = ciphersql_fpe_decrypt(&fpe, buf, tweak, sizeof(tweak), buf2);
	printf("%s\n", buf2);

	return 0;
}

int main(int argc, char **argv)
{
	return ciphersql_fpe_test();
}





