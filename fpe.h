#ifndef CIPHERSQL_FPE_H
#define CIPHERSQL_FPE_H

/*
 * Format-Preserve Encryption
 * implementation of NIST 800-38G FF1 schemes
 * 
 * FPE is used to encrypt strings such as credit card numbers and phone numbers
 * the ciphertext is still in valid format, for example:
 *	 FPE_encrypt("13810631266") == "98723498792"
 * the output is still 11 digits
 */

#include <string.h>
#include <openssl/aes.h>


#define CIPHERSQL_FPE_MIN_DIGITS	   6
#define CIPHERSQL_FPE_MAX_DIGITS	  18
#define CIPHERSQL_FPE_MIN_TWEAKLEN	   4
#define CIPHERSQL_FPE_MAX_TWEAKLEN	  11 
#define CIPHERSQL_FPE_NUM_ROUNDS	  10

#define CIPHERSQL_TYPE_BINARY		0x04
#define CIPHERSQL_TYPE_KEYWORD		0x05
#define CIPHERSQL_TYPE_PASSWORD		0x08
#define CIPHERSQL_TYPE_TEXT		0x09
#define CIPHERSQL_TYPE_INTEGER		0x0a
#define CIPHERSQL_TYPE_DIGITS		0x00
#define CIPHERSQL_TYPE_CELLPHONE	0x01
#define CIPHERSQL_TYPE_BANKCARD		0x02
#define CIPHERSQL_TYPE_IDCARD		0x03


#ifdef __cplusplus
extern "C" {
#endif


typedef struct ciphersql_fpe_t ciphersql_fpe_t;

int ciphersql_fpe_init(ciphersql_fpe_t *fpe, int type, const unsigned char *key, int keybits);
int ciphersql_fpe_encrypt(ciphersql_fpe_t *fpe, const char *in, const unsigned char *tweak, size_t tweaklen, char *out);
int ciphersql_fpe_decrypt(ciphersql_fpe_t *fpe, const char *in, const unsigned char *tweak, size_t tweaklen, char *out);
void ciphersql_fpe_cleanup(ciphersql_fpe_t *fpe);


#ifdef __cplusplus
}
#endif
#endif
