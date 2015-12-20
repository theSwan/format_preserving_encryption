// 48 bits encryption 
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

long mod = 16777216;

#define CIPHERSQL_FPE_BITS 48

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

void input_proc(long num, char *str){
    int i = 0;
    long bits = 0;
    for(i = CIPHERSQL_FPE_BITS - 1; i >=0; i--){
        bits = num & 1;
        num = num >> 1;
        str[i] = bits + '0';
    }
    str[CIPHERSQL_FPE_BITS] = '\0';
}


long output_proc(char *numstr){
    int i = 0;
    long bits = 0;
    long num = 0;
    for(i = 0; i < CIPHERSQL_FPE_BITS; i++){
        num = num << 1;
        bits = numstr[i] - '0';
        num = num | bits;
    }
    return num;
}

void num2str(long num, char *str, int m){
    int i = 0;
    long bits = 0;
    for(i = m - 1; i >=0; i--){
        bits = num & 1;
        num = num >> 1;
        str[i] = bits + '0';
    }
    str[m] = '\0';
}


long str2num(char *numstr){
    int i = 0;
    long bits = 0;
    long num = 0;
    for(i = 0; i < strlen(numstr); i++){
        num = num << 1;
        bits = numstr[i] - '0';
        num = num | bits;
    }
    return num;
}

void rev(char *in, char *out){
    int len = sizeof(in);
    int i = 0;
    for(i = 0; i < len; i++){
        out[len-1-i] = in[i];
    }

}


long ciphersql_fpe_bits_encrypt(ciphersql_fpe_t *fpe, long input_num, char *tweak)
{
    char in[CIPHERSQL_FPE_BITS + 2];
    char out[CIPHERSQL_FPE_BITS + 2];
    memset(in, 0, sizeof(in));

    input_proc(input_num, in);
    printf("the 48-bits representation of the input: %s\n", in);

    size_t inlen;
    int llen, rlen, i;
    uint32_t lval, rval, tl, tr, m, w, tmp;
    
    char lbuf[CIPHERSQL_FPE_BITS/2 + 2];
    char rbuf[CIPHERSQL_FPE_BITS/2 + 2];
    char tlbuf[33];
    long yval, aval, bval;

    assert(out);
    assert(in);
    assert(tweak);

    inlen = strlen(in);
    
    for (i = 0; i < inlen; i++) {
        if (!isdigit(in[i])) {
            fprintf(stderr, "%s: invalid bits format\n", __FUNCTION__);
            return -1;
        }
    }
    llen = inlen / 2;
    rlen = inlen - llen;

    memcpy(lbuf, in, llen);
    lbuf[llen] = 0;  // 末位赋值为0，可以作为字符串操作
    //printf("%s\n", lbuf);
    memcpy(rbuf, in+llen, rlen);
    rbuf[rlen] = 0;
    //printf("%s\n", rbuf);

    memcpy(tlbuf, tweak, 32);
    tlbuf[32] = 0;  // 末位赋值为0，可以作为字符串操作
    tl = str2num(tlbuf);
    tr = str2num(tweak + 32);
   // printf("%ld %ld\n", tl, tr);

    unsigned char pblock[16], yblock[16];
    //printf("%ld %ld\n", str2num(lbuf), str2num(rbuf));

    for (i = 0; i < 8; i++) {

        if(i%2 == 0){
            m = llen;
            w = tr;
        }
        else{
            m = rlen;
            w = tl;
        }
        memset(pblock, 0, sizeof(pblock));
        memset(yblock, 0, sizeof(yblock));
        tmp = w ^ i;
        
        rval = str2num(rbuf);
        memcpy(pblock, &rval, sizeof(rval));
        memcpy(pblock + 12, &tmp, sizeof(tmp));

        AES_encrypt(pblock, yblock, &fpe->key);
        yval = *((long *)yblock) % mod;
        aval = str2num(lbuf);
        
        lval = (aval + yval) % mod;

        //printf("%ld \n", yval);

        char cbuf[CIPHERSQL_FPE_BITS/2 + 2];
        num2str(lval, cbuf, m);
        strcpy(lbuf, rbuf);
        strcpy(rbuf, cbuf);
        // printf("%s %s\n", lbuf, rbuf);
         //printf("%ld %ld\n", str2num(lbuf), str2num(rbuf));
        
    }

    memset(out, '0', inlen);
    memcpy(out, rbuf, strlen(rbuf));
    strcpy(out + strlen(rbuf), lbuf);

    printf("the encrypted bits is: %s\n", out);
    return output_proc(out);
}

long ciphersql_fpe_bits_decrypt(ciphersql_fpe_t *fpe, long input_num, char *tweak)
{
    char in[CIPHERSQL_FPE_BITS + 2];
    char out[CIPHERSQL_FPE_BITS + 2];
    memset(in, 0, sizeof(in));

    input_proc(input_num, in);
    //printf("%ld %s\n", in);

    size_t inlen;
    int llen, rlen, i;
    uint32_t lval, rval, tl, tr, m, w, tmp;
    
    char lbuf[CIPHERSQL_FPE_BITS/2 + 2];
    char rbuf[CIPHERSQL_FPE_BITS/2 + 2];
    char tlbuf[33];
    long yval, aval, bval;

    assert(out);
    assert(in);
    assert(tweak);

    inlen = strlen(in);
    
    for (i = 0; i < inlen; i++) {
        if (!isdigit(in[i])) {
            fprintf(stderr, "%s: invalid bits format\n", __FUNCTION__);
            return -1;
        }
    }
    llen = inlen / 2;
    rlen = inlen - llen;

    memcpy(lbuf, in, llen);
    lbuf[llen] = 0;  // 末位赋值为0，可以作为字符串操作
    //printf("%s\n", lbuf);
    memcpy(rbuf, in+llen, rlen);
    rbuf[rlen] = 0;
    //printf("%s\n", rbuf);

    memcpy(tlbuf, tweak, 32);
    tlbuf[32] = 0;  // 末位赋值为0，可以作为字符串操作
    tl = str2num(tlbuf);
    tr = str2num(tweak + 32);
    //printf("%ld %ld\n", tl, tr);

    unsigned char pblock[16], yblock[16];
    //printf("%ld %ld\n", str2num(lbuf), str2num(rbuf));

    for (i = 7; i >= 0; i--) {
        if(i%2 == 0){
            m = llen;
            w = tr;
        }
        else{
            m = rlen;
            w = tl;
        }
        memset(pblock, 0, sizeof(pblock));
        memset(yblock, 0, sizeof(yblock));
        tmp = w ^ i;
        
        rval = str2num(rbuf);
        memcpy(pblock, &rval, sizeof(rval));
        memcpy(pblock + 12, &tmp, sizeof(tmp));
        
        AES_encrypt(pblock, yblock, &fpe->key);
        yval = *((long *)yblock) % mod;
        aval = str2num(lbuf);
        
        lval =  (aval >= yval) ? (aval - yval) : aval + mod - yval;

        //printf("%ld \n", yval);

        char cbuf[CIPHERSQL_FPE_BITS/2 + 2];
        num2str(lval, cbuf, m);
        strcpy(lbuf, rbuf);
        strcpy(rbuf, cbuf);
        //printf("%s %s\n", lbuf, rbuf);
        //printf("%ld %ld\n", str2num(lbuf), str2num(rbuf));
    }

    memset(out, '0', inlen);
    memcpy(out, rbuf, strlen(rbuf));
    strcpy(out + strlen(rbuf), lbuf);

    //printf("%s\n", out);
    return output_proc(out);
}


int ciphersql_fpe_test()
{
    char buf[100];
    char buf2[100];
    unsigned char key[32] = {0};
    ciphersql_fpe_t fpe;
    long r;

    ERR_load_crypto_strings();

    if (ciphersql_fpe_init(&fpe, 0, key, sizeof(key) * 8) < 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "%s: %d\n", __FILE__, __LINE__);
        return -1;
    }

    long tweak = 12345678;
    num2str(tweak, buf, 64);
    printf("%s\n", buf);

    r = ciphersql_fpe_bits_encrypt(&fpe, 123546798, buf);

    if (r < 0) {
        printf("failed\n");
        return -1;
    }

    printf("the corresponding ciphertext is: %ld\n", r);
    printf("\n");

    r = ciphersql_fpe_bits_decrypt(&fpe, r, buf);
    printf("the decrypted ciphertext is: %ld\n", r);

    return 0;
}

int main(int argc, char **argv)
{
    return ciphersql_fpe_test();
}





